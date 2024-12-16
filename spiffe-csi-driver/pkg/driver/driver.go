package driver

import (
	"context"
	"errors"
	"fmt"
	"github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/go-logr/logr"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"os"
	"path/filepath"
	"spiffe-csi-driver/internal/version"
	"spiffe-csi-driver/pkg/logkeys"
	"spiffe-csi-driver/pkg/mount"
	"spiffe-csi-driver/pkg/proxy"
	"strings"
	"sync"
	"time"
)

const (
	// Directory permissions - more restrictive than 0777
	socketDirMode = 0755 // rwxr-x--- for proxy socket directory
	targetDirMode = 0755 // rwxr-x--- for target directory

	// Socket file permissions
	socketFileMode = 0666 // rw-rw---- owner and group can read/write

	// Timeout for socket creation
	socketCreationTimeout = 5 * time.Second
)

type Config struct {
	Log                  logr.Logger
	NodeID               string
	PluginName           string
	WorkloadAPISocketDir string
	ProxySocketDir       string
	TrustDomain          string
}

type Driver struct {
	csi.UnimplementedIdentityServer
	csi.UnimplementedNodeServer

	log                  logr.Logger
	nodeID               string
	pluginName           string
	workloadAPISocketDir string
	proxySocketDir       string
	trustDomain          string

	proxyMu     sync.RWMutex
	proxies     map[string]*proxy.WorkloadProxy
	proxyCtx    context.Context
	proxyCancel context.CancelFunc
}

func New(config Config) (*Driver, error) {
	switch {
	case config.NodeID == "":
		return nil, errors.New("node ID is required")
	case config.WorkloadAPISocketDir == "":
		return nil, errors.New("workload API socket directory is required")
	case config.ProxySocketDir == "":
		return nil, errors.New("proxy socket directory is required")
	case config.TrustDomain == "":
		return nil, errors.New("trust domain is required")
	}

	ctx, cancel := context.WithCancel(context.Background())

	d := &Driver{
		log:                  config.Log,
		nodeID:               config.NodeID,
		pluginName:           config.PluginName,
		workloadAPISocketDir: config.WorkloadAPISocketDir,
		proxySocketDir:       config.ProxySocketDir,
		trustDomain:          config.TrustDomain,
		proxies:              make(map[string]*proxy.WorkloadProxy),
		proxyCtx:             ctx,
		proxyCancel:          cancel,
	}

	// Ensure proxy directory exists
	if err := os.MkdirAll(config.ProxySocketDir, socketDirMode); err != nil {
		return nil, fmt.Errorf("failed to create proxy directory: %w", err)
	}

	// Restore existing volumes
	if err := d.restoreExistingVolumes(); err != nil {
		d.log.Error(err, "Failed to restore existing volumes")
	}

	return d, nil
}

func (d *Driver) GetPluginInfo(context.Context, *csi.GetPluginInfoRequest) (*csi.GetPluginInfoResponse, error) {
	return &csi.GetPluginInfoResponse{
		Name:          d.pluginName,
		VendorVersion: version.Version(),
	}, nil
}

func (d *Driver) GetPluginCapabilities(context.Context, *csi.GetPluginCapabilitiesRequest) (*csi.GetPluginCapabilitiesResponse, error) {
	return &csi.GetPluginCapabilitiesResponse{}, nil
}

func (d *Driver) restoreExistingVolumes() error {
	log := d.log.WithName("restore")
	log.Info("Restoring existing volumes after restart")

	// Find all existing proxy directories
	entries, err := os.ReadDir(d.proxySocketDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to read proxy directory: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		volumeID := entry.Name()

		// Check if the volume is still mounted
		targetPath := d.findMountPointForVolume(volumeID)
		if targetPath == "" {
			// Clean up abandoned proxy directory
			log.Info("Removing abandoned proxy directory", "volumeID", volumeID)
			if err := os.RemoveAll(filepath.Join(d.proxySocketDir, volumeID)); err != nil {
				log.Error(err, "Failed to remove abandoned proxy directory", "volumeID", volumeID)
			}
			continue
		}

		log.Info("Restoring proxy for volume", "volumeID", volumeID, "targetPath", targetPath)

		if err := d.recreateProxy(volumeID, targetPath); err != nil {
			log.Error(err, "Failed to restore proxy", "volumeID", volumeID)
			continue
		}
	}

	return nil
}

func (d *Driver) findMountPointForVolume(volumeID string) string {
	mounts, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return ""
	}

	volumePath := filepath.Join(d.proxySocketDir, volumeID)
	for _, line := range strings.Split(string(mounts), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && strings.Contains(fields[0], volumePath) {
			return fields[1]
		}
	}
	return ""
}

func (d *Driver) recreateProxy(volumeID, targetPath string) error {
	sourceSocket := filepath.Join(d.proxySocketDir, volumeID, "socket")
	p, err := proxy.New(
		sourceSocket,
		filepath.Join(d.workloadAPISocketDir, "socket"),
		d.trustDomain,
		nil, // We can't recover the original volume context
		d.log,
	)
	if err != nil {
		return err
	}

	d.proxyMu.Lock()
	d.proxies[volumeID] = p
	d.proxyMu.Unlock()

	proxyCtx := context.WithValue(d.proxyCtx, "volume_context", map[string]string{})
	go func() {
		if err := p.Start(proxyCtx); err != nil {
			d.log.Error(err, "Restored proxy failed", "volumeID", volumeID)
		}
	}()

	return nil
}

func (d *Driver) Probe(context.Context, *csi.ProbeRequest) (*csi.ProbeResponse, error) {
	return &csi.ProbeResponse{}, nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func (d *Driver) NodePublishVolume(ctx context.Context, req *csi.NodePublishVolumeRequest) (*csi.NodePublishVolumeResponse, error) {
	// Track success for cleanup
	d.log.V(0).Info("request", "request", req)
	success := false
	var createdPaths []string
	defer func() {
		if !success {
			// Cleanup on failure
			d.proxyMu.Lock()
			if _, exists := d.proxies[req.VolumeId]; exists {
				d.log.V(0).Info("deleting from driver proxies", "volumeID", req.VolumeId, "driverProxies", d.proxies)
				delete(d.proxies, req.VolumeId)
			}
			d.proxyMu.Unlock()

			for _, path := range createdPaths {
				if err := os.RemoveAll(path); err != nil {
					d.log.Error(err, "cleanup failed", "path", path)
				}
			}
		}
	}()

	log := d.log.WithValues(
		logkeys.VolumeID, req.VolumeId,
		logkeys.TargetPath, req.TargetPath,
	)

	// Validate paths
	if err := validatePath(req.TargetPath); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid target path: %v", err)
	}

	// Existing request validation...
	ephemeralMode := req.GetVolumeContext()["csi.storage.k8s.io/ephemeral"]
	switch {
	case req.VolumeId == "":
		return nil, status.Error(codes.InvalidArgument, "volume ID is required")
	case req.TargetPath == "":
		return nil, status.Error(codes.InvalidArgument, "target path is required")
	case req.VolumeCapability == nil:
		return nil, status.Error(codes.InvalidArgument, "volume capability is required")
	case !req.Readonly:
		return nil, status.Error(codes.InvalidArgument, "read-only mode is required")
	case ephemeralMode != "true":
		return nil, status.Error(codes.InvalidArgument, "only ephemeral volumes are supported")
	}

	// Create proxy socket directory with secure permissions
	proxySocketPath := filepath.Join(d.proxySocketDir, req.VolumeId)
	if err := secureCreateDir(proxySocketPath, socketDirMode); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create proxy socket directory: %v", err)
	}
	createdPaths = append(createdPaths, proxySocketPath)

	proxyCtx := context.WithValue(d.proxyCtx, "volume_context", req.VolumeContext)
	errChan := make(chan error, 1)
	sourceSocket := filepath.Join(proxySocketPath, "socket")
	p, err := proxy.New(
		sourceSocket,
		filepath.Join(d.workloadAPISocketDir, "socket"),
		d.trustDomain,
		req.VolumeContext,
		d.log,
	)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create proxy: %v", err)
	}

	d.proxyMu.Lock()
	d.proxies[req.VolumeId] = p
	d.proxyMu.Unlock()

	// Create target directory with secure permissions
	if err := secureCreateDir(req.TargetPath, targetDirMode); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create target directory: %v", err)
	}
	createdPaths = append(createdPaths, req.TargetPath)

	// Start proxy with proper error handling
	socketReady := make(chan struct{})

	go func() {
		if err := p.Start(proxyCtx); err != nil {
			errChan <- err
		}
	}()

	// Wait for socket creation with timeout
	go func() {
		deadline := time.Now().Add(socketCreationTimeout)
		for time.Now().Before(deadline) {
			if _, err := os.Stat(sourceSocket); err == nil {
				if err := os.Chmod(sourceSocket, socketFileMode); err == nil {
					socketReady <- struct{}{}
					return
				}
			}
			time.Sleep(100 * time.Millisecond)
		}
		errChan <- fmt.Errorf("timeout waiting for socket creation")
	}()

	readyCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	select {
	case err := <-errChan:
		return nil, status.Errorf(codes.Internal, "proxy startup failed: %v", err)
	case <-readyCtx.Done():
		return nil, status.Error(codes.DeadlineExceeded, "timeout waiting for proxy to be ready")
	case <-socketReady:
		// Continue with mount
	}

	// Validate socket before mounting
	if err := validateSocketFile(sourceSocket); err != nil {
		return nil, status.Errorf(codes.Internal, "socket validation failed: %v", err)
	}

	// Mount with existing mount point check
	mounted, err := mount.IsMountPoint(req.TargetPath)
	if err != nil {
		log.Error(err, "Failed to check if path is mount point", "path", req.TargetPath)
	}
	if !mounted {
		log.Info("Mounting directory",
			"source", proxySocketPath,
			"target", req.TargetPath,
			"sourceExists", fileExists(proxySocketPath),
			"targetExists", fileExists(req.TargetPath))
		if err := mount.BindMountRW(proxySocketPath, req.TargetPath); err != nil {
			return nil, status.Errorf(codes.Internal, "mount failed: %v", err)
		}
	}

	// Validate mounted socket
	mountedSocket := filepath.Join(req.TargetPath, "socket")
	if err := validateSocketFile(mountedSocket); err != nil {
		_ = mount.Unmount(req.TargetPath)
		return nil, status.Errorf(codes.Internal, "mounted socket validation failed: %v", err)
	}

	success = true
	log.Info("Volume published successfully")
	return &csi.NodePublishVolumeResponse{}, nil
}

func (d *Driver) shouldRemoveProxyDir(volumeID string, targetPath string) bool {
	// Check if this volume is mounted anywhere else
	mounts, err := os.ReadFile("/proc/mounts")
	if err != nil {
		d.log.Error(err, "Failed to read mounts, assuming safe to remove")
		return true
	}

	volumePath := filepath.Join(d.proxySocketDir, volumeID)
	mountLines := strings.Split(string(mounts), "\n")

	for _, line := range mountLines {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			// If we find any mount point for this volume that's not the target path
			// being unmounted, we should preserve the proxy directory
			if strings.Contains(fields[0], volumePath) && fields[1] != targetPath {
				return false
			}
		}
	}

	return true
}

func (d *Driver) NodeUnpublishVolume(ctx context.Context, req *csi.NodeUnpublishVolumeRequest) (*csi.NodeUnpublishVolumeResponse, error) {
	log := d.log.WithValues(
		logkeys.VolumeID, req.VolumeId,
		logkeys.TargetPath, req.TargetPath,
	)

	// Validate paths
	if err := validatePath(req.TargetPath); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid target path: %v", err)
	}

	// Check if this is a pod termination or driver restart
	isPodTermination := false
	if _, err := os.Stat(req.TargetPath); err == nil {
		// If the path exists, this is likely a pod termination
		isPodTermination = true
	}

	// Stop proxy if this is a pod termination
	d.proxyMu.Lock()
	if proxy, ok := d.proxies[req.VolumeId]; ok {
		if isPodTermination {
			if err := proxy.Stop(); err != nil {
				log.Error(err, "Error stopping proxy")
			}
			delete(d.proxies, req.VolumeId)
		}
	}
	d.proxyMu.Unlock()

	// If this is a driver restart (path doesn't exist), don't try to unmount
	if !isPodTermination {
		log.Info("Skipping unmount during driver restart")
		return &csi.NodeUnpublishVolumeResponse{}, nil
	}

	// Unmount with retries for pod termination
	maxRetries := 3
	for i := 0; i < maxRetries; i++ {
		if ok, err := mount.IsMountPoint(req.TargetPath); err != nil {
			if !os.IsNotExist(err) {
				log.Error(err, "Failed to verify mount point")
				if i == maxRetries-1 {
					return nil, status.Errorf(codes.Internal, "mount point verification failed: %v", err)
				}
			} else {
				break // Path doesn't exist, nothing to unmount
			}
		} else if ok {
			if err := mount.Unmount(req.TargetPath); err != nil {
				if i == maxRetries-1 {
					return nil, status.Errorf(codes.Internal, "failed to unmount after retries: %v", err)
				}
				time.Sleep(time.Second)
				continue
			}
		}
		break
	}

	// Only clean up if this is a pod termination
	if isPodTermination {
		// Clean up the target path
		if err := os.RemoveAll(req.TargetPath); err != nil && !os.IsNotExist(err) {
			return nil, status.Errorf(codes.Internal, "failed to remove target path: %v", err)
		}

		// Remove proxy socket directory
		proxySocketPath := filepath.Join(d.proxySocketDir, req.VolumeId)
		if err := os.RemoveAll(proxySocketPath); err != nil && !os.IsNotExist(err) {
			return nil, status.Errorf(codes.Internal, "failed to remove proxy socket directory: %v", err)
		}
		log.Info("Removed proxy socket directory", "path", proxySocketPath)
	}

	log.Info("Volume unpublished successfully")
	return &csi.NodeUnpublishVolumeResponse{}, nil
}

func (d *Driver) NodeGetCapabilities(context.Context, *csi.NodeGetCapabilitiesRequest) (*csi.NodeGetCapabilitiesResponse, error) {
	return &csi.NodeGetCapabilitiesResponse{
		Capabilities: []*csi.NodeServiceCapability{
			{
				Type: &csi.NodeServiceCapability_Rpc{
					Rpc: &csi.NodeServiceCapability_RPC{
						Type: csi.NodeServiceCapability_RPC_VOLUME_CONDITION,
					},
				},
			},
			{
				Type: &csi.NodeServiceCapability_Rpc{
					Rpc: &csi.NodeServiceCapability_RPC{
						Type: csi.NodeServiceCapability_RPC_GET_VOLUME_STATS,
					},
				},
			},
		},
	}, nil
}

func (d *Driver) NodeGetInfo(context.Context, *csi.NodeGetInfoRequest) (*csi.NodeGetInfoResponse, error) {
	return &csi.NodeGetInfoResponse{
		NodeId:            d.nodeID,
		MaxVolumesPerNode: 0,
	}, nil
}

func (d *Driver) NodeGetVolumeStats(ctx context.Context, req *csi.NodeGetVolumeStatsRequest) (*csi.NodeGetVolumeStatsResponse, error) {
	log := d.log.WithValues(
		logkeys.VolumeID, req.VolumeId,
		logkeys.VolumePath, req.VolumePath,
	)

	volumeConditionAbnormal := false
	volumeConditionMessage := "mounted"
	if err := d.checkWorkloadAPIMount(req.VolumePath); err != nil {
		volumeConditionAbnormal = true
		volumeConditionMessage = err.Error()
		log.Error(err, "Volume is unhealthy")
	} else {
		log.Info("Volume is healthy")
	}

	return &csi.NodeGetVolumeStatsResponse{
		VolumeCondition: &csi.VolumeCondition{
			Abnormal: volumeConditionAbnormal,
			Message:  volumeConditionMessage,
		},
	}, nil
}

func (d *Driver) checkWorkloadAPIMount(volumePath string) error {
	if ok, err := mount.IsMountPoint(volumePath); err != nil {
		return fmt.Errorf("failed to determine mount point: %w", err)
	} else if !ok {
		return errors.New("volume path is not mounted")
	}

	if _, err := os.ReadDir(volumePath); err != nil {
		return fmt.Errorf("unable to list contents of volume path: %w", err)
	}
	return nil
}
