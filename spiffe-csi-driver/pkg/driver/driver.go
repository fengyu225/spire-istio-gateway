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
	"sync"
	"time"
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

	return &Driver{
		log:                  config.Log,
		nodeID:               config.NodeID,
		pluginName:           config.PluginName,
		workloadAPISocketDir: config.WorkloadAPISocketDir,
		proxySocketDir:       config.ProxySocketDir,
		trustDomain:          config.TrustDomain,
		proxies:              make(map[string]*proxy.WorkloadProxy),
		proxyCtx:             ctx,
		proxyCancel:          cancel,
	}, nil
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

func (d *Driver) Probe(context.Context, *csi.ProbeRequest) (*csi.ProbeResponse, error) {
	return &csi.ProbeResponse{}, nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func (d *Driver) NodePublishVolume(ctx context.Context, req *csi.NodePublishVolumeRequest) (*csi.NodePublishVolumeResponse, error) {
	ephemeralMode := req.GetVolumeContext()["csi.storage.k8s.io/ephemeral"]

	log := d.log.WithValues(
		logkeys.VolumeID, req.VolumeId,
		logkeys.TargetPath, req.TargetPath,
	)

	log.Info("NodePublishVolume called", "targetPath", req.TargetPath, "volumeCapability", req.VolumeCapability)

	// Validate request
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

	proxySocketPath := filepath.Join(d.proxySocketDir, req.VolumeId)
	log.Info("Creating proxy socket directory", "path", proxySocketPath)
	if err := os.MkdirAll(proxySocketPath, 0777); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create proxy socket directory: %v", err)
	}
	if err := os.Chmod(proxySocketPath, 0777); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to set proxy socket directory permissions: %v", err)
	}

	sourceSocket := filepath.Join(proxySocketPath, "socket")
	log.Info("Creating new proxy",
		"sourceSocket", sourceSocket,
		"destinationSocket", filepath.Join(d.workloadAPISocketDir, "socket"))

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

	// Create a context with volume context for the proxy
	proxyCtx := context.WithValue(d.proxyCtx, "volume_context", req.VolumeContext)

	go func() {
		if err := p.Start(proxyCtx); err != nil {
			log.Error(err, "proxy failed", "volume_id", req.VolumeId)
		}
		// Set socket permissions after proxy starts
		if err := os.Chmod(sourceSocket, 0777); err != nil {
			log.Error(err, "failed to set socket permissions", "socket", sourceSocket)
		}
	}()

	// Wait a bit for the socket to be created and set permissions
	time.Sleep(100 * time.Millisecond)
	if err := os.Chmod(sourceSocket, 0777); err != nil {
		log.Error(err, "failed to set socket permissions during initial setup", "socket", sourceSocket)
	}

	// Create target directory if it doesn't exist
	log.Info("Creating target directory", "path", req.TargetPath)
	if err := os.MkdirAll(req.TargetPath, 0777); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create target directory: %v", err)
	}
	if err := os.Chmod(req.TargetPath, 0777); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to set target directory permissions: %v", err)
	}

	// Check if directory is already a mount point
	mounted, err := mount.IsMountPoint(req.TargetPath)
	if err != nil {
		log.Error(err, "Failed to check if path is mount point", "path", req.TargetPath)
	}
	log.Info("Mount point check", "path", req.TargetPath, "isMounted", mounted)

	log.Info("Mounting directory",
		"source", proxySocketPath,
		"target", req.TargetPath,
		"sourceExists", fileExists(proxySocketPath),
		"targetExists", fileExists(req.TargetPath))

	if err := mount.BindMountRW(proxySocketPath, req.TargetPath); err != nil {
		return nil, status.Errorf(codes.Internal, "unable to mount %q: %v",
			req.TargetPath, err)
	}

	// After mounting, ensure all permissions are correct
	if err := os.Chmod(req.TargetPath, 0777); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to set final target directory permissions: %v", err)
	}

	// Set permissions on the mounted socket file
	mountedSocket := filepath.Join(req.TargetPath, "socket")
	if err := os.Chmod(mountedSocket, 0777); err != nil {
		log.Error(err, "failed to set mounted socket permissions", "socket", mountedSocket)
	}

	log.Info("Volume published successfully")
	return &csi.NodePublishVolumeResponse{}, nil
}

func (d *Driver) NodeUnpublishVolume(ctx context.Context, req *csi.NodeUnpublishVolumeRequest) (*csi.NodeUnpublishVolumeResponse, error) {
	log := d.log.WithValues(
		logkeys.VolumeID, req.VolumeId,
		logkeys.TargetPath, req.TargetPath,
	)

	log.Info("NodeUnpublishVolume called",
		"volumeId", req.VolumeId,
		"targetPath", req.TargetPath)

	// Validate request
	switch {
	case req.VolumeId == "":
		return nil, status.Error(codes.InvalidArgument, "volume ID is required")
	case req.TargetPath == "":
		return nil, status.Error(codes.InvalidArgument, "target path is required")
	}

	// Stop the proxy if it exists
	d.proxyMu.Lock()
	if _, ok := d.proxies[req.VolumeId]; ok {
		delete(d.proxies, req.VolumeId)
	}
	d.proxyMu.Unlock()

	// Check if target is a valid mount and issue unmount request
	if ok, err := mount.IsMountPoint(req.TargetPath); err != nil {
		log.Error(err, "Failed to verify mount point")
		return nil, status.Errorf(codes.Internal, "unable to verify mount point %q: %v", req.TargetPath, err)
	} else if ok {
		log.Info("Unmounting target path", "path", req.TargetPath)
		if err := mount.Unmount(req.TargetPath); err != nil {
			log.Error(err, "Failed to unmount target path")
			return nil, status.Errorf(codes.Internal, "unable to unmount %q: %v", req.TargetPath, err)
		}
	}

	// Clean up the mount path
	log.Info("Removing target path", "path", req.TargetPath)
	if err := os.Remove(req.TargetPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, status.Errorf(codes.Internal, "unable to remove target path %q: %v", req.TargetPath, err)
	}

	log.Info("Volume unpublished")
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
