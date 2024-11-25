package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc"
)

const (
	driverName    = "ingress.csi.spiffe.io"
	driverVersion = "1.0.0"
)

type IngressGatewaySVIDDriver struct {
	nodeID string
	csi.UnimplementedControllerServer
}

func (d *IngressGatewaySVIDDriver) NodeStageVolume(ctx context.Context, req *csi.NodeStageVolumeRequest) (*csi.NodeStageVolumeResponse, error) {
	log.Printf("NodeStageVolume called with volume ID: %s", req.VolumeId)
	return &csi.NodeStageVolumeResponse{}, nil
}

func (d *IngressGatewaySVIDDriver) NodeUnstageVolume(ctx context.Context, req *csi.NodeUnstageVolumeRequest) (*csi.NodeUnstageVolumeResponse, error) {
	log.Printf("NodeUnstageVolume called with volume ID: %s", req.VolumeId)
	return &csi.NodeUnstageVolumeResponse{}, nil
}

func (d *IngressGatewaySVIDDriver) NodeUnpublishVolume(ctx context.Context, req *csi.NodeUnpublishVolumeRequest) (*csi.NodeUnpublishVolumeResponse, error) {
	log.Printf("NodeUnpublishVolume called for volume ID: %s at target path: %s", req.VolumeId, req.TargetPath)

	if err := syscall.Unmount(req.TargetPath, 0); err != nil {
		log.Printf("Warning: failed to unmount %s: %v", req.TargetPath, err)
	}

	if err := os.RemoveAll(req.TargetPath); err != nil {
		log.Printf("Warning: failed to remove target path %s: %v", req.TargetPath, err)
	}

	return &csi.NodeUnpublishVolumeResponse{}, nil
}

func (d *IngressGatewaySVIDDriver) NodeGetVolumeStats(ctx context.Context, req *csi.NodeGetVolumeStatsRequest) (*csi.NodeGetVolumeStatsResponse, error) {
	log.Printf("NodeGetVolumeStats called for volume ID: %s at path: %s", req.VolumeId, req.VolumePath)
	return &csi.NodeGetVolumeStatsResponse{
		Usage: []*csi.VolumeUsage{
			{
				Available: 0,
				Total:     0,
				Used:      0,
				Unit:      csi.VolumeUsage_BYTES,
			},
		},
	}, nil
}

func (d *IngressGatewaySVIDDriver) NodeExpandVolume(ctx context.Context, req *csi.NodeExpandVolumeRequest) (*csi.NodeExpandVolumeResponse, error) {
	log.Printf("NodeExpandVolume called for volume ID: %s", req.VolumeId)
	return &csi.NodeExpandVolumeResponse{}, nil
}

func (d *IngressGatewaySVIDDriver) NodeGetCapabilities(ctx context.Context, req *csi.NodeGetCapabilitiesRequest) (*csi.NodeGetCapabilitiesResponse, error) {
	log.Printf("NodeGetCapabilities called")
	var caps []*csi.NodeServiceCapability
	for _, cap := range []csi.NodeServiceCapability_RPC_Type{
		csi.NodeServiceCapability_RPC_STAGE_UNSTAGE_VOLUME,
		csi.NodeServiceCapability_RPC_GET_VOLUME_STATS,
		csi.NodeServiceCapability_RPC_EXPAND_VOLUME,
	} {
		caps = append(caps, &csi.NodeServiceCapability{
			Type: &csi.NodeServiceCapability_Rpc{
				Rpc: &csi.NodeServiceCapability_RPC{
					Type: cap,
				},
			},
		})
	}
	return &csi.NodeGetCapabilitiesResponse{
		Capabilities: caps,
	}, nil
}

func (d *IngressGatewaySVIDDriver) NodeGetInfo(ctx context.Context, req *csi.NodeGetInfoRequest) (*csi.NodeGetInfoResponse, error) {
	log.Printf("NodeGetInfo called")
	return &csi.NodeGetInfoResponse{
		NodeId: d.nodeID,
		AccessibleTopology: &csi.Topology{
			Segments: map[string]string{
				"kubernetes.io/hostname": d.nodeID,
			},
		},
	}, nil
}

func (d *IngressGatewaySVIDDriver) GetPluginInfo(ctx context.Context, req *csi.GetPluginInfoRequest) (*csi.GetPluginInfoResponse, error) {
	log.Printf("GetPluginInfo called")
	return &csi.GetPluginInfoResponse{
		Name:          driverName,
		VendorVersion: driverVersion,
	}, nil
}

func (d *IngressGatewaySVIDDriver) GetPluginCapabilities(ctx context.Context, req *csi.GetPluginCapabilitiesRequest) (*csi.GetPluginCapabilitiesResponse, error) {
	log.Printf("GetPluginCapabilities called")
	return &csi.GetPluginCapabilitiesResponse{
		Capabilities: []*csi.PluginCapability{
			{
				Type: &csi.PluginCapability_Service_{
					Service: &csi.PluginCapability_Service{
						Type: csi.PluginCapability_Service_CONTROLLER_SERVICE,
					},
				},
			},
		},
	}, nil
}

func (d *IngressGatewaySVIDDriver) Probe(ctx context.Context, req *csi.ProbeRequest) (*csi.ProbeResponse, error) {
	log.Printf("Probe called")
	return &csi.ProbeResponse{}, nil
}

type SVIDNode struct {
	fs.Inode
	client   *workloadapi.Client
	spiffeID string
	isKey    bool
}

func (n *SVIDNode) Open(ctx context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	if flags&syscall.O_ACCMODE != syscall.O_RDONLY {
		return nil, 0, syscall.EACCES
	}
	return n, 0, 0
}

func (n *SVIDNode) Read(ctx context.Context, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	log.Printf("Read request for SVID node (isKey: %v) at offset %d with buffer size %d", n.isKey, off, len(dest))

	svid, err := n.client.FetchX509SVID(ctx)
	if err != nil {
		log.Printf("Failed to fetch SVID for %s: %v", n.spiffeID, err)
		return nil, syscall.EIO
	}
	log.Printf("Successfully fetched fresh SVID for %s", n.spiffeID)

	var pemData []byte
	if n.isKey {
		pkcs8Key, err := x509.MarshalPKCS8PrivateKey(svid.PrivateKey)
		if err != nil {
			log.Printf("Failed to marshal private key: %v", err)
			return nil, syscall.EIO
		}
		pemData = pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: pkcs8Key,
		})
		log.Printf("Generated private key PEM data, size: %d bytes", len(pemData))
	} else {
		pemData = pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: svid.Certificates[0].Raw,
		})
		log.Printf("Generated certificate PEM data, size: %d bytes", len(pemData))
	}

	if off >= int64(len(pemData)) {
		return fuse.ReadResultData([]byte{}), 0
	}

	end := off + int64(len(dest))
	if end > int64(len(pemData)) {
		end = int64(len(pemData))
	}

	data := pemData[off:end]
	log.Printf("Returning %d bytes of data", len(data))
	return fuse.ReadResultData(data), 0
}

func (n *SVIDNode) Getattr(ctx context.Context, fh fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	out.Mode = 0644
	if n.isKey {
		out.Mode = 0600
	}

	svid, err := n.client.FetchX509SVID(ctx)
	if err != nil {
		log.Printf("Failed to fetch SVID for size calculation: %v", err)
		return syscall.EIO
	}

	var pemData []byte
	if n.isKey {
		pkcs8Key, err := x509.MarshalPKCS8PrivateKey(svid.PrivateKey)
		if err != nil {
			log.Printf("Failed to marshal private key for size calculation: %v", err)
			return syscall.EIO
		}
		pemData = pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: pkcs8Key,
		})
	} else {
		pemData = pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: svid.Certificates[0].Raw,
		})
	}

	out.Size = uint64(len(pemData))
	now := time.Now()
	out.SetTimes(&now, &now, &now)

	return 0
}

type CustomFSNode struct {
	fs.Inode
	client *workloadapi.Client
}

func (n *CustomFSNode) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	log.Printf("Lookup called for: %s", name)

	if strings.HasPrefix(name, "app") {
		appDir := &CustomFSNode{
			client: n.client,
		}
		return n.NewPersistentInode(ctx, appDir, fs.StableAttr{Mode: syscall.S_IFDIR | 0755}), 0
	}

	if name == "tls.crt" || name == "tls.key" {
		parentName, parentNode := n.Parent()
		if parentNode == nil {
			log.Printf("No parent directory found")
			return nil, syscall.ENOENT
		}

		if !strings.HasPrefix(parentName, "app") {
			log.Printf("Invalid path structure, parent is not an app directory: %s", parentName)
			return nil, syscall.ENOENT
		}

		// Use the parent directory name (e.g., "app1", "app2") to construct the SPIFFE ID
		spiffeID := fmt.Sprintf("spiffe://example.org/ns/istio-system/sa/%s", parentName)

		log.Printf("Creating SVID node for %s with SPIFFE ID: %s", name, spiffeID)

		svidNode := &SVIDNode{
			client:   n.client,
			spiffeID: spiffeID,
			isKey:    name == "tls.key",
		}

		mode := syscall.S_IFREG | 0444
		if name == "tls.key" {
			mode = syscall.S_IFREG | 0400
		}

		return n.NewPersistentInode(ctx, svidNode, fs.StableAttr{Mode: uint32(mode)}), 0
	}

	return nil, syscall.ENOENT
}

func (n *CustomFSNode) Readdir(ctx context.Context) (fs.DirStream, syscall.Errno) {
	_, parentNode := n.Parent()
	if parentNode == nil {
		// This is the root directory - return empty for now
		// Files will be created on demand through Lookup
		log.Printf("Readdir called for root directory")
		return fs.NewListDirStream([]fuse.DirEntry{}), 0
	}

	// For app directories, always show tls.crt and tls.key
	log.Printf("Readdir called for app directory")
	entries := []fuse.DirEntry{
		{Mode: syscall.S_IFREG | 0444, Name: "tls.crt"},
		{Mode: syscall.S_IFREG | 0400, Name: "tls.key"},
	}
	return fs.NewListDirStream(entries), 0
}

func (n *CustomFSNode) Getattr(ctx context.Context, fh fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	out.Mode = syscall.S_IFDIR | 0755
	return 0
}

func (d *IngressGatewaySVIDDriver) NodePublishVolume(ctx context.Context, req *csi.NodePublishVolumeRequest) (*csi.NodePublishVolumeResponse, error) {
	log.Printf("NodePublishVolume called with:")
	log.Printf("  Target Path: %s", req.TargetPath)
	log.Printf("  Volume Context: %+v", req.VolumeContext)
	log.Printf("  Volume ID: %s", req.VolumeId)
	log.Printf("  Volume Capability: %+v", req.VolumeCapability)
	log.Printf("  Readonly: %v", req.Readonly)

	podName, exists := req.VolumeContext["csi.storage.k8s.io/pod.name"]
	if !exists {
		err := fmt.Errorf("pod name not found in volume context")
		log.Printf("Error: %v", err)
		return nil, err
	}

	if !strings.Contains(podName, "istio-ingressgateway") {
		err := fmt.Errorf("this CSI driver is only for istio-ingressgateway pods, got pod name: %s", podName)
		log.Printf("Error: %v", err)
		return nil, err
	}
	log.Printf("Verified pod is ingress gateway: %s", podName)

	log.Printf("Creating workload API client using socket: %s", os.Getenv("SPIFFE_ENDPOINT_SOCKET"))
	client, err := workloadapi.New(ctx, workloadapi.WithAddr(
		fmt.Sprintf("unix://%s", os.Getenv("SPIFFE_ENDPOINT_SOCKET")),
	))
	if err != nil {
		log.Printf("Failed to create workload API client: %v", err)
		return nil, fmt.Errorf("failed to create workload API client: %v", err)
	}
	log.Printf("Successfully created workload API client")

	log.Printf("Creating mount point directory: %s", req.TargetPath)
	if err := os.MkdirAll(req.TargetPath, 0755); err != nil {
		log.Printf("Failed to create mount point directory: %v", err)
		return nil, fmt.Errorf("failed to create mount point directory: %v", err)
	}

	root := &CustomFSNode{
		client: client,
	}

	log.Printf("Mounting FUSE filesystem at: %s", req.TargetPath)
	server, err := fs.Mount(req.TargetPath, root, &fs.Options{
		MountOptions: fuse.MountOptions{
			Debug:      true,
			AllowOther: true,
			Name:       "svid-csi",
		},
		FirstAutomaticIno: 1,
	})
	if err != nil {
		log.Printf("Failed to mount filesystem: %v", err)
		return nil, fmt.Errorf("failed to mount filesystem: %v", err)
	}
	log.Printf("Successfully mounted FUSE filesystem")

	go func() {
		log.Printf("Starting FUSE server for path: %s", req.TargetPath)
		server.Serve()
		log.Printf("FUSE server stopped for path: %s", req.TargetPath)
	}()

	log.Printf("NodePublishVolume completed successfully")
	return &csi.NodePublishVolumeResponse{}, nil
}

func main() {
	nodeID := os.Getenv("NODE_ID")
	if nodeID == "" {
		log.Fatal("NODE_ID environment variable must be set")
	}

	driver := &IngressGatewaySVIDDriver{
		nodeID: nodeID,
	}

	log.Printf("Starting CSI driver with node ID: %s", nodeID)

	server := grpc.NewServer()
	csi.RegisterIdentityServer(server, driver)
	csi.RegisterNodeServer(server, driver)
	csi.RegisterControllerServer(server, driver)

	log.Printf("Removing existing socket if present")
	os.Remove("/csi/csi.sock")

	log.Printf("Creating Unix domain socket listener")
	listener, err := net.Listen("unix", "/csi/csi.sock")
	if err != nil {
		log.Fatalf("Failed to create listener: %v", err)
	}

	log.Printf("Starting SVID CSI driver for Istio Ingress Gateway on socket: /csi/csi.sock")
	if err := server.Serve(listener); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}
