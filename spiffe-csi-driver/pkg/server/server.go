package server

import (
	"context"
	"errors"
	"fmt"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"net"
	"os"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/go-logr/logr"
	"google.golang.org/grpc"
	"spiffe-csi-driver/pkg/logkeys"
)

type Config struct {
	Log           logr.Logger
	CSISocketPath string
	Driver        Driver
}

type Driver interface {
	csi.IdentityServer
	csi.NodeServer
}

func Run(config Config) error {
	if config.CSISocketPath == "" {
		return errors.New("CSI socket path is required")
	}

	fmt.Printf("config.CSISocketPath: %s\n", config.CSISocketPath)

	if err := os.Remove(config.CSISocketPath); err != nil && !os.IsNotExist(err) {
		config.Log.Error(err, "Unable to remove CSI socket")
	}

	listener, err := net.Listen("unix", config.CSISocketPath)
	if err != nil {
		return fmt.Errorf("unable to create CSI socket listener: %w", err)
	}

	rpcLogger := rpcLogger{Log: config.Log}

	server := grpc.NewServer(
		grpc.UnaryInterceptor(rpcLogger.UnaryRPCLogger),
		grpc.StreamInterceptor(rpcLogger.StreamRPCLogger),
	)
	csi.RegisterIdentityServer(server, config.Driver)
	csi.RegisterNodeServer(server, config.Driver)

	// Add health check service
	healthServer := health.NewServer()
	healthServer.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(server, healthServer)

	config.Log.Info("Listening...")
	return server.Serve(listener)
}

type rpcLogger struct {
	Log logr.Logger
}

func (l rpcLogger) UnaryRPCLogger(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	log := l.Log.WithValues(logkeys.FullMethod, info.FullMethod)
	resp, err := handler(ctx, req)
	if err != nil {
		log.Error(err, "RPC failed")
	} else {
		log.V(0).Info("RPC succeeded")
	}
	return resp, err
}

func (l rpcLogger) StreamRPCLogger(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	log := l.Log.WithValues(logkeys.FullMethod, info.FullMethod)
	err := handler(srv, ss)
	if err != nil {
		log.Error(err, "RPC failed")
	} else {
		log.V(0).Info("RPC succeeded")
	}
	return err
}
