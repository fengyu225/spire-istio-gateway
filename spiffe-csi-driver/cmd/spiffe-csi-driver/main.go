package main

import (
	"flag"
	"fmt"
	"os"
	"spiffe-csi-driver/internal/version"
	"spiffe-csi-driver/pkg/driver"
	"spiffe-csi-driver/pkg/logkeys"
	"spiffe-csi-driver/pkg/server"

	"github.com/go-logr/zapr"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	nodeIDFlag               = flag.String("node-id", "", "Kubernetes Node ID. If unset, the node ID is obtained from the environment (i.e., -node-id-env)")
	nodeIDEnvFlag            = flag.String("node-id-env", "MY_NODE_NAME", "Envvar from which to obtain the node ID. Overridden by -node-id.")
	csiSocketPathFlag        = flag.String("csi-socket-path", "/spiffe-csi/csi.sock", "Path to the CSI socket")
	pluginNameFlag           = flag.String("plugin-name", "csi.spiffe.io", "Plugin name to register")
	workloadAPISocketDirFlag = flag.String("workload-api-socket-dir", "", "Path to the Workload API socket directory")
	proxySocketDirFlag       = flag.String("proxy-socket-dir", "", "Path to the proxy socket directory")
	trustDomainFlag          = flag.String("trust-domain", "", "Trust domain for SPIFFE IDs")
	logLevelFlag             = flag.String("log-level", "info", "Log level (debug, info, warn, error)")
)

func getZapLevel(level string) zapcore.Level {
	switch level {
	case "debug":
		return zapcore.DebugLevel // -1
	case "info":
		return zapcore.InfoLevel // 0
	case "warn":
		return zapcore.WarnLevel // 1
	case "error":
		return zapcore.ErrorLevel // 2
	case "dpanic":
		return zapcore.DPanicLevel // 3
	case "panic":
		return zapcore.PanicLevel // 4
	case "fatal":
		return zapcore.FatalLevel // 5
	default:
		return zapcore.InfoLevel // 0 (default)
	}
}

func main() {
	flag.Parse()

	// Create custom zap config based on log level
	zapCfg := zap.NewDevelopmentConfig()
	zapCfg.Level = zap.NewAtomicLevelAt(getZapLevel(*logLevelFlag))
	zapCfg.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	zapCfg.EncoderConfig.TimeKey = "timestamp"
	zapCfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder

	zapLog, err := zapCfg.Build()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to set up logger: %v", err)
		os.Exit(1)
	}
	defer zapLog.Sync()

	log := zapr.NewLogger(zapLog)

	nodeID := getNodeIDFromFlags()

	log.Info("Starting.",
		logkeys.Version, version.Version(),
		logkeys.NodeID, nodeID,
		logkeys.WorkloadAPISocketDir, *workloadAPISocketDirFlag,
		logkeys.CSISocketPath, *csiSocketPathFlag,
		"logLevel", *logLevelFlag,
	)

	driver, err := driver.New(driver.Config{
		Log:                  log,
		NodeID:               nodeID,
		PluginName:           *pluginNameFlag,
		WorkloadAPISocketDir: *workloadAPISocketDirFlag,
		ProxySocketDir:       *proxySocketDirFlag,
		TrustDomain:          *trustDomainFlag,
	})
	if err != nil {
		log.Error(err, "Failed to create driver")
		os.Exit(1)
	}

	serverConfig := server.Config{
		Log:           log,
		CSISocketPath: *csiSocketPathFlag,
		Driver:        driver,
	}

	if err := server.Run(serverConfig); err != nil {
		log.Error(err, "Failed to serve")
		os.Exit(1)
	}
	log.Info("Done")
}

func getNodeIDFromFlags() string {
	nodeID := os.Getenv(*nodeIDEnvFlag)
	if *nodeIDFlag != "" {
		nodeID = *nodeIDFlag
	}
	return nodeID
}
