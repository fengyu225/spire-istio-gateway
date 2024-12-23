package proxy

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	secretservice "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"
	"github.com/go-logr/logr"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"
	"io"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	SecretType = "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret"
)

type WorkloadProxy struct {
	sourceSocket      string
	destinationSocket string
	listener          net.Listener
	server            *grpc.Server
	client            *workloadapi.Client
	trustDomain       string
	log               logr.Logger
	volumeContext     map[string]string
	mu                sync.RWMutex
	shutdown          bool
}

type RateLimit struct {
	timestamps []time.Time
	version    string
}

type sdsX509ContextWatcher struct {
	updates chan *workloadapi.X509Context
	log     logr.Logger
}

func (w *sdsX509ContextWatcher) OnX509ContextUpdate(update *workloadapi.X509Context) {
	w.log.V(-1).Info("Received X509 context update from SPIRE")
	select {
	case w.updates <- update:
		w.log.V(0).Info("Successfully sent update to update channel subscribed by SDS server")
	default:
		// If channel is full, remove old update and send new one
		select {
		case <-w.updates:
			w.updates <- update
			w.log.V(1).Info("Dropped old update and sent new one")
		default:
			w.log.V(1).Info("Channel full, skipping update")
		}
	}
}

func (w *sdsX509ContextWatcher) OnX509ContextWatchError(err error) {
	w.log.Error(err, "Error watching X509 context")
}

func New(sourceSocket, destinationSocket, trustDomain string, volumeContext map[string]string, log logr.Logger) (*WorkloadProxy, error) {
	return &WorkloadProxy{
		sourceSocket:      sourceSocket,
		destinationSocket: destinationSocket,
		trustDomain:       trustDomain,
		log:               log,
		volumeContext:     volumeContext,
	}, nil
}

func (p *WorkloadProxy) Start(ctx context.Context) error {
	//if err := p.validateVolumeContext(); err != nil {
	//	p.log.Error(err, "Authorization failed for StreamSecrets")
	//	return status.Error(codes.PermissionDenied, "unauthorized")
	//}

	p.log.V(0).Info("Starting SDS proxy",
		"sourceSocket", p.sourceSocket,
		"destinationSocket", p.destinationSocket)

	if err := os.Remove(p.sourceSocket); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove existing socket: %v", err)
	}

	listener, err := net.Listen("unix", p.sourceSocket)
	if err != nil {
		return fmt.Errorf("failed to create listener: %v", err)
	}
	p.listener = listener

	// Connect to the SPIRE Agent's Workload API
	client, err := workloadapi.New(ctx, workloadapi.WithAddr(
		fmt.Sprintf("unix://%s", p.destinationSocket),
	))
	if err != nil {
		p.log.Error(err, "Failed to create workload API client")
		return fmt.Errorf("failed to create workload API client: %v", err)
	}
	p.client = client

	p.server = grpc.NewServer()
	sdsCtx, cancel := context.WithCancel(context.Background())

	sdsServer := &sdsServer{
		client:       client,
		trustDomain:  p.trustDomain,
		log:          p.log,
		mu:           sync.RWMutex{},
		lastVersions: make(map[string]string),
		updates:      make(chan *workloadapi.X509Context, 1000),
		watchCtx:     sdsCtx,
		watchCancel:  cancel,
		rateLimiter:  make(map[string]*RateLimit),
	}
	secretservice.RegisterSecretDiscoveryServiceServer(p.server, sdsServer)

	watcher := &sdsX509ContextWatcher{
		updates: sdsServer.updates,
		log:     sdsServer.log,
	}

	go func() {
		err := client.WatchX509Context(ctx, watcher)
		if err != nil {
			sdsServer.log.Error(err, "Failed to start X509 context watcher")
		}
	}()

	healthServer := health.NewServer()
	healthServer.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(p.server, healthServer)

	go func() {
		<-ctx.Done()
		p.server.GracefulStop()
		if p.client != nil {
			p.client.Close()
		}
	}()

	return p.server.Serve(listener)
}

func (p *WorkloadProxy) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// If already shutdown, return immediately
	if p.shutdown {
		return nil
	}
	p.shutdown = true

	// Stop the gRPC server gracefully if it exists
	if p.server != nil {
		p.server.GracefulStop()
	}

	// Close workload API client if it exists
	if p.client != nil {
		p.client.Close()
	}

	// Close listener if it exists
	if p.listener != nil {
		if err := p.listener.Close(); err != nil {
			p.log.Error(err, "Error closing listener")
		}
	}

	// Clean up socket file
	if err := os.Remove(p.sourceSocket); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove socket file: %w", err)
	}

	p.log.Info("Proxy stopped successfully",
		"source", p.sourceSocket,
		"destination", p.destinationSocket)

	return nil
}

type sdsServer struct {
	secretservice.UnimplementedSecretDiscoveryServiceServer
	client           *workloadapi.Client
	trustDomain      string
	log              logr.Logger
	mu               sync.RWMutex
	lastVersions     map[string]string
	updates          chan *workloadapi.X509Context
	watchCtx         context.Context
	watchCancel      context.CancelFunc
	watchedResources map[string]*WatchedResource
	rateLimiter      map[string]*RateLimit // resourceName -> RateLimit
	rateMu           sync.RWMutex
}

type WatchedResource struct {
	NonceSent  string
	NonceAcked string
	Resources  []string
}

func (s *sdsServer) DeltaSecrets(secretservice.SecretDiscoveryService_DeltaSecretsServer) error {
	return fmt.Errorf("delta secrets not implemented")
}

func (s *sdsServer) StreamSecrets(stream secretservice.SecretDiscoveryService_StreamSecretsServer) error {
	ctx := stream.Context()
	log := s.log.WithName("StreamSecrets")
	log.Info("Starting new SDS stream")

	reqCh := make(chan *discovery.DiscoveryRequest)
	errCh := make(chan error)

	// Track requests in separate goroutine
	go func() {
		for {
			req, err := stream.Recv()
			if err != nil {
				errCh <- err
				return
			}
			reqCh <- req
		}
	}()

	// Track last sent versions per resource
	versions := make(map[string]string)
	// Track current subscribed resources
	subscribed := make(map[string]struct{})

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case err := <-errCh:
			if err == io.EOF || status.Code(err) == codes.Canceled {
				log.Info("Stream closed normally")
				return nil
			}
			log.Error(err, "Stream error")
			return err

		case req := <-reqCh:
			if len(req.ResourceNames) == 0 {
				continue
			}

			// Handle each resource separately
			for _, resourceName := range req.ResourceNames {
				subscribed[resourceName] = struct{}{}

				// Check if version matches last sent version
				if lastVersion, exists := versions[resourceName]; exists {
					if lastVersion == req.VersionInfo {
						// Add 100ms latency for same version
						time.Sleep(5 * time.Second)
						log.V(1).Info("Added latency for same version",
							"resource", resourceName,
							"version", req.VersionInfo)
					}
				}

				// Create single-resource request
				singleReq := &discovery.DiscoveryRequest{
					TypeUrl:       req.TypeUrl,
					ResourceNames: []string{resourceName},
					VersionInfo:   req.VersionInfo,
				}

				// Get fresh secrets for this resource
				resp, err := s.FetchSecrets(ctx, singleReq)
				if err != nil {
					log.Error(err, "Failed to fetch secrets", "resource", resourceName)
					continue
				}

				// Update tracked version
				versions[resourceName] = resp.VersionInfo

				// Send individual response
				if err := stream.Send(resp); err != nil {
					log.Error(err, "Failed to send response", "resource", resourceName)
					return err
				}

				log.V(1).Info("Sent response",
					"resource", resourceName,
					"version", resp.VersionInfo)
			}

		case update := <-s.updates:
			// On SVID update, push new certs to all subscribed resources
			log.V(1).Info("Received SVID update", "numSVIDs", len(update.SVIDs))

			for resourceName := range subscribed {
				// Build discovery request for single resource
				req := &discovery.DiscoveryRequest{
					TypeUrl:       SecretType,
					ResourceNames: []string{resourceName},
				}

				// Fetch fresh secrets for this resource
				resp, err := s.FetchSecrets(ctx, req)
				if err != nil {
					log.Error(err, "Failed to fetch secrets after SVID update",
						"resource", resourceName)
					continue
				}

				// Send individual response
				if err := stream.Send(resp); err != nil {
					log.Error(err, "Failed to send update")
					return err
				}

				log.V(1).Info("Sent update after SVID change",
					"resource", resourceName,
					"version", resp.VersionInfo)
			}

		}
	}
}

func (s *sdsServer) getSpiffeIDForResource(resource string) (string, error) {
	switch {
	case resource == "ROOTCA":
		return "", nil
	case resource == "default":
		return fmt.Sprintf("spiffe://%s/ns/istio-system/sa/istio-ingressgateway", s.trustDomain), nil
	case strings.HasPrefix(resource, "file-cert:"):
		return s.convertFilePathToSpiffeID(resource)
	default:
		return "", fmt.Errorf("unknown resource type: %s", resource)
	}
}

func (s *sdsServer) FetchSecrets(ctx context.Context, req *discovery.DiscoveryRequest) (*discovery.DiscoveryResponse, error) {
	s.log.V(0).Info("FetchSecrets called", "resources", req.ResourceNames)

	s.mu.Lock()
	defer s.mu.Unlock()

	// Get all SVIDs once for this request
	svids, err := s.client.FetchX509SVIDs(ctx)
	//s.log.V(0).Info("Fetched SVIDs", "SVIDs", svids)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch SVIDs: %v", err)
	}

	// Debug log all available SVIDs
	for _, svid := range svids {
		s.log.V(-1).Info("Available SVID",
			"spiffeID", svid.ID.String(),
			"notBefore", svid.Certificates[0].NotBefore,
			"notAfter", svid.Certificates[0].NotAfter)
	}

	resources := make([]*anypb.Any, 0, len(req.ResourceNames))

	versions := make(map[string]string)

	for _, name := range req.ResourceNames {
		var secret *tlsv3.Secret
		var err error

		switch {
		case name == "ROOTCA":
			bundle, err := s.client.FetchX509Bundles(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to fetch trust bundle: %v", err)
			}

			// Get root certs from bundle
			trustDomain, err := spiffeid.TrustDomainFromString(s.trustDomain)
			if err != nil {
				return nil, fmt.Errorf("failed to parse trust domain: %v", err)
			}
			x509Bundle, err := bundle.GetX509BundleForTrustDomain(trustDomain)
			if err != nil {
				return nil, fmt.Errorf("failed to get trust bundle for trust domain: %v", err)
			}
			rootCerts := x509Bundle.X509Authorities()
			if len(rootCerts) == 0 {
				return nil, fmt.Errorf("no root certificates in trust bundle")
			}

			secret, err = s.createRootCASecret(rootCerts)
			if err != nil {
				return nil, err
			}

		case name == "default":
			expectedID := fmt.Sprintf("spiffe://%s/ns/istio-system/sa/istio-ingressgateway", s.trustDomain)
			var targetSVID *x509svid.SVID
			for _, svid := range svids {
				if svid.ID.String() == expectedID {
					targetSVID = svid
					break
				}
			}
			if targetSVID == nil {
				s.log.Error(nil, "No matching SVID found for default", "expectedID", expectedID)
				continue
			}
			secret = s.createTLSSecret(name, targetSVID)
			s.log.V(0).Info("Created default secret",
				"spiffeID", targetSVID.ID.String(),
				"notBefore", targetSVID.Certificates[0].NotBefore,
				"notAfter", targetSVID.Certificates[0].NotAfter)

		case strings.HasPrefix(name, "file-cert:"):
			spiffeID, err := s.convertFilePathToSpiffeID(name)
			if err != nil {
				s.log.Error(err, "Failed to convert file path to SPIFFE ID", "path", name)
				continue
			}
			s.log.V(0).Info("Looking for SVID", "spiffeID", spiffeID, "path", name)

			// Find the matching SVID
			var targetSVID *x509svid.SVID
			for _, svid := range svids {
				if svid.ID.String() == spiffeID {
					targetSVID = svid
					break
				}
			}
			if targetSVID == nil {
				s.log.Error(nil, "No matching SVID found for file-cert",
					"path", name,
					"spiffeID", spiffeID,
					"available_svids", fmt.Sprintf("%v", svids))
				continue
			}
			secret = s.createTLSSecret(name, targetSVID)
			s.log.V(0).Info("Created secret for file-cert",
				"path", name,
				"spiffeID", spiffeID,
				"notBefore", targetSVID.Certificates[0].NotBefore,
				"notAfter", targetSVID.Certificates[0].NotAfter)
		}

		if err != nil {
			s.log.Error(err, "Failed to create secret", "name", name)
			continue
		}

		if secret != nil {
			any, err := anypb.New(secret)
			if err != nil {
				s.log.Error(err, "Failed to marshal secret")
				continue
			}
			resources = append(resources, any)

			// Compute version for this specific resource
			resourceData := extractResourceData(secret)
			version := s.computeResourceVersion(name, resourceData)
			versions[name] = version
		}

	}

	combinedVersion := s.combineVersions(versions)
	s.log.V(0).Info("Computed versions",
		"resourceVersions", versions,
		"combinedVersion", combinedVersion,
		"numResources", len(resources))

	return &discovery.DiscoveryResponse{
		VersionInfo: combinedVersion,
		Resources:   resources,
		TypeUrl:     "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret",
		Nonce:       fmt.Sprintf("nonce-%s", combinedVersion),
	}, nil
}

func (s *sdsServer) computeResourceVersion(name string, data []byte) string {
	h := sha256.New()
	h.Write([]byte(name))
	h.Write(data)
	return fmt.Sprintf("sha256-%.32x", h.Sum(nil))
}

func (s *sdsServer) combineVersions(versions map[string]string) string {
	h := sha256.New()
	var names []string
	for name := range versions {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		h.Write([]byte(name))
		h.Write([]byte(versions[name]))
	}
	return fmt.Sprintf("sha256-%.32x", h.Sum(nil))
}

func extractResourceData(secret *tlsv3.Secret) []byte {
	var resourceData []byte
	switch t := secret.Type.(type) {
	case *tlsv3.Secret_TlsCertificate:
		if cert := t.TlsCertificate.GetCertificateChain(); cert != nil {
			resourceData = append(resourceData, cert.GetInlineBytes()...)
		}
		if key := t.TlsCertificate.GetPrivateKey(); key != nil {
			resourceData = append(resourceData, key.GetInlineBytes()...)
		}
		// Add expiry time to resource data to force updates
		if cert := t.TlsCertificate.GetCertificateChain(); cert != nil {
			block, _ := pem.Decode(cert.GetInlineBytes())
			if block != nil {
				if x509Cert, err := x509.ParseCertificate(block.Bytes); err == nil {
					resourceData = append(resourceData, []byte(x509Cert.NotAfter.String())...)
				}
			}
		}
	case *tlsv3.Secret_ValidationContext:
		if ca := t.ValidationContext.GetTrustedCa(); ca != nil {
			resourceData = append(resourceData, ca.GetInlineBytes()...)
			// Add expiry time from CA cert
			block, _ := pem.Decode(ca.GetInlineBytes())
			if block != nil {
				if x509Cert, err := x509.ParseCertificate(block.Bytes); err == nil {
					resourceData = append(resourceData, []byte(x509Cert.NotAfter.String())...)
				}
			}
		}
	}
	return resourceData
}

func (s *sdsServer) computeResourceHash(secret *tlsv3.Secret) string {
	h := sha256.New()

	h.Write([]byte(secret.Name))

	switch t := secret.Type.(type) {
	case *tlsv3.Secret_TlsCertificate:
		if cert := t.TlsCertificate.GetCertificateChain(); cert != nil {
			h.Write(cert.GetInlineBytes())
		}
		if key := t.TlsCertificate.GetPrivateKey(); key != nil {
			h.Write(key.GetInlineBytes())
		}
	case *tlsv3.Secret_ValidationContext:
		if ca := t.ValidationContext.GetTrustedCa(); ca != nil {
			h.Write(ca.GetInlineBytes())
		}
	}

	return fmt.Sprintf("sha256-%.32x", h.Sum(nil))
}

func (s *sdsServer) createRootCASecret(certs []*x509.Certificate) (*tlsv3.Secret, error) {
	return &tlsv3.Secret{
		Name: "ROOTCA",
		Type: &tlsv3.Secret_ValidationContext{
			ValidationContext: &tlsv3.CertificateValidationContext{
				TrustedCa: &core.DataSource{
					Specifier: &core.DataSource_InlineBytes{
						InlineBytes: pemEncodeCertChain(certs),
					},
				},
			},
		},
	}, nil
}

func (s *sdsServer) createTLSSecret(name string, svid *x509svid.SVID) *tlsv3.Secret {
	return &tlsv3.Secret{
		Name: name,
		Type: &tlsv3.Secret_TlsCertificate{
			TlsCertificate: &tlsv3.TlsCertificate{
				CertificateChain: &core.DataSource{
					Specifier: &core.DataSource_InlineBytes{
						InlineBytes: pemEncodeCertChain(svid.Certificates),
					},
				},
				PrivateKey: &core.DataSource{
					Specifier: &core.DataSource_InlineBytes{
						InlineBytes: pemEncodePrivateKey(svid.PrivateKey),
					},
				},
			},
		},
	}
}

// Example filePath: file-cert:/etc/istio/istio-system/app1/tls.crt~/etc/istio/istio-system/app1/tls.key
func (s *sdsServer) convertFilePathToSpiffeID(filePath string) (string, error) {
	path := strings.TrimPrefix(filePath, "file-cert:")

	parts := strings.Split(path, "~")
	if len(parts) < 1 {
		return "", fmt.Errorf("invalid file-cert path format")
	}

	certPath := parts[0]
	components := strings.Split(certPath, "/")

	var namespace, serviceAccount string
	for i, comp := range components {
		if comp == "istio" && i+2 < len(components) {
			namespace = components[i+1]
			serviceAccount = components[i+2]
			break
		}
	}

	if namespace == "" || serviceAccount == "" {
		return "", fmt.Errorf("could not extract namespace and service account from path %s", certPath)
	}

	return fmt.Sprintf("spiffe://%s/ns/%s/sa/%s", s.trustDomain, namespace, serviceAccount), nil
}

func pemEncodeCertChain(certs []*x509.Certificate) []byte {
	var pemData []byte
	for _, cert := range certs {
		pemBlock := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}
		pemData = append(pemData, pem.EncodeToMemory(pemBlock)...)
	}
	return pemData
}

func pemEncodePrivateKey(privateKey crypto.PrivateKey) []byte {
	pkcs8Key, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil
	}

	pemBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8Key,
	}
	return pem.EncodeToMemory(pemBlock)
}
