package main

import (
	"certificate"
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

type Server struct {
	sync.RWMutex
	server      *http.Server
	certManager *certificate.CertManager
}

func NewServer(addr string, certDir string) (*Server, error) {
	srv := &Server{}

	certManager, err := certificate.NewCertManager(certDir, srv.updateCertificates)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize certificate manager: %v", err)
	}

	httpServer := &http.Server{
		Addr: addr,
		TLSConfig: &tls.Config{
			GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				cert := certManager.GetCertificate()
				return cert, nil
			},
			MinVersion: tls.VersionTLS12,
		},
	}

	srv.server = httpServer
	srv.certManager = certManager

	mux := http.NewServeMux()
	mux.HandleFunc("/", srv.handleRoot)
	httpServer.Handler = mux

	return srv, nil
}

func (s *Server) updateCertificates(cert *tls.Certificate, pool *x509.CertPool) {
	log.Println("Server certificates updated")
}

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Server running with TLS! Current time: %s\n", time.Now().Format(time.RFC3339))
}

func (s *Server) Start(ctx context.Context) error {
	go s.certManager.Start(ctx)

	errCh := make(chan error, 1)
	go func() {
		log.Printf("Starting server on %s", s.server.Addr)
		if err := s.server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			errCh <- fmt.Errorf("server error: %v", err)
		}
		close(errCh)
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		return s.Stop()
	}
}

func (s *Server) Stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := s.server.Shutdown(ctx); err != nil {
		return fmt.Errorf("server shutdown failed: %v", err)
	}

	if err := s.certManager.Close(); err != nil {
		return fmt.Errorf("certificate manager close failed: %v", err)
	}

	return nil
}

func main() {
	addr := flag.String("addr", ":8443", "Server address")
	certDir := flag.String("cert-dir", "./certs", "Directory containing certificates")
	flag.Parse()

	server, err := NewServer(*addr, *certDir)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Printf("Received signal: %v", sig)
		cancel()
	}()

	if err := server.Start(ctx); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
