package main

import (
	"certificate"
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Client struct {
	sync.RWMutex
	transport *http.Transport
	client    *http.Client
}

func newClient() *Client {
	return &Client{
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func formatName(name pkix.Name) string {
	var parts []string
	if name.CommonName != "" {
		parts = append(parts, fmt.Sprintf("CN=%s", name.CommonName))
	}
	for _, org := range name.Organization {
		parts = append(parts, fmt.Sprintf("O=%s", org))
	}
	for _, orgUnit := range name.OrganizationalUnit {
		parts = append(parts, fmt.Sprintf("OU=%s", orgUnit))
	}
	for _, country := range name.Country {
		parts = append(parts, fmt.Sprintf("C=%s", country))
	}
	for _, locality := range name.Locality {
		parts = append(parts, fmt.Sprintf("L=%s", locality))
	}
	for _, province := range name.Province {
		parts = append(parts, fmt.Sprintf("ST=%s", province))
	}
	return strings.Join(parts, ", ")
}

func logCertificateInfo(cert *x509.Certificate) {
	log.Printf("Certificate Information:")
	log.Printf("  Subject: %s", formatName(cert.Subject))
	log.Printf("  Not Before: %s", cert.NotBefore.Format(time.RFC3339))
	log.Printf("  Not After: %s", cert.NotAfter.Format(time.RFC3339))
	log.Printf("  Time until expiration: %s", time.Until(cert.NotAfter).Round(time.Second))
}

func (c *Client) updateTransport(cert *tls.Certificate, pool *x509.CertPool) {
	c.Lock()
	defer c.Unlock()

	c.transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{*cert},
			RootCAs:      pool,
			MinVersion:   tls.VersionTLS12,
			VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
				if len(verifiedChains) > 0 && len(verifiedChains[0]) > 0 {
					logCertificateInfo(verifiedChains[0][0])
				}
				return nil
			},
		},
		ForceAttemptHTTP2:     true,
		DisableKeepAlives:     true, // Disable keep-alives
		MaxIdleConns:          -1,   // Disable connection pooling
		IdleConnTimeout:       1 * time.Millisecond,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	c.client.Transport = c.transport
}

func main() {
	serverURL := flag.String("server-url", "https://localhost:8443", "Server URL")
	certDir := flag.String("cert-dir", "./certs", "Directory containing certificates")
	flag.Parse()

	client := newClient()

	certManager, err := certificate.NewCertManager(*certDir, client.updateTransport)
	if err != nil {
		log.Fatalf("Failed to initialize certificate manager: %v", err)
	}
	defer certManager.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go certManager.Start(ctx)

	time.Sleep(1 * time.Second)

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	requestCount := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			requestCount++
			log.Printf("\nMaking request #%d", requestCount)

			func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()

				req, err := http.NewRequestWithContext(ctx, "GET", *serverURL, nil)
				if err != nil {
					log.Printf("Failed to create request: %v", err)
					return
				}
				req.Close = true
				resp, err := client.client.Do(req)
				if err != nil {
					log.Printf("Request failed: %v", err)
					return
				}
				defer resp.Body.Close()
			}()
		}
	}
}
