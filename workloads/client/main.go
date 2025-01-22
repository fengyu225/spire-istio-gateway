package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

func main() {
	serverURL := flag.String("server-url", "", "Server URL")
	certDir := flag.String("cert-dir", "", "Directory containing TLS certificates")
	flag.Parse()

	// Load client certificates
	cert, err := tls.LoadX509KeyPair(
		fmt.Sprintf("%s/svid.pem", *certDir),
		fmt.Sprintf("%s/svid_key.pem", *certDir),
	)
	if err != nil {
		log.Fatalf("Failed to load certificates: %v", err)
	}

	// Load CA bundle
	bundle, err := ioutil.ReadFile(fmt.Sprintf("%s/svid_bundle.pem", *certDir))
	if err != nil {
		log.Fatalf("Failed to load CA bundle: %v", err)
	}

	bundlePool := x509.NewCertPool()
	bundlePool.AppendCertsFromPEM(bundle)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
				RootCAs:      bundlePool,
			},
		},
	}

	resp, err := client.Get(*serverURL)
	if err != nil {
		log.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Failed to read response: %v", err)
	}

	log.Printf("Server response: %s", string(body))
}
