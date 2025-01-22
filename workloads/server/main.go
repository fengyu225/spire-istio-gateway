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
	port := flag.String("port", "8443", "Server port")
	certDir := flag.String("cert-dir", "", "Directory containing TLS certificates")
	flag.Parse()

	// Load certificates
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

	server := &http.Server{
		Addr: fmt.Sprintf(":%s", *port),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "Hello from secure server!")
		}),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			ClientCAs:    bundlePool,
			ClientAuth:   tls.RequireAndVerifyClientCert,
		},
	}

	log.Printf("Starting server on port %s", *port)
	log.Fatal(server.ListenAndServeTLS("", ""))
}
