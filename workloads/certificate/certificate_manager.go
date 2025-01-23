package certificate

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

type CertManager struct {
	sync.RWMutex
	certDir     string
	certificate tls.Certificate
	certPool    *x509.CertPool
	watcher     *fsnotify.Watcher
	callback    func(*tls.Certificate, *x509.CertPool)

	cachedCertPEM   []byte
	cachedKeyPEM    []byte
	cachedBundlePEM []byte
}

func NewCertManager(certDir string, callback func(*tls.Certificate, *x509.CertPool)) (*CertManager, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to create watcher: %v", err)
	}

	cm := &CertManager{
		certDir:  certDir,
		certPool: x509.NewCertPool(),
		watcher:  watcher,
		callback: callback,
	}

	// Initial load of certificates
	if err := cm.loadCertificates(); err != nil {
		watcher.Close()
		return nil, fmt.Errorf("initial certificate load failed: %v", err)
	}

	if err := watcher.Add(certDir); err != nil {
		watcher.Close()
		return nil, fmt.Errorf("failed to watch directory: %v", err)
	}

	return cm, nil
}

func (cm *CertManager) loadCertificates() error {
	cm.Lock()
	defer cm.Unlock()

	certPath := filepath.Join(cm.certDir, "svid.pem")
	keyPath := filepath.Join(cm.certDir, "svid_key.pem")
	bundlePath := filepath.Join(cm.certDir, "svid_bundle.pem")

	// Read all files
	certPEM, err := ioutil.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("failed to read cert: %v", err)
	}

	keyPEM, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("failed to read key: %v", err)
	}

	bundlePEM, err := ioutil.ReadFile(bundlePath)
	if err != nil {
		return fmt.Errorf("failed to read bundle: %v", err)
	}

	// Check if certificates have changed
	if bytes.Equal(cm.cachedCertPEM, certPEM) &&
		bytes.Equal(cm.cachedKeyPEM, keyPEM) &&
		bytes.Equal(cm.cachedBundlePEM, bundlePEM) {
		return nil
	}

	// Try to load new certificates
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("failed to parse cert/key: %v", err)
	}

	// Parse the leaf certificate
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return fmt.Errorf("failed to parse leaf certificate: %v", err)
	}
	cert.Leaf = leaf

	// Create new cert pool and add the CA bundle
	newPool := x509.NewCertPool()
	if !newPool.AppendCertsFromPEM(bundlePEM) {
		return fmt.Errorf("failed to parse CA bundle")
	}

	// Verify the certificate chain
	opts := x509.VerifyOptions{
		Roots:       newPool,
		CurrentTime: time.Now(),
	}
	if _, err := cert.Leaf.Verify(opts); err != nil {
		return fmt.Errorf("certificate verification failed: %v", err)
	}

	// Update cache and certificates
	cm.cachedCertPEM = certPEM
	cm.cachedKeyPEM = keyPEM
	cm.cachedBundlePEM = bundlePEM
	cm.certificate = cert
	cm.certPool = newPool

	log.Printf("Certificates reloaded successfully")

	// Notify callback if set
	if cm.callback != nil {
		go cm.callback(&cm.certificate, cm.certPool)
	}

	return nil
}

func (cm *CertManager) Start(ctx context.Context) {
	go cm.watchEvents(ctx)

	// Periodic reload as backup
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			cm.watcher.Close()
			return
		case <-ticker.C:
			if err := cm.loadCertificates(); err != nil {
				log.Printf("Periodic certificate reload failed: %v", err)
			}
		}
	}
}

func (cm *CertManager) watchEvents(ctx context.Context) {
	// Use debouncing to prevent multiple rapid reloads
	var debounceTimer *time.Timer
	debounceInterval := 100 * time.Millisecond

	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-cm.watcher.Events:
			if !ok {
				return
			}

			// Only handle write and create events
			if event.Op&(fsnotify.Write|fsnotify.Create) != 0 {
				// Reset or create debounce timer
				if debounceTimer != nil {
					debounceTimer.Stop()
				}
				debounceTimer = time.AfterFunc(debounceInterval, func() {
					if err := cm.loadCertificates(); err != nil {
						log.Printf("Failed to reload certificates after change: %v", err)
					}
				})
			}
		case err, ok := <-cm.watcher.Errors:
			if !ok {
				return
			}
			log.Printf("Watch error: %v", err)
		}
	}
}

func (cm *CertManager) GetCertificate() *tls.Certificate {
	cm.RLock()
	defer cm.RUnlock()
	return &cm.certificate
}

func (cm *CertManager) GetCertPool() *x509.CertPool {
	cm.RLock()
	defer cm.RUnlock()
	return cm.certPool
}

func (cm *CertManager) Close() error {
	return cm.watcher.Close()
}
