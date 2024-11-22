package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spiffe/go-spiffe/v2/workloadapi"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func extractAppName(spiffeID string) string {
	parts := strings.Split(spiffeID, "/")
	return parts[len(parts)-1]
}

func certsToBytes(certs []*x509.Certificate) []byte {
	var pemData []byte
	for _, cert := range certs {
		b := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})
		pemData = append(pemData, b...)
	}
	return pemData
}

func encodeSPIFFEIDForLabel(spiffeID string) string {
	// Replace invalid characters with '-'
	// This will convert "spiffe://example.org/ns/istio-system/sa/app1"
	// to something like "spiffe-example-org-ns-istio-system-sa-app1"
	return strings.NewReplacer(
		":", "-",
		"/", "-",
		".", "-",
		"@", "-",
		"//", "-",
	).Replace(spiffeID)
}

type SVIDWatcher struct {
	client         *kubernetes.Clientset
	workloadClient *workloadapi.Client
	namespace      string
	ctx            context.Context
	knownSVIDs     sync.Map
	updateCh       chan *workloadapi.X509Context
	mu             sync.Mutex
}

func (w *SVIDWatcher) startPeriodicCleanup(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-w.ctx.Done():
				return
			case <-ticker.C:
				if err := w.cleanupOrphanedSecrets(); err != nil {
					log.Printf("Error during periodic cleanup: %v", err)
				}
			}
		}
	}()
}

func (w *SVIDWatcher) cleanupOrphanedSecrets() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	log.Printf("Cleaning up orphaned secrets...")
	secrets, err := w.client.CoreV1().Secrets(w.namespace).List(w.ctx, metav1.ListOptions{
		LabelSelector: labels.Set{"managed-by": "svid-secret-sync"}.String(),
	})
	if err != nil {
		return err
	}

	x509Context, err := w.workloadClient.FetchX509Context(w.ctx)
	if err != nil {
		return err
	}

	currentSVIDs := make(map[string]bool)
	for _, svid := range x509Context.SVIDs {
		currentSVIDs[svid.ID.String()] = true
	}

	for _, secret := range secrets.Items {
		log.Printf("Checking secret %s", secret.Name)
		spiffeID := secret.Annotations["spiffeid"]
		if spiffeID == "" {
			log.Printf("Skipping secret %s with no spiffeid annotation", secret.Name)
			continue
		}

		if !currentSVIDs[spiffeID] {
			log.Printf("Cleaning up orphaned secret for SVID: %s", spiffeID)
			err := w.client.CoreV1().Secrets(w.namespace).Delete(w.ctx, secret.Name, metav1.DeleteOptions{})
			if err != nil {
				log.Printf("Failed to delete orphaned secret %s: %v", secret.Name, err)
			}
		}
	}

	return nil
}

func (w *SVIDWatcher) OnX509ContextUpdate(update *workloadapi.X509Context) {
	updateCopy := *update

	go func() {
		select {
		case <-w.ctx.Done():
			return
		case w.updateCh <- &updateCopy:
			log.Printf("Queued update with %d SVIDs", len(updateCopy.SVIDs))
		}
	}()
}

func (w *SVIDWatcher) processUpdates() {
	for {
		select {
		case <-w.ctx.Done():
			return
		case update := <-w.updateCh:
			w.handleUpdate(update)
		}
	}
}

func (w *SVIDWatcher) handleUpdate(update *workloadapi.X509Context) {
	w.mu.Lock()
	defer w.mu.Unlock()
	currentSVIDs := make(map[string]bool)

	for _, svid := range update.SVIDs {
		spiffeID := svid.ID.String()
		appName := extractAppName(spiffeID)
		currentSVIDs[spiffeID] = true

		log.Printf("Processing SVID for %s", spiffeID)

		certPEM := certsToBytes(svid.Certificates)

		privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(svid.PrivateKey)
		if err != nil {
			log.Printf("Failed to marshal private key for %s: %v", spiffeID, err)
			continue
		}
		keyPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: privateKeyBytes,
		})

		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      appName + "-credential",
				Namespace: w.namespace,
				Labels: map[string]string{
					"managed-by": "svid-secret-sync",
					"spiffeid":   encodeSPIFFEIDForLabel(spiffeID),
				},
				Annotations: map[string]string{
					"last-updated": time.Now().Format(time.RFC3339),
					"spiffeid":     spiffeID,
				},
			},
			Type: corev1.SecretTypeTLS,
			Data: map[string][]byte{
				"tls.crt": certPEM,
				"tls.key": keyPEM,
			},
		}

		_, err = w.client.CoreV1().Secrets(w.namespace).Update(w.ctx, secret, metav1.UpdateOptions{})
		if err != nil {
			_, err = w.client.CoreV1().Secrets(w.namespace).Create(w.ctx, secret, metav1.CreateOptions{})
			if err != nil {
				log.Printf("Failed to create/update secret for %s: %v", spiffeID, err)
				continue
			}
		}

		w.knownSVIDs.Store(spiffeID, appName)
		log.Printf("Successfully updated secret for %s", spiffeID)
	}

	// Check for deleted SVIDs
	w.knownSVIDs.Range(func(key, value interface{}) bool {
		spiffeID := key.(string)
		appName := value.(string)

		if !currentSVIDs[spiffeID] {
			log.Printf("SVID %s no longer exists, deleting secret", spiffeID)
			err := w.client.CoreV1().Secrets(w.namespace).Delete(w.ctx, appName+"-credential", metav1.DeleteOptions{})
			if err != nil {
				log.Printf("Failed to delete secret for %s: %v", spiffeID, err)
			} else {
				w.knownSVIDs.Delete(spiffeID)
			}
		}
		return true
	})
}

func (w *SVIDWatcher) OnX509ContextWatchError(err error) {
	log.Printf("X509 context watch error: %v", err)
}

func (w *SVIDWatcher) Watch(ctx context.Context) error {
	w.ctx = ctx
	go w.processUpdates()
	w.startPeriodicCleanup(1 * time.Minute)
	return w.workloadClient.WatchX509Context(ctx, w)
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-signalChan
		cancel()
	}()

	config, err := rest.InClusterConfig()
	if err != nil {
		log.Fatalf("Failed to get kubernetes config: %v", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatalf("Failed to create kubernetes client: %v", err)
	}

	workloadClient, err := workloadapi.New(ctx, workloadapi.WithAddr("unix:///run/secrets/workload-spiffe-uds/socket"))
	if err != nil {
		log.Fatalf("Failed to create workload API client: %v", err)
	}
	defer workloadClient.Close()

	watcher := &SVIDWatcher{
		client:         clientset,
		workloadClient: workloadClient,
		namespace:      "istio-system",
		updateCh:       make(chan *workloadapi.X509Context),
		mu:             sync.Mutex{},
	}

	log.Printf("Starting SVID watcher...")
	if err := watcher.Watch(ctx); err != nil {
		log.Fatalf("Watcher failed: %v", err)
	}
}
