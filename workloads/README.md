# SPIRE Workload Certificate Auto-Reload Example

This project demonstrates:
- SPIRE issues workload X.509 SVID
- spiffe-helper sidecar request and refresh certificates from SPIRE
- Golang workloads reloads TLS certificate at runtime, enabling zero-downtime certificate updates.

## Overview

When using SPIRE for workload identity:
1. SPIRE issues X.509-SVIDs to workloads
2. spiffe-helper writes these certificates to files
3. Workloads detect and reload these certificate changes
4. TLS connections need to be updated with the new certificates

## SPIRE Certificate Flow

```
SPIRE Server 
    ↓ (issues X.509-SVID)
SPIRE Agent
    ↓ (workload attestation)
spiffe-helper
    ↓ (writes to files)
Certificate Files (svid.pem, key.pem, bundle.pem)
    ↓ (file system events)
Application (this example)
    ↓ (updates TLS config)
TLS Connections
```

## Certificate Files

spiffe-helper manages these files:

- `svid.pem`: The X.509-SVID certificate
- `svid_key.pem`: The private key
- `svid_bundle.pem`: The trust bundle containing the X.509 root certificates

## Runtime Certificate Reloading

### Certificate Manager

The `CertManager` component handles certificate reloading:

```go
func NewCertManager(certDir string, callback func(*tls.Certificate, *x509.CertPool)) (*CertManager, error) {
    // Initialize file watcher
    // Set up certificate management
    // Handle updates
}
```

- Watches for file system events on certificate files
- Validates new certificates before using them
- Updates TLS configuration atomically
- Provides callbacks for certificate updates
- Implements periodic reloading as backup

## Running with SPIRE

1. Deploy SPIRE server and agent:
```bash
cd spire
kubectl apply -k . 
```

2. Deploy spiffe-helper:
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: spiffe-helper
spec:
  template:
    spec:
      containers:
      - name: spiffe-helper
        image: spiffe/spiffe-helper:latest
        args:
        - -config
        - /etc/spiffe-helper/helper.conf
        volumeMounts:
        - name: helper-config
          mountPath: /etc/spiffe-helper
        - name: certs
          mountPath: /run/spire/certs
```

4. Configure spiffe-helper:
```json
{
  "certDir": "/run/spire/certs",
  "svidFileName": "svid.pem",
  "svidKeyFileName": "svid_key.pem",
  "svidBundleFileName": "svid_bundle.pem",
  "renewSignal": "SIGHUP"
}
```

5. Deploy application:
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp
spec:
  template:
    spec:
      containers:
      - name: myapp
        image: myapp:latest
        args:
        - --cert-dir=/run/spire/certs
        volumeMounts:
        - name: certs
          mountPath: /run/spire/certs
          readOnly: true
      volumes:
      - name: certs
        emptyDir: {}
```

## Certificate Rotation Process

1. SPIRE Agent receives new X.509-SVID from SPIRE Server
2. spiffe-helper detects the new certificate
3. spiffe-helper writes new certificates to the shared volume
4. Application's CertManager detects file changes
5. CertManager validates and loads new certificates
6. TLS configuration is updated for new connections

## Testing Certificate Rotation

1. Deploy server and client workloads:
```bash
cd workloads/deployment
kubectl apply -k .
```

2. Check client logs:
```bash
kubectl logs -l app=client -n spiffe-demo -f
```

You should see:
```
2025/01/23 16:43:09 Certificate Information:
2025/01/23 16:43:09   Subject: CN=server-service, O=SPIRE, C=US
2025/01/23 16:43:09   Not Before: 2025-01-23T16:42:55Z
2025/01/23 16:43:09   Not After: 2025-01-23T16:43:15Z
2025/01/23 16:43:09   Time until expiration: 5s
```