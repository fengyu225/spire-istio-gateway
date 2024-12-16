package proxy

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"strings"
)

type jwks struct {
	Keys []struct {
		Kid string `json:"kid"`
		Kty string `json:"kty"`
		Alg string `json:"alg"`
		Use string `json:"use"`
		N   string `json:"n"`
		E   string `json:"e"`
	} `json:"keys"`
}

type tokenClaims struct {
	Issuer       string `json:"iss"`
	Sub          string `json:"sub"`
	KubernetesIO struct {
		Namespace      string `json:"namespace"`
		ServiceAccount struct {
			Name string `json:"name"`
		} `json:"serviceaccount"`
	} `json:"kubernetes.io"`
}

func (p *WorkloadProxy) getPublicKey(token string) (*rsa.PublicKey, error) {
	// Decode header to get kid
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode header: %v", err)
	}

	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("failed to parse header: %v", err)
	}

	p.log.V(1).Info("Parsed token header", "algorithm", header.Alg, "keyID", header.Kid)

	if header.Alg != "RS256" {
		p.log.Error(nil, "Invalid token algorithm", "algorithm", header.Alg, "expected", "RS256")
		return nil, fmt.Errorf("invalid algorithm: %s", header.Alg)
	}

	// Get JWKS URL from token issuer
	issuer, err := p.getTokenIssuer(token)
	if err != nil {
		return nil, fmt.Errorf("failed to get token issuer: %v", err)
	}

	p.log.V(1).Info("Getting JWKS for issuer", "issuer", issuer)

	// Get OIDC configuration
	configURL := fmt.Sprintf("%s/.well-known/openid-configuration", strings.TrimSuffix(issuer, "/"))
	resp, err := http.Get(configURL)
	if err != nil {
		p.log.Error(err, "Failed to get OIDC configuration", "url", configURL)
		return nil, fmt.Errorf("failed to get OIDC configuration: %v", err)
	}
	defer resp.Body.Close()

	var oidcConfig struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&oidcConfig); err != nil {
		p.log.Error(err, "Failed to decode OIDC config")
		return nil, fmt.Errorf("failed to decode OIDC config: %v", err)
	}

	p.log.V(1).Info("Found JWKS URI", "uri", oidcConfig.JWKSURI)

	// Get JWKS
	resp, err = http.Get(oidcConfig.JWKSURI)
	if err != nil {
		p.log.Error(err, "Failed to get JWKS", "url", oidcConfig.JWKSURI)
		return nil, fmt.Errorf("failed to get JWKS: %v", err)
	}
	defer resp.Body.Close()

	var jwks jwks
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		p.log.Error(err, "Failed to decode JWKS")
		return nil, fmt.Errorf("failed to decode JWKS: %v", err)
	}

	p.log.V(2).Info("Retrieved JWKS", "numKeys", len(jwks.Keys))

	// Find key by kid
	for _, key := range jwks.Keys {
		if key.Kid == header.Kid {
			p.log.V(1).Info("Found matching key", "keyID", key.Kid)

			// Convert to RSA public key
			n, err := base64.RawURLEncoding.DecodeString(key.N)
			if err != nil {
				p.log.Error(err, "Failed to decode key modulus")
				return nil, fmt.Errorf("failed to decode key modulus: %v", err)
			}
			e, err := base64.RawURLEncoding.DecodeString(key.E)
			if err != nil {
				p.log.Error(err, "Failed to decode key exponent")
				return nil, fmt.Errorf("failed to decode key exponent: %v", err)
			}

			var exponent int
			for i := 0; i < len(e); i++ {
				exponent = exponent<<8 + int(e[i])
			}

			return &rsa.PublicKey{
				N: new(big.Int).SetBytes(n),
				E: exponent,
			}, nil
		}
	}

	p.log.Error(nil, "Key not found", "keyID", header.Kid, "availableKeys", len(jwks.Keys))
	return nil, fmt.Errorf("key not found: %s", header.Kid)
}

func (p *WorkloadProxy) getTokenIssuer(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid token format")
	}

	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("failed to decode claims: %v", err)
	}

	var claims struct {
		Issuer string `json:"iss"`
	}
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return "", fmt.Errorf("failed to parse claims: %v", err)
	}

	return claims.Issuer, nil
}

func (p *WorkloadProxy) validateToken(token string) error {
	p.log.V(1).Info("Starting token validation")

	// Get public key and verify signature
	pubKey, err := p.getPublicKey(token)
	if err != nil {
		p.log.Error(err, "Failed to get public key")
		return fmt.Errorf("failed to get public key: %v", err)
	}

	parts := strings.Split(token, ".")
	signedData := []byte(parts[0] + "." + parts[1])
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		p.log.Error(err, "Failed to decode signature")
		return fmt.Errorf("failed to decode signature: %v", err)
	}

	// Verify signature
	hashed := sha256.Sum256(signedData)
	if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hashed[:], signature); err != nil {
		p.log.Error(err, "Signature verification failed")
		return fmt.Errorf("signature verification failed: %v", err)
	}

	p.log.V(1).Info("Token signature verified successfully")

	// Decode and verify claims
	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		p.log.Error(err, "Failed to decode claims")
		return fmt.Errorf("failed to decode claims: %v", err)
	}

	var claims tokenClaims
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		p.log.Error(err, "Failed to parse claims")
		return fmt.Errorf("failed to parse claims: %v", err)
	}

	p.log.V(2).Info("Parsed token claims",
		"subject", claims.Sub,
		"namespace", claims.KubernetesIO.Namespace,
		"serviceAccount", claims.KubernetesIO.ServiceAccount.Name)

	// Validate namespace and service account
	if claims.KubernetesIO.Namespace != "istio-system" {
		p.log.Error(nil, "Invalid namespace",
			"expected", "istio-system",
			"actual", claims.KubernetesIO.Namespace)
		return fmt.Errorf("invalid namespace: got %s, want istio-system", claims.KubernetesIO.Namespace)
	}
	if claims.KubernetesIO.ServiceAccount.Name != "istio-ingressgateway-service-account" {
		p.log.Error(nil, "Invalid service account",
			"expected", "istio-ingressgateway-service-account",
			"actual", claims.KubernetesIO.ServiceAccount.Name)
		return fmt.Errorf("invalid service account: got %s, want istio-ingressgateway-service-account", claims.KubernetesIO.ServiceAccount.Name)
	}

	p.log.V(1).Info("Token claims validation successful",
		"namespace", claims.KubernetesIO.Namespace,
		"serviceAccount", claims.KubernetesIO.ServiceAccount.Name)

	return nil
}

func (p *WorkloadProxy) validateVolumeContext() error {
	p.log.V(1).Info("Starting volume context validation")

	if p.volumeContext == nil {
		return fmt.Errorf("volume context is not available")
	}

	// Get token data from volume context
	tokenData := p.volumeContext["csi.storage.k8s.io/serviceAccount.tokens"]
	if tokenData == "" {
		p.log.Error(nil, "Service account token not found in volume context")
		return fmt.Errorf("service account token not found in volume context")
	}

	// Parse tokens
	var tokens map[string]struct {
		Token               string `json:"token"`
		ExpirationTimestamp string `json:"expirationTimestamp"`
	}
	if err := json.Unmarshal([]byte(tokenData), &tokens); err != nil {
		p.log.Error(err, "Failed to parse token data")
		return fmt.Errorf("failed to parse token data: %v", err)
	}

	// Get token for our trust domain
	audience := fmt.Sprintf("spiffe://%s", p.trustDomain)
	tokenInfo, ok := tokens[audience]
	if !ok {
		p.log.Error(nil, "Token not found for audience", "audience", audience)
		return fmt.Errorf("token not found for audience %s", audience)
	}

	p.log.V(2).Info("Found token for audience",
		"audience", audience,
		"expiration", tokenInfo.ExpirationTimestamp)

	// Get own service account token
	ownToken, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		p.log.Error(err, "Failed to read proxy service account token")
		return fmt.Errorf("failed to read proxy service account token: %v", err)
	}
	if len(ownToken) == 0 {
		p.log.Error(nil, "Proxy service account token is empty")
		return fmt.Errorf("proxy service account token is empty")
	}

	p.log.V(2).Info("Read proxy service account token",
		"tokenLength", len(ownToken))

	// Get and compare issuers
	ownIssuer, err := p.getTokenIssuer(string(ownToken))
	if err != nil {
		p.log.Error(err, "Failed to get proxy token issuer")
		return fmt.Errorf("failed to get proxy token issuer: %v", err)
	}

	clientIssuer, err := p.getTokenIssuer(tokenInfo.Token)
	if err != nil {
		p.log.Error(err, "Failed to get client token issuer")
		return fmt.Errorf("failed to get client token issuer: %v", err)
	}

	p.log.V(2).Info("Comparing token issuers",
		"proxyIssuer", ownIssuer,
		"clientIssuer", clientIssuer)

	if clientIssuer != ownIssuer {
		p.log.Error(nil, "Token issuer mismatch",
			"expected", ownIssuer,
			"actual", clientIssuer)
		return fmt.Errorf("token issuer mismatch: got %s, want %s", clientIssuer, ownIssuer)
	}

	// Validate token signature and claims
	if err := p.validateToken(tokenInfo.Token); err != nil {
		p.log.Error(err, "Token validation failed")
		return fmt.Errorf("token validation failed: %v", err)
	}

	p.log.V(1).Info("Volume context validation successful")
	return nil
}
