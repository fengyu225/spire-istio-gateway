#!/bin/bash

# Set Vault environment variables
VAULT_ADDR='https://127.0.0.1:8200'
VAULT_TOKEN='root'
VAULT_SKIP_VERIFY='true'

# Export them for the current shell
export VAULT_ADDR VAULT_TOKEN VAULT_SKIP_VERIFY

# Wait for Vault to be ready
until docker-compose exec -T vault sh -c 'VAULT_ADDR=https://127.0.0.1:8200 vault status -tls-skip-verify' > /dev/null 2>&1; do
    echo "Waiting for Vault to start..."
    sleep 1
done

# Enable PKI secret engine at path pki_root
docker-compose exec -T vault sh -c 'VAULT_ADDR=https://127.0.0.1:8200 VAULT_TOKEN=root vault secrets enable -tls-skip-verify -path=pki_root pki'
docker-compose exec -T vault sh -c 'VAULT_ADDR=https://127.0.0.1:8200 VAULT_TOKEN=root vault secrets tune -tls-skip-verify -max-lease-ttl=87600h pki_root'

# Generate root CA and save its information
docker-compose exec -T vault sh -c 'VAULT_ADDR=https://127.0.0.1:8200 VAULT_TOKEN=root vault write -tls-skip-verify pki_root/root/generate/internal \
    common_name="Root CA" \
    ttl=87600h \
    issuer_name="root-2025" \
    key_type="rsa" \
    key_bits=4096'

# Configure CRL and issuer URLs
docker-compose exec -T vault sh -c 'VAULT_ADDR=https://127.0.0.1:8200 VAULT_TOKEN=root vault write -tls-skip-verify pki_root/config/urls \
    issuing_certificates="https://vault:8200/v1/pki_root/ca" \
    crl_distribution_points="https://vault:8200/v1/pki_root/crl"'

# Enable cert auth method with custom max TTL
docker-compose exec -T vault sh -c 'VAULT_ADDR=https://127.0.0.1:8200 VAULT_TOKEN=root vault auth enable -tls-skip-verify cert'
docker-compose exec -T vault sh -c 'VAULT_ADDR=https://127.0.0.1:8200 VAULT_TOKEN=root vault auth tune -tls-skip-verify -max-lease-ttl=87600h cert'

# Generate client certificate with proper CN and O fields
mkdir -p vault/certs
openssl genrsa -out vault/certs/client.key 4096
openssl req -new -key vault/certs/client.key -out vault/certs/client.csr \
    -subj "/CN=spire-client/O=SPIRE"
openssl x509 -req -in vault/certs/client.csr \
    -signkey vault/certs/client.key \
    -out vault/certs/client.crt \
    -days 3650 \
    -sha256

# Create policy for PKI access
docker-compose exec -T vault sh -c 'VAULT_ADDR=https://127.0.0.1:8200 VAULT_TOKEN=root vault policy write -tls-skip-verify pki-policy - <<EOF
path "pki_root/root/sign-intermediate" {
  capabilities = ["create", "update"]
}

path "pki_root/cert/ca" {
  capabilities = ["read"]
}

path "pki_root/crl" {
  capabilities = ["read"]
}

path "auth/cert/login" {
  capabilities = ["create", "read"]
}

path "pki_root/config/*" {
  capabilities = ["read"]
}
EOF'

# Configure cert auth with display name and policy
docker-compose exec -T vault sh -c 'VAULT_ADDR=https://127.0.0.1:8200 VAULT_TOKEN=root vault write -tls-skip-verify auth/cert/certs/spire-client \
    display_name="spire-client" \
    policies="pki-policy" \
    certificate=@/vault/certs/client.crt \
    ttl=87600h \
    allowed_common_names="spire-client" \
    allowed_organizations="SPIRE" \
    require_matching_certificates=true'

# Save CA certificate
docker-compose exec -T vault sh -c 'VAULT_ADDR=https://127.0.0.1:8200 VAULT_TOKEN=root vault read -tls-skip-verify -field=certificate pki_root/cert/ca' > vault/certs/ca.crt

echo "Vault setup complete!"
echo "Client certificate: vault/certs/client.crt"
echo "Client key: vault/certs/client.key"
echo "CA certificate: vault/certs/ca.crt"
echo ""
echo "UI Access:"
echo "URL: https://localhost:8200"
echo "Token: root"

# Verify the setup
echo -e "\nVerifying auth methods..."
docker-compose exec -T vault sh -c 'VAULT_ADDR=https://127.0.0.1:8200 VAULT_TOKEN=root vault auth list -tls-skip-verify'

echo -e "\nVerifying certificate auth configuration..."
docker-compose exec -T vault sh -c 'VAULT_ADDR=https://127.0.0.1:8200 VAULT_TOKEN=root vault read -tls-skip-verify auth/cert/certs/spire-client'

echo -e "\nVerifying policy..."
docker-compose exec -T vault sh -c 'VAULT_ADDR=https://127.0.0.1:8200 VAULT_TOKEN=root vault policy read -tls-skip-verify pki-policy'

echo -e "\nVerifying mount tuning..."
docker-compose exec -T vault sh -c 'VAULT_ADDR=https://127.0.0.1:8200 VAULT_TOKEN=root vault read -tls-skip-verify sys/auth/cert/tune'
docker-compose exec -T vault sh -c 'VAULT_ADDR=https://127.0.0.1:8200 VAULT_TOKEN=root vault read -tls-skip-verify sys/mounts/pki_root/tune'
