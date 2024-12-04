# SPIRE Deployment with Istio Ingress Gateway in AWS EKS

## Architecture

1. SPIRE Server in HA mode using AWS RDS PostgreSQL and KMS for key manager.
2. Intermediate CA in AWS Private Certificate Authority (PCA)
3. Secure gateway using Istio Ingress Gateway with TLS termination using SPIRE-issued certificates
4. SDS Proxy as CSI Driver interfacing between Istio and SPIRE
    - Mounts SPIRE Workload API socket to Istio Ingress Gateway pods
    - Handles certificate updates and distribution
    - Converts SPIRE SVIDs to Istio-compatible formats

## Deployment Process

### 1. EKS Cluster Setup

```bash
eksctl create cluster -f cluster-config.yaml
aws eks update-kubeconfig --name spire-demo --region us-east-1
kubectl create namespace spire

# Set up OIDC provider for IAM roles
eksctl utils associate-iam-oidc-provider \
    --cluster spire-demo \
    --region us-east-1 \
    --approve

# Configure EBS CSI Driver IAM role
eksctl create iamserviceaccount \
  --name ebs-csi-controller-sa \
  --namespace kube-system \
  --cluster spire-demo \
  --role-name EKS-EBS-CSI-DriverRole \
  --role-only \
  --attach-policy-arn arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy \
  --approve

# Create SPIRE Server IAM policies and role
# Create SpireServerPolicy
cat << EOF > spire-server-policy.json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "kms:Decrypt",
                "kms:GenerateDataKey",
                "kms:CreateGrant",
                "kms:ListGrants",
                "kms:RevokeGrant"
            ],
            "Resource": "arn:aws:kms:us-east-1:*:key/*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "acm-pca:IssueCertificate",
                "acm-pca:GetCertificate",
                "acm-pca:GetCertificateAuthorityCertificate"
            ],
            "Resource": "arn:aws:acm-pca:us-east-1:164314285563:certificate-authority/4cc5758d-ac26-41dd-b3c8-165cb2ffc80f"
        }
    ]
}
EOF

# Get the OIDC provider ID from the cluster
OIDC_ID=$(aws eks describe-cluster --name spire-demo --region us-east-1 \
  --query "cluster.identity.oidc.issuer" --output text | cut -d'/' -f5)

# Create trust policy with dynamic OIDC ID
cat << EOF > trust-policy.json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Federated": "arn:aws:iam::164314285563:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/${OIDC_ID}"
            },
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {
                    "oidc.eks.us-east-1.amazonaws.com/id/${OIDC_ID}:sub": "system:serviceaccount:spire:spire-server",
                    "oidc.eks.us-east-1.amazonaws.com/id/${OIDC_ID}:aud": "sts.amazonaws.com"
                }
            }
        }
    ]
}
EOF

# Create the IAM policy
aws iam create-policy \
    --policy-name SpireServerPolicy \
    --policy-document file://spire-server-policy.json

# Create the IAM role or update IAM role with trust policy
aws iam create-role \
    --role-name SpireServerRole \
    --assume-role-policy-document file://trust-policy.json
    
aws iam update-assume-role-policy \
    --role-name SpireServerRole \
    --policy-document file://trust-policy.json

# Attach the policies to the role
aws iam attach-role-policy \
    --role-name SpireServerRole \
    --policy-arn arn:aws:iam::$(aws sts get-caller-identity --query Account --output text):policy/SpireServerPolicy

aws iam attach-role-policy \
    --role-name SpireServerRole \
    --policy-arn arn:aws:iam::164314285563:policy/SpirePCAPolicy
```

### 2. AWS RDS PostgreSQL Setup

```bash
# Create security group
VPC_ID=$(aws eks describe-cluster --name spire-demo \
  --query "cluster.resourcesVpcConfig.vpcId" --output text)
SG_ID=$(aws ec2 create-security-group \
  --group-name spire-rds-sg \
  --description "Security group for SPIRE RDS" \
  --vpc-id $VPC_ID \
  --query 'GroupId' --output text)

# Configure security group
aws ec2 authorize-security-group-ingress \
  --group-id $SG_ID \
  --protocol tcp \
  --port 5432 \
  --source-group $(aws eks describe-cluster --name spire-demo \
    --query "cluster.resourcesVpcConfig.clusterSecurityGroupId" --output text)

# Create DB subnet group
aws rds create-db-subnet-group \
  --db-subnet-group-name spire-db-subnet \
  --db-subnet-group-description "Subnet group for SPIRE RDS" \
  --subnet-ids $(aws ec2 describe-subnets \
    --filters "Name=vpc-id,Values=$VPC_ID" \
    --query "Subnets[?MapPublicIpOnLaunch==\`false\`].SubnetId" \
    --output text)

# Create RDS instance
DB_PASSWORD=$(openssl rand -base64 12)
aws rds create-db-instance \
  --db-instance-identifier spire-db \
  --db-instance-class db.t3.micro \
  --engine postgres \
  --engine-version 14.10 \
  --master-username spire_admin \
  --master-user-password $DB_PASSWORD \
  --allocated-storage 5 \
  --vpc-security-group-ids $SG_ID \
  --db-subnet-group-name spire-db-subnet \
  --no-multi-az \
  --db-name spiredb

# Store credentials in Kubernetes
kubectl create secret generic spire-db-credentials \
  -n spire \
  --from-literal=password=$DB_PASSWORD
```

### 3. AWS PCA Setup

```bash
aws iam create-policy \
    --policy-name SpirePCAPolicy \
    --policy-document file://pca-policy.json

eksctl create iamserviceaccount \
    --cluster spire-demo \
    --namespace spire \
    --name spire-server \
    --attach-policy-arn arn:aws:iam::164314285563:policy/SpirePCAPolicy \
    --override-existing-serviceaccounts \
    --region us-east-1 \
    --approve
```

### 4. SPIRE Deployment

Deploy SDS proxy

```bash
cd spiffe-csi-driver/deploy/
kubectl apply -k .
```

Deploy SPIRE server and agents

```bash
cd spire
kubectl apply -k .
```

### 5. Istio Integration

1. Install Istio with SPIFFE integration:

```bash
istioctl install -f istio-spire-config.yaml
```

2. Configure SPIFFE ID registration:

```bash
kubectl apply -f clusterspiffeid.yaml
```

3. Enable SPIRE identity for Ingress Gateway:

```bash
kubectl patch deployment istio-ingressgateway -n istio-system \
  -p '{"spec":{"template":{"metadata":{"labels":{"spiffe.io/spire-managed-identity": "true"}}}}}'
```

### Monitor SDS Proxy Logs

```bash
kubectl logs -l app=spiffe-csi-proxy -n spiffe-csi-proxy -c spiffe-csi-proxy -f
```

### Check Istio Secret Configuration

View the secrets configured in Istio Ingress Gateway:

```bash
istioctl pc secret -n istio-system $(kubectl get pod -n istio-system -l app=istio-ingressgateway -o jsonpath='{.items[0].metadata.name}')
```

### Test TLS Certificates

Get certificate information for a specific domain:

```bash
INGRESS_HOST=$(kubectl -n istio-system get service istio-ingressgateway -o jsonpath='{.status.loadBalancer.ingress[0].hostname}')
INGRESS_PORT=443
echo | openssl s_client -connect $INGRESS_HOST:$INGRESS_PORT -servername app1.example.org -showcerts | openssl x509 -noout -text
```

### Inspect Individual Certificates

View app1 certificate:

```bash
istioctl pc secret -n istio-system $(kubectl get pod -n istio-system -l app=istio-ingressgateway -o jsonpath='{.items[0].metadata.name}') -o json | jq -r '.dynamicActiveSecrets[1].secret.tlsCertificate.certificateChain.inlineBytes' | base64 -d | openssl x509 -text -noout
```

View default certificate:

```bash
istioctl pc secret -n istio-system $(kubectl get pod -n istio-system -l app=istio-ingressgateway -o jsonpath='{.items[0].metadata.name}') -o json | jq -r '.dynamicActiveSecrets[0].secret.tlsCertificate.certificateChain.inlineBytes' | base64 -d | openssl x509 -text -noout
```

### Verify SPIRE Registration

View registered SPIFFE IDs:

```bash
kubectl exec -n spire $(kubectl get pod -n spire -l app=spire-server -o jsonpath='{.items[0].metadata.name}') -c spire-server -- /opt/spire/bin/spire-server entry show
```

## Components

- SPIRE Server and Agent
- SPIFFE CSI Driver (SDS Proxy)
- Istio with SPIFFE integration

The SDS proxy operates as a CSI driver, mounting the SPIRE Workload API socket into Istio pods. It acts as an
intermediary between SPIRE and Istio, handling certificate updates and conversion of SPIRE SVIDs into formats compatible
with Istio's Secret Discovery Service (SDS).