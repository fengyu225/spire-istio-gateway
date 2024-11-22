# SPIRE Deployment with Istio Ingress Gateway in AWS EKS

## Architecture

1. SPIRE Server in HA mode using AWS RDS PostgreSQL and KMS for key manager. 
2. Intermediate CA in AWS Private Certificate Authority (PCA)
3. Secure gateway using Istio Ingress Gateway with TLS termination using SPIRE-issued certificates 
4. Custom SVID Secret Sync Controller

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

### 6. SVID Secret Sync Controller

The SVID Secret Sync Controller syncs SPIRE-issued SVIDs to Kubernetes secrets for Istio gateway certificates.
The controller:
- Watches for SPIFFE X.509 SVIDs
- Converts SVIDs to Kubernetes TLS secrets
- Manages secret lifecycle
- Supports multiple gateway certificates
- Performs automatic cleanup

1. Build and push the controller image:
```bash
# REGISTRY=<registry>

docker build -t $REGISTRY/svid-secret-sync:v0.1.8 .
docker push $REGISTRY/svid-secret-sync:v0.1.8
```

2. Deploy the controller:
```bash
kubectl apply -f rbac.yaml
kubectl apply -f deployment.yaml
```

## Testing

### Verify SPIRE Registration

```bash
kubectl exec -n spire $(kubectl get pod -n spire -l app=spire-server \
  -o jsonpath='{.items[0].metadata.name}') \
  -c spire-server -- /opt/spire/bin/spire-server entry show
```

### Test TLS Certificates

```bash
INGRESS_HOST=$(kubectl -n istio-system get service istio-ingressgateway \
  -o jsonpath='{.status.loadBalancer.ingress[0].hostname}')
INGRESS_PORT=443

# Test app1 certificate
openssl s_client -connect $INGRESS_HOST:$INGRESS_PORT \
  -servername app1.example.org -showcerts

# Test app2 certificate
openssl s_client -connect $INGRESS_HOST:$INGRESS_PORT \
  -servername app2.example.org -showcerts
```

Example certificate:
```
Issuer: C=US, O=Example Organization, CN=example.org
Subject: C=US, O=SPIRE, CN=app1.example.org
X509v3 Subject Alternative Name:
    DNS:app1.example.org
    URI:spiffe://example.org/ns/istio-system/sa/app1
```

## Components Version 
- SPIRE Server: 1.5.4
- SPIRE Agent: 1.5.4
- SPIFFE CSI Driver: 0.2.0
- SPIRE Controller Manager: 0.2.3
- Istio: 1.14+ required
- SVID Secret Sync: v0.1.8
- PostgreSQL: 14.10