# StudentVC - Multi-Tenant Verifiable Credentials Platform

StudentVC is a production-ready, multi-tenant platform for issuing and verifying student credentials using W3C Verifiable Credentials with BBS+ signatures for selective disclosure. The platform supports multiple university instances with distinct branding and configurations.

## 🎓 Supported Universities

- **TU Berlin** (Technische Universität Berlin) - Red branding
- **FU Berlin** (Freie Universität Berlin) - Green branding

Each university instance operates independently with:
- Unique branding (colors, logos, styling)
- Separate credential schemas and configurations
- Independent X.509 certificate management
- Isolated data and security contexts

## 🚀 Quick Start

### Prerequisites

- Docker and Docker Compose
- Git with submodule support
- (Optional) Kubernetes cluster for production deployment

### Clone and Setup

```bash
# Clone the repository
git clone <repository-url>
cd studentVC/backend

# Initialize submodules for BBS+ cryptographic library
git submodule update --init --recursive
```

### Single University Development

Start individual university instances:

```bash
# Start TU Berlin instance only
docker compose up tu-berlin --build

# OR start FU Berlin instance only
docker compose up fu-berlin --build

# Access TU Berlin: https://localhost:8080
# Access FU Berlin: https://localhost:8081
```

### Multi-Tenant Development

Start both universities simultaneously:

```bash
# Start both TU Berlin and FU Berlin instances
docker compose --profile multi-tenant up --build

# OR start them separately:
# Start TU Berlin (port 8080)
docker compose up tu-berlin -d --build

# Start FU Berlin (port 8081)  
docker compose up fu-berlin -d --build

# Access TU Berlin: https://localhost:8080
# Access FU Berlin: https://localhost:8081
```

### Manual Docker Run (Alternative)

You can also run instances manually with explicit tenant names:

```bash
# Build the image first
docker compose build

# Start TU Berlin manually
docker run -d --name tu-berlin \
  -p 8080:8080 \
  -e TENANT_NAME="TU Berlin" \
  -v ./instance/tu-berlin:/instance \
  backend-tu-berlin

# Start FU Berlin manually
docker run -d --name fu-berlin \
  -p 8081:8080 \
  -e TENANT_NAME="FU Berlin" \
  -v ./instance/fu-berlin:/instance \
  backend-tu-berlin
```

## 🏗️ Production Deployment

### Docker Compose (Simple Multi-Tenant)

Create a `docker-compose.prod.yml`:

```yaml
version: '3.8'
services:
  tu-berlin:
    build: .
    ports:
      - "8080:8080"
    environment:
      - TENANT_NAME=TU Berlin
      - SERVER_URL=https://tu-berlin.studentvc.org
    volumes:
      - ./instance/tu-berlin:/src/instance
    restart: unless-stopped
    
  fu-berlin:
    build: .
    ports:
      - "8081:8080"
    environment:
      - TENANT_NAME=FU Berlin
      - SERVER_URL=https://fu-berlin.studentvc.org
    volumes:
      - ./instance/fu-berlin:/src/instance
    restart: unless-stopped
    
  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./ssl:/etc/ssl/certs
    depends_on:
      - tu-berlin
      - fu-berlin
    restart: unless-stopped
```

### Kubernetes Deployment

#### 1. Create Namespace and ConfigMaps

```bash
# Create namespace
kubectl create namespace studentvc

# Create ConfigMaps for each university
kubectl create configmap tu-berlin-config \
  --from-literal=TENANT_NAME="TU Berlin" \
  --from-literal=SERVER_URL="https://tu-berlin.studentvc.org" \
  -n studentvc

kubectl create configmap fu-berlin-config \
  --from-literal=TENANT_NAME="FU Berlin" \
  --from-literal=SERVER_URL="https://fu-berlin.studentvc.org" \
  -n studentvc
```

#### 2. Deploy Applications

Create `k8s-deployment.yaml`:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: tu-berlin-deployment
  namespace: studentvc
spec:
  replicas: 3
  selector:
    matchLabels:
      app: tu-berlin
  template:
    metadata:
      labels:
        app: tu-berlin
    spec:
      containers:
      - name: studentvc
        image: studentvc:latest
        ports:
        - containerPort: 8080
        envFrom:
        - configMapRef:
            name: tu-berlin-config
        volumeMounts:
        - name: instance-storage
          mountPath: /src/instance
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
          limits:
            memory: "1Gi"
            cpu: "500m"
      volumes:
      - name: instance-storage
        persistentVolumeClaim:
          claimName: tu-berlin-pvc
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: fu-berlin-deployment
  namespace: studentvc
spec:
  replicas: 3
  selector:
    matchLabels:
      app: fu-berlin
  template:
    metadata:
      labels:
        app: fu-berlin
    spec:
      containers:
      - name: studentvc
        image: studentvc:latest
        ports:
        - containerPort: 8080
        envFrom:
        - configMapRef:
            name: fu-berlin-config
        volumeMounts:
        - name: instance-storage
          mountPath: /src/instance
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
          limits:
            memory: "1Gi"
            cpu: "500m"
      volumes:
      - name: instance-storage
        persistentVolumeClaim:
          claimName: fu-berlin-pvc
---
apiVersion: v1
kind: Service
metadata:
  name: tu-berlin-service
  namespace: studentvc
spec:
  selector:
    app: tu-berlin
  ports:
  - port: 80
    targetPort: 8080
  type: ClusterIP
---
apiVersion: v1
kind: Service
metadata:
  name: fu-berlin-service
  namespace: studentvc
spec:
  selector:
    app: fu-berlin
  ports:
  - port: 80
    targetPort: 8080
  type: ClusterIP
```

#### 3. Setup Ingress with SSL

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: studentvc-ingress
  namespace: studentvc
  annotations:
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
spec:
  tls:
  - hosts:
    - tu-berlin.studentvc.org
    secretName: tu-berlin-tls
  - hosts:
    - fu-berlin.studentvc.org
    secretName: fu-berlin-tls
  rules:
  - host: tu-berlin.studentvc.org
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: tu-berlin-service
            port:
              number: 80
  - host: fu-berlin.studentvc.org
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: fu-berlin-service
            port:
              number: 80
```

Apply all configurations:

```bash
kubectl apply -f k8s-deployment.yaml
kubectl apply -f k8s-ingress.yaml
```

## 🔧 Configuration

### Quick Reference Commands

```bash
# TU Berlin only
docker compose up tu-berlin --build

# FU Berlin only  
docker compose up fu-berlin --build

# Both universities
docker compose --profile multi-tenant up --build

# Stop all
docker compose down

# Rebuild and restart TU Berlin
docker compose up tu-berlin --build --force-recreate

# Rebuild and restart FU Berlin
docker compose up fu-berlin --build --force-recreate
```

### Environment Variables

| Variable | Description | TU Berlin | FU Berlin |
|----------|-------------|-----------|-----------|
| `TENANT_NAME` | University identifier | `"TU Berlin"` | `"FU Berlin"` |
| `SERVER_URL` | Public server URL | `https://tu-berlin.domain.com` | `https://fu-berlin.domain.com` |
| `TENANT_ID` | Internal tenant ID | `tu-berlin` | `fu-berlin` |

### Advanced Configuration

Override default colors and branding:

```bash
# Custom colors for additional universities
docker run -d \
  -e TENANT_NAME="Custom University" \
  -e TENANT_PRIMARY_COLOR="#1e40af" \
  -e TENANT_SECONDARY_COLOR="#1e3a8a" \
  -e BRAND_PRIMARY_COLOR="#1e40af" \
  -p 8082:8080 \
  backend-issuer
```

### SSL/TLS Configuration

For production, ensure HTTPS is properly configured:

```bash
# Generate certificates
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout private.key -out certificate.crt

# Mount certificates in Docker
docker run -d \
  -v /path/to/ssl:/etc/ssl/certs \
  -e SSL_CERT_PATH=/etc/ssl/certs/certificate.crt \
  -e SSL_KEY_PATH=/etc/ssl/certs/private.key \
  backend-issuer
```

## 🏛️ Architecture

### Multi-Tenant Design

```
┌─────────────────┐    ┌─────────────────┐
│   TU Berlin     │    │   FU Berlin     │
│   Instance      │    │   Instance      │
│                 │    │                 │
│ ┌─────────────┐ │    │ ┌─────────────┐ │
│ │   Issuer    │ │    │ │   Issuer    │ │
│ │   Service   │ │    │ │   Service   │ │
│ └─────────────┘ │    │ └─────────────┘ │
│ ┌─────────────┐ │    │ ┌─────────────┐ │
│ │  Verifier   │ │    │ │  Verifier   │ │
│ │   Service   │ │    │ │   Service   │ │
│ └─────────────┘ │    │ └─────────────┘ │
│ ┌─────────────┐ │    │ ┌─────────────┐ │
│ │ Validator   │ │    │ │ Validator   │ │
│ │   Service   │ │    │ │   Service   │ │
│ └─────────────┘ │    │ └─────────────┘ │
└─────────────────┘    └─────────────────┘
```

### Security Features

- **BBS+ Signatures**: Zero-knowledge selective disclosure
- **X.509 Integration**: Enterprise certificate management
- **DID Support**: Decentralized identity standards
- **RBAC**: Role-based access control per tenant
- **Audit Logging**: Comprehensive security logging

## 📱 Mobile Integration

### Android Wallet

```bash
# Build Android wallet
cd ../android
./gradlew assembleDebug

# Configure server endpoints
# Update app/src/main/res/values/strings.xml:
# <string name="server_url_tu">https://tu-berlin.studentvc.org</string>
# <string name="server_url_fu">https://fu-berlin.studentvc.org</string>
```

### iOS Wallet

```bash
# Build iOS wallet
cd ../ios
xcodebuild -workspace StudentWallet.xcworkspace -scheme StudentWallet
```

## 🧪 Testing

### Local Testing

```bash
# Test TU Berlin instance
curl -k https://localhost:8080/verifier/settings

# Test FU Berlin instance  
curl -k https://localhost:8081/verifier/settings

# Run integration tests
python -m pytest tests/
```

### Load Testing

```bash
# Install testing tools
pip install locust

# Run load tests against both instances
locust -f tests/load_test.py --host=https://localhost:8080
```

## 🔍 Monitoring

### Health Checks

Each instance provides health check endpoints:

```bash
# Basic health check
curl https://tu-berlin.studentvc.org/health

# Detailed status
curl https://fu-berlin.studentvc.org/status
```

### Kubernetes Monitoring

```yaml
# Add to deployment.yaml
livenessProbe:
  httpGet:
    path: /health
    port: 8080
  initialDelaySeconds: 30
  periodSeconds: 10

readinessProbe:
  httpGet:
    path: /ready
    port: 8080
  initialDelaySeconds: 5
  periodSeconds: 5
```

## 🛠️ Development

### Local Development Setup

```bash
# Setup development environment
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows
pip install -r requirements-dev.txt

# Run development server
export TENANT_NAME="TU Berlin"
python main.py
```

### Adding New Universities

1. Add configuration to `src/tenant_config.py`:

```python
'new-university': {
    'name': 'New University',
    'full_name': 'New University Full Name',
    'colors': {
        'primary': '#your-color',
        'primary_text': '#ffffff'
    },
    'logo': {
        'main': '/static/logos/new_logo.png'
    }
}
```

2. Add logos to `src/static/logos/`
3. Deploy new instance with `TENANT_NAME="New University"`

## 🐛 Troubleshooting

### Common Issues

**Windows Docker Build Error**: 
```bash
# Fix line endings
git config core.autocrlf false
git rm --cached -r .
git reset --hard
```

**Port Conflicts**:
```bash
# Check running containers
docker ps

# Stop conflicting containers
docker stop $(docker ps -q)
```

**Certificate Issues**:
```bash
# Regenerate certificates
rm -rf instance/
docker compose up --build
```

### Debugging

```bash
# View logs for specific tenant
docker logs tu-berlin-container -f

# Access container shell
docker exec -it fu-berlin-container /bin/bash

# Check tenant configuration
curl -k https://localhost:8080/debug/config
```

## 📚 API Documentation

### Credential Issuance

```bash
# Request credential offer
POST /issuer/credential-offer
Content-Type: application/json

{
  "credential_type": "StudentCard",
  "holder_did": "did:key:..."
}
```

### Credential Verification

```bash
# Verify presentation
POST /verifier/verify
Content-Type: application/json

{
  "vp_token": "...",
  "presentation_definition": {...}
}
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/new-university`
3. Make changes and test thoroughly
4. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Documentation**: [Project Wiki](link-to-wiki)
- **Issues**: [GitHub Issues](link-to-issues)
- **Discussions**: [GitHub Discussions](link-to-discussions)
- **Email**: support@studentvc.org