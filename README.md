# StudentVC - Verifiable Credentials Platform

A production-ready, multi-tenant verifiable credentials system implementing W3C VC Data Model 2.0 with BBS+ signatures for selective disclosure. Integrates X.509 certificates with DIDs following the HAVID specification.

## Architecture

- **Multi-Tenant SaaS**: Single codebase serving multiple universities
- **Dual Trust Model**: X.509 PKI + DID-based verification
- **Selective Disclosure**: BBS+ signatures for privacy-preserving presentations
- **OID4VC/VP Compliant**: OpenID for Verifiable Credentials protocol implementation

## Quick Start

### Prerequisites

- Docker & Docker Compose
- Node.js 18+ (for CI/CD testing)
- Git

### Local Development

```bash
# Clone repository
git clone <repository-url>
cd studentVC

# Start TU Berlin instance (single tenant)
make local

# Start multi-tenant (TU Berlin + FU Berlin)
make dev

# Access applications
# TU Berlin: http://localhost:8080
# FU Berlin: http://localhost:8081 (multi-tenant only)
```

## Production Deployment

### Environment Configuration

Each tenant requires specific environment variables:

```bash
# Required for all deployments
TENANT_NAME=tu-berlin                    # or fu-berlin
UNIVERSITY_TYPE=technical               # or research
SERVER_URL=https://your-domain.com
ENVIRONMENT=production                  # testing, staging, production

# Security
SECRET_KEY=<strong-secret-key>
BBS_PRIVATE_KEY_PATH=/app/instance/bbs_private.pem
SSL_CERT_PATH=/app/instance/certs/server.crt
SSL_KEY_PATH=/app/instance/certs/server.key

# Database
DATABASE_URL=sqlite:///instance/database.db

# External Authentication (optional)
SHIBBOLETH_ENABLED=true
KEYCLOAK_URL=https://auth.university.edu
```

### TU Berlin Instance

```bash
# Production deployment
docker compose -f docker-compose.yml --profile production up -d

# Environment variables
export TENANT_NAME=tu-berlin
export UNIVERSITY_TYPE=technical
export SERVER_URL=https://studentvc.tu-berlin.de
export ENVIRONMENT=production
```

### FU Berlin Instance

```bash
# Production deployment  
docker compose -f docker-compose.yml --profile production up -d

# Environment variables
export TENANT_NAME=fu-berlin
export UNIVERSITY_TYPE=research
export SERVER_URL=https://studentvc.fu-berlin.de
export ENVIRONMENT=production
```

### Kubernetes Deployment

```bash
# Deploy to testing environment
kubectl apply -f k8s/testing/

# Deploy to staging environment  
kubectl apply -f k8s/staging/

# Deploy to production environment
kubectl apply -f k8s/production/
```

## CI/CD Pipeline

### Local Testing

```bash
# Test CI/CD pipeline locally
make test-ci

# Full CI/CD simulation with Act
make test-full

# Quick validation
make test-quick
```

### Deployment Environments

#### Testing Environment
- **Purpose**: Feature testing and integration validation
- **URL Pattern**: `https://test-studentvc-{tenant}.example.com`
- **Database**: Isolated test data
- **SSL**: Self-signed certificates acceptable

#### Staging Environment  
- **Purpose**: Production replica for final validation
- **URL Pattern**: `https://staging-studentvc-{tenant}.example.com`
- **Database**: Production-like data
- **SSL**: Valid certificates required

#### Production Environment
- **Purpose**: Live system serving end users
- **URL Pattern**: `https://studentvc-{tenant}.edu`
- **Database**: Persistent production data
- **SSL**: Valid certificates required
- **Monitoring**: Full observability stack

## Security Requirements

### SSL/TLS Configuration

```bash
# Generate SSL certificates
./generate_ssl_certs.sh

# For production, obtain certificates from CA:
# - Let's Encrypt (automated)
# - University CA (manual)
# - Commercial CA (manual)
```

### BBS+ Key Management

```bash
# Generate BBS+ signing keys (automatic on first run)
cd backend/bbs-core/python
./build.sh
```

### X.509 Certificate Management

- Certificate-DID binding in SubjectAlternativeName
- Automatic certificate lifecycle monitoring
- CRL distribution for revocation checking

## API Endpoints

### Core OID4VC Endpoints

- `GET /.well-known/openid-credential-issuer` - Issuer metadata
- `GET /.well-known/openid-configuration` - OAuth configuration
- `POST /token` - Token exchange
- `POST /credential` - Credential issuance
- `POST /presentations/submission` - Presentation verification

### Management Endpoints

- `GET /stats` - System statistics dashboard
- `GET /validate` - Credential status management
- `POST /validate/credential/toggle/{id}` - Revoke/reactivate credentials

## Mobile Applications

### Android
```bash
cd android
./gradlew build
./gradlew installDebug
```

### iOS
```bash
cd ios
xcodebuild -scheme "Student Wallet" build
```

## Monitoring & Observability

### Health Checks

- `GET /health` - Application health
- `GET /stats` - Detailed system metrics
- WebSocket connections for real-time monitoring

### Logging

- Structured JSON logging
- Category-based log levels
- Performance metrics collection
- Security event tracking

## Development

### Testing

```bash
# Backend tests
cd backend
python -m pytest

# Integration tests
python -m pytest tests/integration/

# End-to-end X.509 flow
./run_x509_tests.sh
```

### Security Scanning

```bash
# Security analysis
bandit -r src/ -f json -o bandit_report.json
```

## Configuration Files

- `docker-compose.yml` - Local/development
- `k8s/*/` - Kubernetes deployments
- `backend/gunicorn.conf.py` - Production WSGI configuration
- `backend/pytest.ini` - Test configuration

## Support

- **Documentation**: Complete API documentation in `/docs`
- **Issues**: Report via GitHub Issues
- **Security**: Security issues to security@university.edu

## License

This project implements standards-compliant verifiable credentials infrastructure for educational institutions.