# StudentVC - Multi-Tenant Verifiable Credentials Platform

A containerized verifiable credentials system serving multiple universities through isolated tenant containers.

## Overview

StudentVC runs as separate Docker containers for different university tenants:
- **TU Berlin container** (Technical University)
- **FU Berlin container** (Research University)

Each container is completely isolated with its own database, certificates, and configuration.

## Quick Start

### Prerequisites
- Docker & Docker Compose
- Git

### Local Development

```bash
# Clone repository
git clone <repository-url>
cd studentVC

# Start single tenant (TU Berlin only)
make local
# Access: http://localhost:8080

# Start both university containers (multi-tenant)
make dev
# TU Berlin: http://localhost:8080
# FU Berlin: http://localhost:8081
```

### Production Deployment

#### TU Berlin Container
```bash
cd backend
export TENANT_NAME=tu-berlin
export UNIVERSITY_TYPE=technical
export SERVER_URL=https://studentvc.tu-berlin.de
docker compose --profile production up -d
```

#### FU Berlin Container
```bash
cd backend
export TENANT_NAME=fu-berlin
export UNIVERSITY_TYPE=research
export SERVER_URL=https://studentvc.fu-berlin.de
docker compose --profile production up -d
```

## Container Configuration

Each tenant container requires:

```bash
# Essential environment variables
TENANT_NAME=tu-berlin           # or fu-berlin
UNIVERSITY_TYPE=technical       # or research
SERVER_URL=https://your-domain.com
ENVIRONMENT=production          # local, staging, production
SECRET_KEY=<secure-random-key>
```

## Kubernetes Deployment

```bash
# Deploy tenant-specific containers
kubectl apply -f k8s/production/tu-berlin-deployment.yml
kubectl apply -f k8s/production/fu-berlin-deployment.yml
```

## Key Endpoints

- `/` - University-specific login page
- `/issuer` - Credential issuance portal
- `/verifier` - Credential verification
- `/stats` - Container health and statistics

## Mobile Applications

### Android
```bash
cd android && ./gradlew build
```

### iOS
```bash
cd ios && xcodebuild -scheme "Student Wallet" build
```

## Support

- Container logs: `docker logs <container-name>`
- Health check: `GET /health`
- Issues: Report via GitHub Issues