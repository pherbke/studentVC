# StudentVC: Privacy-Preserving Academic Credential Management

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![Platform: Android](https://img.shields.io/badge/Platform-Android-brightgreen.svg)](https://shields.io/)
[![Platform: iOS](https://img.shields.io/badge/Platform-iOS-lightgray.svg)](https://shields.io/)
[![BBS+: Signatures](https://img.shields.io/badge/BBS+-Signatures-orange.svg)](https://shields.io/)

## Abstract

StudentVC implements a cryptographically secure, cross-platform mobile ecosystem for academic credential management based on W3C Verifiable Credentials and BBS+ signature schemes. The system enables selective disclosure through zero-knowledge proofs while maintaining compliance with educational privacy standards. This research prototype demonstrates practical deployment of privacy-preserving digital identity solutions in academic environments.

*Developed at the Internet of Services Lab (IoSL), TU Berlin, Winter 2024/25*  
*Principal Investigator: Prof. Dr. Axel Küpper | Research Associate: Patrick Herbke*

## System Architecture

StudentVC operates as a multi-tenant SaaS platform serving Berlin's major universities:

### **Production Deployments**
- **🔴 TU Berlin Instance**: Branded with institutional identity, serving technical university students
- **🟢 FU Berlin Instance**: Customized for humanities and social sciences credentials  

Each tenant maintains cryptographic isolation while sharing the underlying infrastructure, ensuring scalability and operational efficiency.

## Core Features & Capabilities

### 🔐 **Cryptographic Foundation**
- **BBS+ Signatures**: Implements pairing-based cryptography for selective disclosure [[Camenisch et al., 2016]](https://eprint.iacr.org/2016/663.pdf)
- **Zero-Knowledge Proofs**: Enables attribute revelation without exposing entire credentials
- **Unlinkable Presentations**: Prevents correlation attacks across verification sessions

### 📱 **Cross-Platform Implementation**
- **Native Android**: Kotlin-based implementation with secure enclave integration
- **Native iOS**: Swift implementation leveraging CryptoKit framework
- **Unified Backend**: Multi-tenant Flask service with OID4VC/OID4VP protocol support

### 🎓 **Academic Use Cases**
- Student ID card issuance and verification
- Academic transcript management with selective disclosure
- Campus access control integration
- Inter-institutional credential transfer

### 🌐 **Standards Compliance**
- [W3C Verifiable Credentials Data Model v2.0](https://www.w3.org/TR/vc-data-model-2.0/)
- [OpenID for Verifiable Credential Issuance](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
- [OpenID for Verifiable Presentations](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)

## Quick Start

### **Multi-Tenant Development Environment**

```bash
# Clone and setup
git clone https://github.com/pherbke/studentVC.git
cd studentVC

# Start both university instances
docker compose up --build

# Access endpoints
# TU Berlin: http://localhost:8080
# FU Berlin: http://localhost:8081
```

### **Mobile Applications**

**Android:**
```bash
cd android
./gradlew build && ./gradlew installDebug
```

**iOS:**
```bash
cd ios && pod install
open StudentWallet.xcworkspace
```

## Research Contributions

### **Privacy-Preserving Selective Disclosure**
- Implements BBS+ signature schemes for minimal disclosure protocols
- Enables students to prove enrollment without revealing grades
- Supports composite predicates (e.g., "enrolled AND semester >= 3")

### **Multi-Tenant Architecture**
- Cryptographic tenant isolation with shared infrastructure
- University-specific branding and credential schemas
- Horizontal scaling with Kubernetes deployment

### **Mobile Security Integration**
- Hardware security module integration on supported devices  
- Biometric authentication with credential access control
- Offline verification capabilities with cached revocation lists

## Future Work & X.509 Integration

**⚠️ In Preparation**: Advanced PKI-DID hybrid trust models are under active development:

- **Dual-Path Verification**: Traditional X.509 chains combined with DID-based verification
- **Certificate Transparency**: Integration with CT logs for educational credentials
- **Cross-Domain Trust**: Bridging academic and professional credential ecosystems

*Current implementation focuses on pure DID-based verification with BBS+ signatures.*

## Project Structure

```
studentVC/
├── android/          # Android application (Kotlin)
├── ios/             # iOS application (Swift)  
├── backend/         # Multi-tenant Flask backend
├── bbs-core/        # Rust-based BBS+ implementation
├── k8s/            # Kubernetes deployment manifests
└── .github/        # CI/CD pipeline automation
```

## Professional Environment Structure

StudentVC follows a **clean, scalable, and professional server setup** with tiered environments for optimal development and deployment workflows:

### **🔧 Environment Tiers**

| Environment | Purpose | Example Hostname | Git Branch | Notes |
|-------------|---------|------------------|------------|-------|
| **local** | Developer machines | `localhost:8080` | `feature/*` | Local development with Docker |
| **dev** | Shared development/testing | `tu-berlin.dev.studentvc.example.com` | `develop` | Internal testing, frequent resets |
| **staging** | Pre-production simulation | `tu-berlin.staging.studentvc.example.com` | `release/*` | Realistic data, final QA |
| **production** | Live system | `tu-berlin.studentvc.example.com` | `main` | Stable, secure, monitored |

### **🏠 Local Development**

```bash
# Default local development
docker compose up  # TU Berlin: http://localhost:8080

# Multi-tenant local development  
docker compose --profile multi-tenant up
# TU Berlin: http://localhost:8080
# FU Berlin: http://localhost:8081
```

### **🧪 Development Environment**

Shared development server for integration testing and early QA:

```bash
# Start development environment locally
docker compose --profile dev up
# TU Berlin Dev: http://localhost:8082 (+ debug port 9092)
# FU Berlin Dev: http://localhost:8083 (+ debug port 9093)

# Deploy to shared dev server
gh workflow run "StudentVC Multi-Tenant CI/CD" -f environment=dev
```

**Dev Features:**
- **Feature flags** enabled for experimental features
- **Mock external services** for isolated testing
- **Debug logging** and enhanced error reporting
- **Frequent resets** - ephemeral storage
- **Insecure connections** allowed for testing

### **🎯 Staging Environment**

Pre-production simulation with realistic data and production-like configuration:

```bash
# Start staging environment locally
docker compose --profile staging up
# TU Berlin Staging: http://localhost:8084
# FU Berlin Staging: http://localhost:8085

# Deploy to staging server
gh workflow run "StudentVC Multi-Tenant CI/CD" -f environment=staging
```

**Staging Features:**
- **Production-like configuration** with test data
- **Audit logging** enabled
- **Performance monitoring** active
- **SSL enforcement** and security hardening
- **Final QA** before production deployment

### **🚀 Production Environment**

Live university instances serving actual students:

```bash
# Production deployment (requires approval)
gh workflow run "StudentVC Multi-Tenant CI/CD" -f environment=production -f university=tu-berlin
```

**Production Endpoints:**
- **TU Berlin**: `tu-berlin.studentvc.example.com`
- **FU Berlin**: `fu-berlin.studentvc.example.com`

### **🛡️ Security & Best Practices**

- **Environment isolation**: Separate databases, secrets, and API keys per environment
- **Feature flags**: Toggle production vs. test features via `.env` settings
- **Monitoring**: Sentry error tracking and performance monitoring on dev/staging/production
- **OIDC credentials**: Isolated per environment for security
- **CI/CD automation**: 
  - `develop → dev`
  - `release/* → staging`  
  - `main → production`

### **Automated CI/CD Pipeline**
- Multi-architecture Docker builds (AMD64/ARM64)
- Automated security scanning with Bandit and Safety
- Environment-specific deployment triggers
- Horizontal pod autoscaling and health monitoring

## Open Research Directions

- **Post-Quantum Cryptography**: Migration strategies for quantum-resistant signature schemes
- **Credential Archival**: Long-term preservation of cryptographic proofs
- **Revocation Mechanisms**: Efficient status list management for large-scale deployments  
- **Cross-Chain Interoperability**: Integration with blockchain-based identity networks
- **Privacy Metrics**: Quantitative analysis of information leakage in selective disclosure

## Documentation & Resources

- [📱 Demo Video](https://tubcloud.tu-berlin.de/s/TjFbGbmHfp6twQH)
- [📄 Technical Report](docs/Mobile_Wallet-Final_Report.pdf)
- [🔧 Backend API Documentation](backend/README.md)
- [📱 Mobile App Guides](ios/README.md)

## License & Attribution

Licensed under [Apache License 2.0](http://www.apache.org/licenses/LICENSE-2.0)

**Citation:**
```bibtex
@software{herbke2024studentvc,
  author = {Herbke, Patrick and Ritter, Christopher},
  title = {StudentVC: Privacy-Preserving Academic Credential Management},
  year = {2024},
  institution = {Technical University of Berlin},
  supervisor = {Küpper, Axel},
  url = {https://github.com/pherbke/studentVC}
}
```

---

**Contact**: Patrick Herbke | p.herbke@tu-berlin.de | [SNET Research Group](https://www.tu.berlin/snet)