# Student Wallet - Verifiable Credentials

## Project Overview

Student Wallet is a comprehensive digital credential platform enabling secure storage, management, and verification of academic credentials using verifiable credentials technology. This project implements a cross-platform mobile solution with secure backend services.

## Final Project Report

The complete project documentation and final report can be accessed here:
[Final Student Project Report](https://tubcloud.tu-berlin.de/s/NWB76D3fynL6qAB)

## Project Structure

The project consists of four main components:

### Components

1. **Android Application** (`/android`)
   - Native Android implementation of the Student Wallet
   - Handles credential storage, display, and verification on Android devices

2. **iOS Application** (`/ios`)
   - Native iOS implementation of the Student Wallet
   - Manages credentials on Apple devices with platform-specific optimizations

3. **Backend Services** (`/backend`)
   - Server-side implementation handling credential issuance and verification
   - Provides API endpoints for mobile applications
   - Manages user authentication and security

4. **BBS Core Library** (`/bbs-core`)
   - Core cryptographic library implementing BBS+ signatures
   - Provides the foundation for secure credential operations
   - Enables zero-knowledge proof capabilities

## Setup Instructions

### Android Application

```bash
cd android
# Install dependencies
./gradlew build
# Run the application in debug mode
./gradlew installDebug
```

### iOS Application

```bash
cd ios
# Install dependencies
pod install
# Open the workspace in Xcode
open StudentWallet.xcworkspace
```

### Backend Services

```bash
cd backend
# Install dependencies
npm install
# Set up environment
cp .env.example .env
# Start development server
npm run dev
```

### BBS Core Library

```bash
cd bbs-core
# Install dependencies
npm install
# Build the library
npm run build
# Run tests
npm test
```

## License

This project is part of academic research at TU Berlin.

## Contact

For questions related to this project, please refer to the contact information in the final project report.

