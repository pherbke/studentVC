# Student Wallet - Verifiable Credentials

[![License: Academic](https://img.shields.io/badge/License-Academic-blue.svg)](https://shields.io/)
[![Platform: Android](https://img.shields.io/badge/Platform-Android-brightgreen.svg)](https://shields.io/)
[![Platform: iOS](https://img.shields.io/badge/Platform-iOS-lightgray.svg)](https://shields.io/)
[![BBS+: Signatures](https://img.shields.io/badge/BBS+-Signatures-orange.svg)](https://shields.io/)

## Project Overview

Student Wallet is a comprehensive digital credential platform enabling secure storage, management, and verification of academic credentials using verifiable credentials technology. This project implements a cross-platform mobile solution with secure backend services.

## Project Attribution

Patrick Herbke is a Research Associate at [SNET](https://www.tu.berlin/snet) TU Berlin, headed by Prof. Dr. Axel Küpper.
This project was completed during the Internet of Services Lab (IoSL) course in winter term 2024/25.
This work was done in collaboration with Christopher Ritter as part of the IDunion project.
## Documentation & Demo

- [📱 Demo Video](https://tubcloud.tu-berlin.de/s/NWB76D3fynL6qAB) - Watch the Student Wallet in action demonstration
- [📄 Project Report](docs/Mobile_Wallet-Final_Report.pdf) - Detailed documentation and implementation details
  
The full project report is available in the `docs/` directory. You can also access the complete documentation by opening the PDF file locally after cloning the repository.

## Quick Start

```bash
# Clone the repository
git clone https://github.com/yourusername/student-wallet.git
cd student-wallet

# Set up and run the backend
cd backend
npm install
npm run dev

# Set up and run the Android app
cd ../android
./gradlew installDebug

# Set up and run the iOS app
cd ../ios
pod install
open StudentWallet.xcworkspace
```

## Project Structure

The project consists of four main components:

### Components

1. **Android Application** (`/android`)
   - Native Android implementation of the Student Wallet
   - Handles credential storage, display, and verification on Android devices
   
   **Prerequisites:**
   - Android Studio 4.0+
   - JDK 11+
   - Android SDK 30+

2. **iOS Application** (`/ios`)
   - Native iOS implementation of the Student Wallet
   - Manages credentials on Apple devices with platform-specific optimizations
   
   **Prerequisites:**
   - Xcode 12.0+
   - CocoaPods
   - iOS 14.0+
   - macOS for development

3. **Backend Services** (`/backend`)
   - Server-side implementation handling credential issuance and verification
   - Provides API endpoints for mobile applications
   - Manages user authentication and security
   
   **Prerequisites:**
   - Node.js 14.0+
   - MongoDB
   - npm or yarn

4. **BBS Core Library** (`/bbs-core`)
   - Core cryptographic library implementing BBS+ signatures
   - Provides the foundation for secure credential operations
   - Enables zero-knowledge proof capabilities
   
   **Prerequisites:**
   - Node.js 14.0+
   - npm or yarn

## Detailed Setup Instructions

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

## Key Features

- **Secure Storage**: Store academic credentials securely on your mobile device
- **Zero-Knowledge Proofs**: Selectively disclose credential information such as student status, name, course status, ...
- **Cross-Platform Support**: Available for both Android and iOS
- **Standards Compliant**: Follows W3C Verifiable Credentials standards
- **BBS+ Signatures**: Advanced cryptographic security

## Development Workflow

1. Set up the BBS core library first as it's a dependency for other components
2. Configure and run the backend services
3. Deploy mobile applications for testing

## License

This project is part of academic research at TU Berlin.

## Contact

For questions related to this project, please refer to the contact information in the project report.
