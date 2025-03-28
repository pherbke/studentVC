# Student Wallet - Verifiable Credentials

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![Platform: Android](https://img.shields.io/badge/Platform-Android-brightgreen.svg)](https://shields.io/)
[![Platform: iOS](https://img.shields.io/badge/Platform-iOS-lightgray.svg)](https://shields.io/)
[![BBS+: Signatures](https://img.shields.io/badge/BBS+-Signatures-orange.svg)](https://shields.io/)

## Project Overview

StudentVC is a cross-platform mobile application designed to securely manage, store, and verify academic credentials using Verifiable Credentials (VC) technology. StudentVC leverages BBS+ signatures to ensure cryptographic security and zero-knowledge proof capabilities for selective disclosure of credential attributes - claims.

This project was completed as part of the Internet of Services Lab (IoSL) course during the winter term 2024/25 at [TU Berlin]((https://www.tu.berlin/)). The project was developed by Patrick Herbke, Research Associate at [SNET](https://www.tu.berlin/snet), lead by Prof. Dr. Axel Küpper, in collaboration with Christopher Ritter as parther during the IDunion project.

## Documentation & Demo

- [📱 Demo Video](https://tubcloud.tu-berlin.de/s/NWB76D3fynL6qAB) - Watch the Student Wallet in action
- [📄 Project Report](docs/Mobile_Wallet-Final_Report.pdf) - Detailed documentation and implementation details

## Key Features

- **Secure Credential Storage:** Safely store academic credentials on mobile devices.
- **Zero-Knowledge Proofs:** Enable selective disclosure of credential attributes.
- **Cross-Platform Support:** Available on Android and [iOS](https://developer.apple.com/documentation/cryptokit/).
- **Standards Compliance:** Conforms to [W3C Verifiable Credentials standards v2.0] (https://www.w3.org/TR/vc-data-model-2.0/).
- **BBS+ Signatures:** Robust cryptographic signature scheme for secure credential management - [Rust crate](https://docs.rs/bbs/0.4.1/bbs/).

## Project Structure

The project consists of four main components:

1. **Android Application** (`/android`): [Native Android implementation] (https://developer.android.com/compose) with credential storage and verification.
2. **iOS Application** (`/ios`): Native iOS implementation with secure credential management.
3. **Backend Services** (`/backend`): Server-side implementation for credential issuance and verification.
4. **BBS Core Library** (`/bbs-core`): Core cryptographic library implementing BBS+ signatures.

## Installation & Setup

### Prerequisites

- Android Studio 4.0+ (for Android development)
- Xcode 12.0+ (for iOS development)
- Node.js 14.0+ and npm or yarn (for backend and library)
- MongoDB (for backend data storage)

### Clone the Repository

```bash
git clone https://github.com/yourusername/student-wallet.git
cd student-wallet
```

### Backend Setup

```bash
cd backend
npm install
npm run dev
```

### Android App Setup

```bash
cd android
./gradlew build
./gradlew installDebug
```

### iOS App Setup

```bash
cd ios
pod install
open StudentWallet.xcworkspace
```

### BBS Core Library Setup

```bash
cd bbs-core
npm install
npm run build
npm test
```

## Usage

1. Set up the BBS core library.
2. Start the backend server.
3. Run the mobile apps on Android or iOS.

## License

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at:

[Apache License 2.0](http://www.apache.org/licenses/LICENSE-2.0)

## Acknowledgements

This project was developed as part of the Internet of Services Lab (IoSL) at TU Berlin, under the supervision of Prof. Dr. Axel Küpper.

For questions or further information, please contact Patrick Herbke p.herbke#at##tu-berlin.de.
