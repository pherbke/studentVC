# Student Wallet - Verifiable Credentials

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![Platform: Android](https://img.shields.io/badge/Platform-Android-brightgreen.svg)](https://shields.io/)
[![Platform: iOS](https://img.shields.io/badge/Platform-iOS-lightgray.svg)](https://shields.io/)
[![BBS+: Signatures](https://img.shields.io/badge/BBS+-Signatures-orange.svg)](https://shields.io/)

## Project Overview

StudentVC is a cross-platform mobile application for managing and verifying academic credentials using Verifiable Credentials (VC) technology with BBS+ signatures for enhanced privacy.

This project was completed as part of the Internet of Services Lab (IoSL) course at [TU Berlin](https://www.tu.berlin/).

## Documentation & Demo

- [📱 Demo Video](https://tubcloud.tu-berlin.de/s/NWB76D3fynL6qAB)
- [📄 Project Report](docs/Mobile_Wallet-Final_Report.pdf)
- [🔧 Backend Documentation](backend/README.md)
- [📱 iOS Documentation](ios/README.md)
- [📱 Android Documentation](android/README.md)

## Quick Setup

### Prerequisites

- Android Studio 4.0+ or Xcode 12.0+
- Docker for backend

### Clone the Repository

```bash
# Clone with submodules
git clone --recursive https://github.com/yourusername/student-wallet.git
cd student-wallet
```

### Setup & Run

#### Backend

```bash
# Run the setup script (handles line endings and Docker setup)
./scripts/setup-backend.sh
```

#### Android App

```bash
cd android
./gradlew build
./gradlew installDebug
```

#### iOS App

```bash
cd ios
pod install
open StudentWallet.xcworkspace
```

## License

Licensed under the [Apache License 2.0](http://www.apache.org/licenses/LICENSE-2.0)

## Contact

Patrick Herbke: p.herbke#at##tu-berlin.de
