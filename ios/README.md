# Student card wallet (ios)

This repository contains the code of the student wallet for ios.


## Setup & Run Instructions
1. Clone this repository using `git clone --recursive <REPO_URL>`
2. Make sure you have used the `--recursive` flag when cloning, otherwise run `git submodule update --init --recursive`
3. Navigate into the `bbs-core` directory and follow the 1. and 2. to generate the required bbs framework
4. Open Project in xcode
5. Click on StudentWallet project settings in top left corner
6. Copy the projectBundle.xcconfig (moving the file into XCODE into the StudentWallet folder)
7. A window with ‘Choose options for adding the files:’ will appear. Select ‘Copy files to destination’ for action and none for targets.
8. Change your 'PRODUCT_BUNDLE_IDENTIFIER' and 'DEVELOPMENT_TEAM' to your own information in the projectBundle.xcconfig. To get the ID of your own development team got to StudentWallet -> TAGETS (Student Wallet) -> Signing & Capabilities and select your team. After selecting a team, it is necessary to perform troubleshooting for the developer team variable. Otherwise, the config stored in git is changed.
9. Check: Is the correct team and the bundle identifier set in StudentWallet -> TARGETS (Student Wallet) -> Signing & Capabilites.
10. Troubleshooting: go to StudentWallet -> TARGETS (Student Wallet) -> Build Settings and remove the entries in 'Product Bundle Identifier' (in Packaging) and 'Development Team' (in Signing). Information is reloaded automatically from the projectBundle.xcconfig.
11. Select Device and run 