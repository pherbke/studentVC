# Student card wallet (android)

This repository contains the code of the student wallet for ios.

## Setup & Run Instructions
Use Gradle to download all dependencies

## Run Backend
To create QR Codes to scan, please run the Backend, its in the same RepoGroup

## Run Local
in
`AppData/Local/Android/Sdk/platform-tools` 
you can find the ADB, to connect with your phone to the docker backend

WIndows:
` .\adb.exe reverse tcp:8080 tcp:8080`
to reverse phone local to computer (therefore docker) local
