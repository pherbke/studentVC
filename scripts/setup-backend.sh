#!/bin/bash
# Script to set up the backend for StudentVC

echo "Setting up StudentVC backend..."

# Fix the line endings in build.sh
echo "Fixing line endings in build.sh..."
cd "$(dirname "$0")/.."
tr -d '\r' < bbs-core/python/build.sh > bbs-core/python/temp.sh 
mv bbs-core/python/temp.sh bbs-core/python/build.sh 
chmod +x bbs-core/python/build.sh

# Copy bbs-core to backend directory
echo "Copying bbs-core to backend directory..."
cd backend
rm -rf bbs-core
mkdir -p bbs-core
cp -R ../bbs-core/* bbs-core/

# Start the backend with Docker Compose
echo "Starting backend with Docker Compose..."
docker compose up --build

echo "Setup complete!" 