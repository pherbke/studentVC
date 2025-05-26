#!/bin/bash

echo "=== Docker Tenant Configuration Test ==="
echo

# Test if Docker is available
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not available. Please install Docker first."
    exit 1
fi

echo "✅ Docker is available"
echo

# Build the image
echo "🔨 Building Docker image..."
docker build -t studentvc-backend:test . 2>/dev/null
if [ $? -eq 0 ]; then
    echo "✅ Docker image built successfully"
else
    echo "❌ Docker build failed"
    exit 1
fi
echo

# Test 1: Default tenant (TU Berlin)
echo "🧪 Test 1: Default tenant (TU Berlin)"
echo "Command: docker run --rm -p 8080:8080 -e TENANT_ID=tu-berlin studentvc-backend:test"
echo "Expected: TU Berlin configuration with red theme"
echo "Manual test: Open http://localhost:8080 in browser to verify red theme"
echo

# Test 2: FU Berlin tenant  
echo "🧪 Test 2: FU Berlin tenant"
echo "Command: docker run --rm -p 8081:8080 -e TENANT_ID=fu-berlin studentvc-backend:test"
echo "Expected: FU Berlin configuration with yellow/green theme"
echo "Manual test: Open http://localhost:8081 in browser to verify yellow/green theme"
echo

# Test 3: Environment override
echo "🧪 Test 3: Environment variable override"
echo "Command: docker run --rm -p 8082:8080 -e TENANT_ID=fu-berlin -e BRAND_PRIMARY_COLOR=#FF0000 studentvc-backend:test"
echo "Expected: FU Berlin with red primary color override"
echo "Manual test: Open http://localhost:8082 in browser to verify red override"
echo

echo "To run these tests manually:"
echo "1. docker run --rm -p 8080:8080 -e TENANT_ID=tu-berlin studentvc-backend:test"
echo "2. docker run --rm -p 8081:8080 -e TENANT_ID=fu-berlin studentvc-backend:test"
echo "3. docker run --rm -p 8082:8080 -e TENANT_ID=fu-berlin -e BRAND_PRIMARY_COLOR=#FF0000 studentvc-backend:test"
echo
echo "Open the respective ports in your browser to verify the themes."
echo "Stop containers with Ctrl+C"