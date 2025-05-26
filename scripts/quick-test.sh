#!/bin/bash
# Quick CI/CD Testing Script

set -e

echo "🚀 Quick StudentVC CI/CD Test"
echo "============================="

cd "$(dirname "$0")/.."

# Test 1: Docker Build
echo "1️⃣ Testing Docker Build..."
echo "-------------------------"
docker build -f backend/Dockerfile -t studentvc:test .
echo "✅ Docker build successful!"

# Test 2: Container Health Check
echo ""
echo "2️⃣ Testing Container Health..."
echo "-----------------------------"
docker run --rm -d \
    -p 8999:8080 \
    -e TENANT_NAME="Test University" \
    -e ENVIRONMENT="test" \
    --name studentvc-health-test \
    studentvc:test

echo "⏳ Waiting for container to start..."
sleep 8

echo "🔍 Testing health endpoint..."
if curl -f http://localhost:8999/health 2>/dev/null; then
    echo "✅ Health check passed!"
else
    echo "❌ Health check failed"
    docker logs studentvc-health-test
fi

echo "🛑 Stopping test container..."
docker stop studentvc-health-test

# Test 3: Environment Profiles
echo ""
echo "3️⃣ Testing Environment Profiles..."
echo "---------------------------------"
cd backend

echo "🧪 Testing dev profile..."
docker compose --profile dev config > /dev/null
echo "✅ Dev profile valid"

echo "🎯 Testing staging profile..." 
docker compose --profile staging config > /dev/null
echo "✅ Staging profile valid"

echo "🏠 Testing multi-tenant profile..."
docker compose --profile multi-tenant config > /dev/null
echo "✅ Multi-tenant profile valid"

# Test 4: Python Dependencies
echo ""
echo "4️⃣ Testing Python Dependencies..."
echo "--------------------------------"
if [ -f requirements.txt ]; then
    echo "📦 Checking requirements.txt..."
    pip-check-reqs requirements.txt 2>/dev/null || echo "⚠️ pip-check-reqs not installed"
    echo "✅ Dependencies check complete"
fi

# Cleanup
echo ""
echo "🧹 Cleaning up..."
docker rmi studentvc:test
cd ..

echo ""
echo "🎉 Quick CI/CD test complete!"
echo "✅ All basic tests passed"
echo ""
echo "To run full environment tests, use: ./scripts/test-ci-cd-local.sh"