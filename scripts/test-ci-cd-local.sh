#!/bin/bash
# Local CI/CD Testing Script for StudentVC

set -e

echo "🧪 StudentVC Local CI/CD Testing"
echo "================================="

# Check if act is installed
if ! command -v act &> /dev/null; then
    echo "❌ Act is not installed. Installing via Homebrew..."
    brew install act
fi

# Check if Docker is running
if ! docker info &> /dev/null; then
    echo "❌ Docker is not running. Please start Docker Desktop."
    exit 1
fi

echo "✅ Prerequisites met"
echo ""

# Function to run specific workflow
run_workflow() {
    local event=$1
    local workflow=$2
    
    echo "🚀 Running workflow: $workflow (event: $event)"
    echo "-------------------------------------------"
    
    act $event \
        --workflows .github/workflows/$workflow \
        --platform ubuntu-latest=catthehacker/ubuntu:act-latest \
        --env GITHUB_TOKEN="fake-token-for-testing" \
        --env-file .env.test \
        --verbose
}

# Create test environment file
create_test_env() {
    echo "📝 Creating test environment file..."
    cat > .env.test << EOF
REGISTRY=localhost:5000
IMAGE_NAME=studentvc-test
ENVIRONMENT=test
TENANT_NAME=Test University
SERVER_URL=http://localhost:8080
UNIVERSITY_TYPE=test
CREDENTIAL_SCHEMA_VERSION=v1.0-test
DID_METHOD=did:web:test:university
LOG_LEVEL=DEBUG
EOF
    echo "✅ Test environment file created"
}

# Menu for testing options
show_menu() {
    echo "Select testing option:"
    echo "1) Test full CI/CD pipeline (push event)"
    echo "2) Test build only (no deployment)"
    echo "3) Test dev deployment"
    echo "4) Test staging deployment"
    echo "5) Test Docker build locally"
    echo "6) Test docker-compose environments"
    echo "7) Exit"
}

# Docker build test
test_docker_build() {
    echo "🐳 Testing Docker build locally..."
    echo "--------------------------------"
    
    cd "$(dirname "$0")/.."
    
    echo "Building StudentVC Docker image..."
    docker build \
        -f backend/Dockerfile \
        -t studentvc:local-test \
        .
    
    echo "✅ Docker build successful!"
    echo "🏃 Testing container startup..."
    
    docker run --rm -d \
        -p 8888:8080 \
        -e TENANT_NAME="Test University" \
        -e ENVIRONMENT="local-test" \
        --name studentvc-test \
        studentvc:local-test
    
    sleep 5
    
    echo "🔍 Testing health endpoint..."
    if curl -f http://localhost:8888/health &> /dev/null; then
        echo "✅ Container is healthy!"
    else
        echo "❌ Container health check failed"
    fi
    
    echo "🛑 Stopping test container..."
    docker stop studentvc-test
    
    echo "🧹 Cleaning up..."
    docker rmi studentvc:local-test
}

# Docker compose test
test_docker_compose() {
    echo "🐳 Testing Docker Compose environments..."
    echo "---------------------------------------"
    
    cd "$(dirname "$0")/.."
    
    echo "Available profiles:"
    echo "- default (local)"
    echo "- multi-tenant"  
    echo "- dev"
    echo "- staging"
    
    read -p "Enter profile to test (or 'default'): " profile
    
    if [ "$profile" = "default" ]; then
        echo "🚀 Testing default local environment..."
        docker compose up --build -d
    else
        echo "🚀 Testing $profile environment..."
        docker compose --profile $profile up --build -d
    fi
    
    echo "⏳ Waiting for services to start..."
    sleep 10
    
    echo "🔍 Checking service health..."
    docker compose ps
    
    echo "🔗 Available endpoints:"
    if [ "$profile" = "default" ]; then
        echo "- TU Berlin: http://localhost:8080"
    elif [ "$profile" = "multi-tenant" ]; then
        echo "- TU Berlin: http://localhost:8080"
        echo "- FU Berlin: http://localhost:8081"
    elif [ "$profile" = "dev" ]; then
        echo "- TU Berlin Dev: http://localhost:8082"
        echo "- FU Berlin Dev: http://localhost:8083"
        echo "- Debug ports: 9092, 9093"
    elif [ "$profile" = "staging" ]; then
        echo "- TU Berlin Staging: http://localhost:8084"
        echo "- FU Berlin Staging: http://localhost:8085"
    fi
    
    read -p "Press Enter to stop and cleanup..."
    docker compose down -v
}

# Simulate CI/CD steps
simulate_ci_steps() {
    echo "🔧 Simulating CI/CD pipeline steps..."
    echo "-----------------------------------"
    
    cd "$(dirname "$0")/.."
    
    echo "1️⃣ Checkout (simulated)"
    echo "✅ Code checkout complete"
    
    echo "2️⃣ Python setup and testing..."
    if [ -d "backend/venv" ]; then
        source backend/venv/bin/activate
    fi
    
    echo "📦 Installing dependencies..."
    cd backend
    pip install -r requirements.txt
    
    echo "🧪 Running tests..."
    python -m pytest tests/ || echo "⚠️ Some tests failed"
    
    echo "🔍 Security scan..."
    bandit -r src/ || echo "⚠️ Security issues found"
    
    cd ..
    
    echo "3️⃣ Version generation..."
    VERSION="local-$(date +%Y%m%d-%H%M%S)"
    echo "Generated version: $VERSION"
    
    echo "4️⃣ Docker build..."
    docker build \
        -f backend/Dockerfile \
        -t "studentvc:$VERSION" \
        .
    
    echo "✅ CI/CD simulation complete!"
    echo "🏷️ Built image: studentvc:$VERSION"
}

# Main execution
main() {
    create_test_env
    
    while true; do
        echo ""
        show_menu
        read -p "Choose option (1-7): " choice
        
        case $choice in
            1)
                echo "🔄 Testing full CI/CD pipeline..."
                run_workflow "push" "ci-cd.yml"
                ;;
            2)
                echo "🔨 Testing build only..."
                simulate_ci_steps
                ;;
            3)
                echo "🧪 Testing dev deployment..."
                run_workflow "workflow_dispatch" "ci-cd.yml" --input environment=dev
                ;;
            4)
                echo "🎯 Testing staging deployment..."
                run_workflow "workflow_dispatch" "ci-cd.yml" --input environment=staging
                ;;
            5)
                test_docker_build
                ;;
            6)
                test_docker_compose
                ;;
            7)
                echo "👋 Goodbye!"
                break
                ;;
            *)
                echo "❌ Invalid option. Please choose 1-7."
                ;;
        esac
    done
    
    # Cleanup
    rm -f .env.test
}

# Run main function
main "$@"