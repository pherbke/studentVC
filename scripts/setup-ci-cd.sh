#!/bin/bash
set -e

echo "🚀 Setting up StudentVC CI/CD Pipeline"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if we're in the right directory
if [ ! -f "backend/main.py" ]; then
    print_error "Please run this script from the StudentVC root directory"
    exit 1
fi

# Check prerequisites
print_status "Checking prerequisites..."

# Check Docker
if ! command -v docker &> /dev/null; then
    print_error "Docker is not installed. Please install Docker first."
    exit 1
fi

# Check kubectl (optional)
if ! command -v kubectl &> /dev/null; then
    print_warning "kubectl not found. Kubernetes deployments won't be available."
fi

# Check if GitHub CLI is available (optional)
if command -v gh &> /dev/null; then
    print_status "GitHub CLI found. You can use 'gh' commands for GitHub integration."
else
    print_warning "GitHub CLI not found. Manual GitHub setup will be required."
fi

# Create necessary directories
print_status "Creating CI/CD directories..."
mkdir -p .github/workflows
mkdir -p k8s/{staging,production}
mkdir -p scripts
mkdir -p backend/tests/integration

# Set up GitHub repository secrets (if GitHub CLI is available)
if command -v gh &> /dev/null && gh auth status &> /dev/null; then
    print_status "Setting up GitHub repository secrets..."
    
    # Generate a sample secret key for demo purposes
    SECRET_KEY=$(openssl rand -base64 32)
    
    # Set secrets (you'll need to replace these with actual values)
    cat << EOF

📋 REQUIRED GITHUB SECRETS:
Please set these secrets in your GitHub repository:

Repository Settings > Secrets and variables > Actions

1. KUBE_CONFIG_STAGING (base64 encoded kubeconfig for staging cluster)
2. KUBE_CONFIG_PRODUCTION (base64 encoded kubeconfig for production cluster)
3. DATABASE_URL_STAGING (PostgreSQL connection string for staging)
4. DATABASE_URL_PRODUCTION (PostgreSQL connection string for production)
5. SECRET_KEY_STAGING (Flask secret key for staging)
6. SECRET_KEY_PRODUCTION (Flask secret key for production)

Example commands to set secrets:
gh secret set KUBE_CONFIG_STAGING < ~/.kube/config-staging-base64
gh secret set SECRET_KEY_STAGING --body "${SECRET_KEY}"

EOF
else
    print_warning "GitHub CLI not authenticated. You'll need to set up repository secrets manually."
fi

# Create health check endpoints
print_status "Setting up health check endpoints..."

# Create health check blueprint
cat > backend/src/health.py << 'EOF'
from flask import Blueprint, jsonify
import os
import time
import psutil

health = Blueprint('health', __name__)

@health.route('/health', methods=['GET'])
def health_check():
    """Basic health check endpoint"""
    return jsonify({
        "status": "healthy",
        "timestamp": int(time.time()),
        "version": os.environ.get("IMAGE_TAG", "dev"),
        "environment": os.environ.get("ENVIRONMENT", "development"),
        "tenant": os.environ.get("TENANT_NAME", "unknown")
    }), 200

@health.route('/ready', methods=['GET'])
def readiness_check():
    """Readiness check for Kubernetes"""
    try:
        # Add your readiness checks here
        # Example: database connection, required services, etc.
        
        return jsonify({
            "status": "ready",
            "checks": {
                "database": "ok",  # Replace with actual DB check
                "storage": "ok"    # Replace with actual storage check
            }
        }), 200
    except Exception as e:
        return jsonify({
            "status": "not ready",
            "error": str(e)
        }), 503

@health.route('/metrics', methods=['GET'])
def metrics():
    """Basic metrics endpoint"""
    try:
        cpu_percent = psutil.cpu_percent()
        memory = psutil.virtual_memory()
        
        return jsonify({
            "cpu_usage_percent": cpu_percent,
            "memory_usage_percent": memory.percent,
            "memory_available_mb": memory.available // 1024 // 1024,
            "uptime_seconds": time.time() - psutil.boot_time()
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
EOF

# Update __init__.py to include health blueprint
print_status "Registering health check blueprint..."

if ! grep -q "from .health import health" backend/src/__init__.py; then
    # Add health import and registration
    sed -i '/from .validate.validate import validate/a from .health import health' backend/src/__init__.py
    sed -i '/app.register_blueprint(validate, url_prefix='"'"'\/validate'"'"')/a \    app.register_blueprint(health, url_prefix='"'"'\/'"'"')' backend/src/__init__.py
fi

# Create test configuration
print_status "Setting up test configuration..."

cat > backend/tests/conftest.py << 'EOF'
import pytest
import os
import sys
import tempfile

# Add the src directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from src import create_app, db

@pytest.fixture
def app():
    """Create application for testing"""
    # Create a temporary file for the test database
    db_fd, db_path = tempfile.mkstemp()
    
    app = create_app()
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
    app.config['WTF_CSRF_ENABLED'] = False
    
    with app.app_context():
        db.create_all()
        yield app
        db.drop_all()
    
    os.close(db_fd)
    os.unlink(db_path)

@pytest.fixture
def client(app):
    """Test client for the Flask application"""
    return app.test_client()

@pytest.fixture
def runner(app):
    """Test runner for the Flask application"""
    return app.test_cli_runner()
EOF

# Create basic tests
cat > backend/tests/test_health.py << 'EOF'
import pytest
import json

def test_health_endpoint(client):
    """Test health check endpoint"""
    response = client.get('/health')
    assert response.status_code == 200
    
    data = json.loads(response.data)
    assert data['status'] == 'healthy'
    assert 'timestamp' in data
    assert 'version' in data

def test_readiness_endpoint(client):
    """Test readiness check endpoint"""
    response = client.get('/ready')
    assert response.status_code == 200
    
    data = json.loads(response.data)
    assert data['status'] == 'ready'
    assert 'checks' in data

def test_metrics_endpoint(client):
    """Test metrics endpoint"""
    response = client.get('/metrics')
    assert response.status_code == 200
    
    data = json.loads(response.data)
    assert 'cpu_usage_percent' in data
    assert 'memory_usage_percent' in data
EOF

# Create integration tests
cat > backend/tests/integration/test_multi_tenant.py << 'EOF'
import pytest
import requests
import time

class TestMultiTenant:
    """Integration tests for multi-tenant deployment"""
    
    def test_tu_berlin_health(self):
        """Test TU Berlin instance health"""
        try:
            response = requests.get('http://localhost:8080/health', timeout=10)
            assert response.status_code == 200
            data = response.json()
            assert data['tenant'] == 'TU Berlin'
        except requests.exceptions.ConnectionError:
            pytest.skip("TU Berlin instance not running")
    
    def test_fu_berlin_health(self):
        """Test FU Berlin instance health"""
        try:
            response = requests.get('http://localhost:8081/health', timeout=10)
            assert response.status_code == 200
            data = response.json()
            assert data['tenant'] == 'FU Berlin'
        except requests.exceptions.ConnectionError:
            pytest.skip("FU Berlin instance not running")
    
    def test_tenant_specific_branding(self):
        """Test that tenants have different branding"""
        try:
            # Test TU Berlin
            tu_response = requests.get('http://localhost:8080/verifier/settings', timeout=10)
            assert tu_response.status_code == 200
            assert 'TU Berlin' in tu_response.text
            
            # Test FU Berlin
            fu_response = requests.get('http://localhost:8081/verifier/settings', timeout=10)
            assert fu_response.status_code == 200
            assert 'FU Berlin' in fu_response.text
            
            # Ensure they're different
            assert tu_response.text != fu_response.text
            
        except requests.exceptions.ConnectionError:
            pytest.skip("One or both tenant instances not running")
EOF

# Create local development script
cat > scripts/dev-multi-tenant.sh << 'EOF'
#!/bin/bash
# Development script for multi-tenant setup

echo "🎓 Starting StudentVC Multi-Tenant Development Environment"

# Build the latest image
echo "Building Docker image..."
cd backend
docker build -t studentvc:dev .
cd ..

# Start both universities
echo "Starting TU Berlin (port 8080)..."
docker run -d --name tu-berlin-dev \
  -p 8080:8080 \
  -e TENANT_NAME="TU Berlin" \
  -e ENVIRONMENT="development" \
  -v $(pwd)/backend/instance/tu-berlin:/instance \
  studentvc:dev

echo "Starting FU Berlin (port 8081)..."
docker run -d --name fu-berlin-dev \
  -p 8081:8080 \
  -e TENANT_NAME="FU Berlin" \
  -e ENVIRONMENT="development" \
  -v $(pwd)/backend/instance/fu-berlin:/instance \
  studentvc:dev

echo "✅ Multi-tenant development environment started!"
echo "🔗 TU Berlin: https://localhost:8080"
echo "🔗 FU Berlin: https://localhost:8081"

# Wait for services to start
echo "Waiting for services to start..."
sleep 10

# Health checks
echo "Running health checks..."
curl -f http://localhost:8080/health && echo "✅ TU Berlin healthy"
curl -f http://localhost:8081/health && echo "✅ FU Berlin healthy"

echo "🎉 Development environment ready!"
EOF

chmod +x scripts/dev-multi-tenant.sh

# Create cleanup script
cat > scripts/cleanup-dev.sh << 'EOF'
#!/bin/bash
echo "🧹 Cleaning up development environment..."

# Stop and remove containers
docker stop tu-berlin-dev fu-berlin-dev 2>/dev/null || true
docker rm tu-berlin-dev fu-berlin-dev 2>/dev/null || true

# Remove development volumes (optional)
# docker volume prune -f

echo "✅ Cleanup completed!"
EOF

chmod +x scripts/cleanup-dev.sh

# Final instructions
print_status "CI/CD setup completed! 🎉"

cat << EOF

📋 NEXT STEPS:

1. 🔑 Set up GitHub repository secrets (see above)

2. 🐳 Test locally:
   ./scripts/dev-multi-tenant.sh

3. 🧪 Run tests:
   cd backend && python -m pytest tests/ -v

4. 🚀 Push to trigger CI/CD:
   git add .
   git commit -m "Add CI/CD pipeline"
   git push origin X509compatibility

5. 📊 Monitor deployments:
   - Check GitHub Actions: https://github.com/$(git config --get remote.origin.url | sed 's|.*github.com[:/]||' | sed 's|\.git||')/actions
   - Staging: https://tu-berlin-staging.studentvc.org
   - Production: https://tu-berlin.studentvc.org

🎛️  MANUAL TRIGGERS:
   - Deploy to staging: GitHub Actions > StudentVC Multi-Tenant CI/CD > Run workflow
   - Deploy to production: Merge to main branch
   - Rollback: Run workflow with 'rollback' environment

Happy deploying! 🚀
EOF
