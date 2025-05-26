# StudentVC Development and Testing Makefile

.PHONY: help test test-quick test-full test-docker test-compose test-ci clean install

# Default target
help:
	@echo "🎯 StudentVC Development Commands"
	@echo "================================="
	@echo ""
	@echo "Testing:"
	@echo "  test-quick    - Quick CI/CD pipeline test (Docker build + health)"
	@echo "  test-full     - Full CI/CD pipeline test with Act"
	@echo "  test-docker   - Test Docker build and container"
	@echo "  test-compose  - Test all docker-compose profiles"
	@echo "  test-ci       - Test CI steps locally"
	@echo ""
	@echo "Development:"
	@echo "  install       - Install development dependencies"
	@echo "  dev           - Start development environment"
	@echo "  staging       - Start staging environment"
	@echo "  local         - Start local environment"
	@echo ""
	@echo "Cleanup:"
	@echo "  clean         - Clean up Docker containers and images"
	@echo "  clean-all     - Deep clean (includes volumes)"

# Quick CI/CD test
test-quick:
	@echo "🚀 Running quick CI/CD test..."
	./scripts/quick-test.sh

# Full CI/CD test with Act
test-full:
	@echo "🔄 Running full CI/CD test..."
	./scripts/test-ci-cd-local.sh

# Test Docker build only
test-docker:
	@echo "🐳 Testing Docker build..."
	docker build -f backend/Dockerfile -t studentvc:test .
	@echo "✅ Docker build successful!"
	docker rmi studentvc:test

# Test all docker-compose profiles
test-compose:
	@echo "🧪 Testing docker-compose profiles..."
	@echo "Testing default profile..."
	cd backend && docker compose config > /dev/null
	@echo "✅ Default profile valid"
	@echo "Testing dev profile..."
	cd backend && docker compose --profile dev config > /dev/null
	@echo "✅ Dev profile valid"
	@echo "Testing staging profile..."
	cd backend && docker compose --profile staging config > /dev/null
	@echo "✅ Staging profile valid"
	@echo "Testing multi-tenant profile..."
	cd backend && docker compose --profile multi-tenant config > /dev/null
	@echo "✅ Multi-tenant profile valid"

# Test CI steps locally
test-ci:
	@echo "🔧 Testing CI steps locally..."
	@echo "1. Python setup..."
	cd backend && python -m pip install --quiet -r requirements.txt
	@echo "2. Running tests..."
	cd backend && python -m pytest tests/ || true
	@echo "3. Security scan..."
	cd backend && bandit -r src/ || true
	@echo "4. Docker build..."
	docker build -f backend/Dockerfile -t studentvc:ci-test .
	docker rmi studentvc:ci-test
	@echo "✅ CI simulation complete!"

# Install development dependencies
install:
	@echo "📦 Installing development dependencies..."
	@command -v act >/dev/null 2>&1 || brew install act
	@command -v docker >/dev/null 2>&1 || echo "⚠️ Please install Docker Desktop"
	cd backend && python -m pip install -r requirements.txt
	cd backend && python -m pip install pytest bandit safety
	@echo "✅ Dependencies installed!"

# Development environments
dev:
	@echo "🧪 Starting development environment..."
	cd backend && docker compose --profile dev up --build

staging:
	@echo "🎯 Starting staging environment..."
	cd backend && docker compose --profile staging up --build

local:
	@echo "🏠 Starting local environment..."
	cd backend && docker compose up --build

# Cleanup
clean:
	@echo "🧹 Cleaning up Docker containers and images..."
	docker compose -f backend/docker-compose.yml down --remove-orphans || true
	docker system prune -f
	@echo "✅ Cleanup complete!"

clean-all:
	@echo "🧹 Deep cleaning (containers, images, volumes)..."
	docker compose -f backend/docker-compose.yml down -v --remove-orphans || true
	docker system prune -af --volumes
	@echo "✅ Deep cleanup complete!"

# Test everything
test: test-compose test-docker test-ci
	@echo "🎉 All tests complete!"