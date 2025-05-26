#!/bin/bash

# Run X.509 Certificate Integration Tests for StudentVC
# This script runs all tests related to X.509 certificate functionality,
# including core functionality, HAVID compliance, and OID4VC/OID4VP integration.

set -e  # Exit on any error

# Define colors for better readability
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=========================================${NC}"
echo -e "${BLUE}  StudentVC X.509 Certificate Test Suite ${NC}"
echo -e "${BLUE}=========================================${NC}"
echo ""

# Ensure we're in the backend directory
cd "$(dirname "$0")"
echo -e "${YELLOW}Working directory: $(pwd)${NC}"
echo ""

# Create necessary test directories if they don't exist
mkdir -p ./tests/coverage

# Run basic setup checks
echo -e "${BLUE}Running dependency checks...${NC}"
python -c "from cryptography.x509 import Certificate; print('✓ Cryptography library installed correctly')" || { echo -e "${RED}Error: Cryptography library not installed or not working${NC}"; exit 1; }
echo ""

# Run tests with coverage
echo -e "${BLUE}Running core X.509 integration tests...${NC}"
python -m pytest tests/test_x509.py -v

echo -e "${BLUE}Running X.509 end-to-end tests...${NC}"
python -m pytest tests/test_x509_e2e.py -v

echo -e "${BLUE}Running HAVID compliance tests...${NC}"
python -m pytest tests/test_havid.py -v

echo -e "${BLUE}Running OID4VC/OID4VP integration tests...${NC}"
python -m pytest tests/test_oid4vc_integration.py -v

# Generate coverage report
echo -e "${BLUE}Generating coverage report...${NC}"
python -m pytest tests/test_x509.py tests/test_x509_e2e.py tests/test_havid.py tests/test_oid4vc_integration.py \
  --cov=src.x509 --cov=src.verifier --cov=src.issuer \
  --cov-report=html:tests/coverage/html \
  --cov-report=term

echo ""
echo -e "${GREEN}✓ All X.509 tests completed successfully${NC}"
echo -e "${YELLOW}Coverage report available at: tests/coverage/html/index.html${NC}"
echo ""

# Provide instructions for viewing the coverage report
echo -e "${BLUE}To view coverage report:${NC}"
echo "  open tests/coverage/html/index.html"
echo "" 