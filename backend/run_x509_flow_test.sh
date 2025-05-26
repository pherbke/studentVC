#!/bin/bash

# Run X.509 Credential Flow Test for StudentVC
# This script runs the end-to-end test for X.509 credential flow with did:web:edu:tub DID

set -e  # Exit on any error

# Define colors for better readability
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}============================================${NC}"
echo -e "${BLUE}  StudentVC X.509 Credential Flow Test     ${NC}"
echo -e "${BLUE}============================================${NC}"
echo ""

# Ensure we're in the backend directory
cd "$(dirname "$0")"
echo -e "${YELLOW}Working directory: $(pwd)${NC}"
echo ""

# Activate virtual environment
if [ -d "venv" ]; then
    echo -e "${BLUE}Activating virtual environment...${NC}"
    source venv/bin/activate
else
    echo -e "${YELLOW}Creating virtual environment...${NC}"
    python3 -m venv venv
    source venv/bin/activate
    echo -e "${BLUE}Installing dependencies...${NC}"
    pip install cryptography pytest
fi
echo ""

# Check for dependencies
echo -e "${BLUE}Checking dependencies...${NC}"
python -c "from cryptography.x509 import Certificate; print('✓ Cryptography library installed correctly')" || { echo -e "${RED}Error: Cryptography library not installed or not working${NC}"; exit 1; }
python -c "import pytest; print('✓ Pytest installed correctly')" || { echo -e "${RED}Error: Pytest not installed${NC}"; exit 1; }
echo ""

# Run the test with detailed output
echo -e "${BLUE}Running X.509 credential flow test...${NC}"
echo -e "${YELLOW}This test demonstrates a complete flow of:${NC}"
echo -e "${YELLOW}1. Creating a test X.509 certificate${NC}"
echo -e "${YELLOW}2. Creating a did:web:edu:tub DID linked to the certificate${NC}"
echo -e "${YELLOW}3. Creating a DID document with the certificate as verification method${NC}"
echo -e "${YELLOW}4. Signing a credential with the X.509 certificate${NC}"
echo -e "${YELLOW}5. Storing the credential locally${NC}"
echo -e "${YELLOW}6. Verifying the credential using both DID and X.509 trust paths${NC}"
echo ""

# Run the test
python -m pytest tests/test_x509_flow.py -v

# Check the result
if [ $? -eq 0 ]; then
    echo ""
    echo -e "${GREEN}✓ X.509 credential flow test completed successfully${NC}"
else
    echo ""
    echo -e "${RED}✗ X.509 credential flow test failed${NC}"
    exit 1
fi

# Deactivate virtual environment
deactivate

# Make script executable
chmod +x "$0" 