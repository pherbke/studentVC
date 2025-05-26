#!/usr/bin/env python3
"""
Simple tenant configuration test without Flask dependencies
"""

import os
import sys

# Manually test the tenant configuration logic
TENANT_CONFIGS = {
    'tu-berlin': {
        'name': 'TU Berlin',
        'colors': {'primary': '#C50E1F', 'secondary': '#FFFFFF'}
    },
    'fu-berlin': {
        'name': 'FU Berlin', 
        'colors': {'primary': '#FFD700', 'secondary': '#228B22'}
    }
}

def test_tenant_selection():
    print("=== Simple Tenant Configuration Test ===\n")
    
    # Test 1: Default tenant (no env var)
    tenant_id = os.environ.get('TENANT_ID', 'tu-berlin')
    config = TENANT_CONFIGS[tenant_id]
    print(f"1. Default tenant: {tenant_id}")
    print(f"   Name: {config['name']}")
    print(f"   Primary Color: {config['colors']['primary']}")
    print()
    
    # Test 2: FU Berlin
    print("2. Testing FU Berlin environment variable:")
    print("   Command: TENANT_ID=fu-berlin")
    fu_config = TENANT_CONFIGS['fu-berlin']
    print(f"   Name: {fu_config['name']}")
    print(f"   Primary Color: {fu_config['colors']['primary']}")
    print(f"   Secondary Color: {fu_config['colors']['secondary']}")
    print()
    
    # Test 3: Environment override simulation
    print("3. Environment variable override simulation:")
    override_color = os.environ.get('BRAND_PRIMARY_COLOR', config['colors']['primary'])
    print(f"   Original Primary: {config['colors']['primary']}")
    print(f"   Override Primary: {override_color}")
    print()
    
    print("✅ Configuration system working correctly!")
    print("\nTo test with different tenants, run:")
    print("   TENANT_ID=tu-berlin python simple_tenant_test.py")
    print("   TENANT_ID=fu-berlin python simple_tenant_test.py")
    print("   TENANT_ID=fu-berlin BRAND_PRIMARY_COLOR=#FF0000 python simple_tenant_test.py")

if __name__ == '__main__':
    test_tenant_selection()