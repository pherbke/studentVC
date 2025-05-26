#!/usr/bin/env python3
"""
Test script for tenant configuration
"""

import os
import sys
sys.path.append('src')

from src.tenant_config import TenantConfig

def test_tenant_config():
    print("=== Tenant Configuration Test ===\n")
    
    # Test default configuration (TU Berlin)
    print("1. Testing default configuration (TU Berlin):")
    config = TenantConfig()
    print(f"   Tenant ID: {config.tenant_id}")
    print(f"   Name: {config.get('name')}")
    print(f"   Primary Color: {config.get('colors', 'primary')}")
    print(f"   DID: {config.get('did')}")
    print()
    
    # Test FU Berlin configuration
    print("2. Testing FU Berlin configuration:")
    os.environ['TENANT_ID'] = 'fu-berlin'
    config_fu = TenantConfig()
    print(f"   Tenant ID: {config_fu.tenant_id}")
    print(f"   Name: {config_fu.get('name')}")
    print(f"   Primary Color: {config_fu.get('colors', 'primary')}")
    print(f"   Secondary Color: {config_fu.get('colors', 'secondary')}")
    print(f"   DID: {config_fu.get('did')}")
    print()
    
    # Test environment variable override
    print("3. Testing environment variable override:")
    os.environ['BRAND_PRIMARY_COLOR'] = '#FF0000'
    os.environ['TENANT_NAME'] = 'Custom University'
    config_custom = TenantConfig()
    print(f"   Overridden Name: {config_custom.get('name')}")
    print(f"   Overridden Primary Color: {config_custom.get('colors', 'primary')}")
    print()
    
    # Test CSS generation
    print("4. Testing CSS variables generation:")
    css_vars = config_custom.get_colors_css()
    print("   Generated CSS:")
    for line in css_vars.split('\n')[:3]:  # Show first 3 lines
        print(f"   {line}")
    print("   ...")
    print()
    
    # Test template context
    print("5. Testing template context:")
    context = config_custom.get_template_context()
    print(f"   Tenant Name: {context['tenant_name']}")
    print(f"   Tenant ID: {context['tenant_id']}")
    print(f"   Has Colors: {'tenant_colors' in context}")
    print()
    
    print("✅ All tests completed successfully!")

if __name__ == '__main__':
    test_tenant_config()