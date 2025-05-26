"""
Tenant Configuration Module

Handles multi-tenant configuration for different universities
based on environment variables.
"""

import os
import logging

logger = logging.getLogger(__name__)

# Default tenant configurations
TENANT_CONFIGS = {
    'tu-berlin': {
        'name': 'TU Berlin',
        'full_name': 'Technische Universität Berlin',
        'domain': 'tu-berlin.de',
        'did': 'did:ebsi:tu-berlin',  # Using shared did:ebsi as requested
        'colors': {
            'primary': '#c40e20',      # TU Berlin Red (corrected)
            'secondary': '#000000',     # Black
            'accent': '#f8f9fa',       # Light Gray
            'text': '#000000',         # Black
            'background': '#ffffff',   # White
            'light': '#f1f3f4',       # Very Light Gray
            'primary_text': '#ffffff'  # White text for primary color buttons
        },
        'logo': {
            'main': '/static/logos/tub_logo.png',
            'icon': '/static/logos/tub_logo.png', 
            'favicon': '/static/logos/tub_logo.png'
        },
        'shibboleth': {
            'metadata_url': 'https://shibboleth.tu-berlin.de/metadata',
            'entity_id': 'https://shibboleth.tu-berlin.de',
            'sso_url': 'https://shibboleth.tu-berlin.de/profile/SAML2/Redirect/SSO',
            'slo_url': 'https://shibboleth.tu-berlin.de/profile/SAML2/Redirect/SLO',
            'attribute_map': {
                'eduPersonPrincipalName': 'username',
                'displayName': 'full_name',
                'givenName': 'first_name', 
                'sn': 'last_name',
                'mail': 'email',
                'eduPersonAffiliation': 'affiliation'
            }
        }
    },
    'fu-berlin': {
        'name': 'FU Berlin',
        'full_name': 'Freie Universität Berlin',
        'domain': 'fu-berlin.de',
        'did': 'did:ebsi:fu-berlin',  # Using shared did:ebsi as requested
        'colors': {
            'primary': '#22c55e',      # Readable green (Tailwind green-500)
            'secondary': '#16a34a',    # Darker green (Tailwind green-600)
            'accent': '#f0fdf4',       # Very light green (Tailwind green-50)
            'text': '#000000',         # Black
            'background': '#ffffff',   # White
            'light': '#ecfdf5',       # Light green (Tailwind green-100)
            'primary_text': '#ffffff'  # White text for better contrast on green buttons
        },
        'logo': {
            'main': '/static/logos/fu_logo.jpg',
            'icon': '/static/logos/fu_logo.jpg',
            'favicon': '/static/logos/fu_logo.jpg'
        },
        'shibboleth': {
            'metadata_url': 'https://shibboleth.fu-berlin.de/metadata',
            'entity_id': 'https://shibboleth.fu-berlin.de',
            'sso_url': 'https://shibboleth.fu-berlin.de/profile/SAML2/Redirect/SSO',
            'slo_url': 'https://shibboleth.fu-berlin.de/profile/SAML2/Redirect/SLO',
            'attribute_map': {
                'eduPersonPrincipalName': 'username',
                'displayName': 'full_name',
                'givenName': 'first_name',
                'sn': 'last_name', 
                'mail': 'email',
                'eduPersonAffiliation': 'affiliation'
            }
        }
    }
}

class TenantConfig:
    """Tenant configuration manager"""
    
    def __init__(self):
        self.tenant_id = self._get_tenant_id()
        self.config = self._load_tenant_config()
        logger.info(f"Initialized tenant configuration for: {self.tenant_id}")
    
    def _get_tenant_id(self):
        """Get tenant ID from environment variable"""
        # Check multiple possible environment variable names
        tenant_id = (os.environ.get('TENANT_ID') or 
                    os.environ.get('TENANT_NAME') or 
                    'tu-berlin')  # Default to TU Berlin
        
        # Map common tenant name variations to canonical IDs
        tenant_mappings = {
            'TU Berlin': 'tu-berlin',
            'TU_Berlin': 'tu-berlin', 
            'tu_berlin': 'tu-berlin',
            'tuberlin': 'tu-berlin',
            'FU Berlin': 'fu-berlin',
            'FU_Berlin': 'fu-berlin',
            'fu_berlin': 'fu-berlin', 
            'fuberlin': 'fu-berlin',
            'fu-berlin-local': 'fu-berlin',
            'tu-berlin-local': 'tu-berlin'
        }
        
        # Check if tenant_id needs mapping
        if tenant_id in tenant_mappings:
            tenant_id = tenant_mappings[tenant_id]
        
        if tenant_id not in TENANT_CONFIGS:
            logger.warning(f"Unknown tenant ID: {tenant_id}, falling back to tu-berlin")
            tenant_id = 'tu-berlin'
        
        return tenant_id
    
    def _load_tenant_config(self):
        """Load configuration for current tenant"""
        base_config = TENANT_CONFIGS[self.tenant_id].copy()
        
        # Override with environment variables if provided
        env_overrides = {
            'TENANT_NAME': ('name',),
            'TENANT_FULL_NAME': ('full_name',),
            'TENANT_DOMAIN': ('domain',),
            'TENANT_DID': ('did',),
            'TENANT_PRIMARY_COLOR': ('colors', 'primary'),
            'TENANT_SECONDARY_COLOR': ('colors', 'secondary'),
            'BRAND_PRIMARY_COLOR': ('colors', 'primary'),
            'BRAND_SECONDARY_COLOR': ('colors', 'secondary'),
            'BRAND_ACCENT_COLOR': ('colors', 'accent'),
            'BRAND_TEXT_COLOR': ('colors', 'text'),
            'BRAND_BACKGROUND_COLOR': ('colors', 'background'),
            'LOGO_MAIN_PATH': ('logo', 'main'),
            'LOGO_ICON_PATH': ('logo', 'icon'),
            'LOGO_FAVICON_PATH': ('logo', 'favicon'),
            'SHIBBOLETH_METADATA_URL': ('shibboleth', 'metadata_url'),
            'SHIBBOLETH_ENTITY_ID': ('shibboleth', 'entity_id')
        }
        
        for env_var, config_path in env_overrides.items():
            env_value = os.environ.get(env_var)
            if env_value:
                # Navigate to the correct nested dictionary level
                current_dict = base_config
                for key in config_path[:-1]:
                    current_dict = current_dict[key]
                current_dict[config_path[-1]] = env_value
                logger.debug(f"Override {env_var}: {env_value}")
        
        return base_config
    
    def get(self, *keys):
        """Get configuration value using dot notation"""
        current = self.config
        for key in keys:
            current = current.get(key, {})
        return current
    
    def get_colors_css(self):
        """Generate CSS custom properties for tenant colors"""
        colors = self.config['colors']
        css_vars = []
        for name, value in colors.items():
            css_vars.append(f'--tenant-{name}: {value};')
        return '\n'.join(css_vars)
    
    def get_template_context(self):
        """Get context variables for templates"""
        return {
            'tenant': self.config,
            'tenant_id': self.tenant_id,
            'tenant_name': self.config['name'],
            'tenant_full_name': self.config['full_name'],
            'tenant_colors': self.config['colors'],
            'tenant_logo': self.config['logo'],
            'tenant_css_vars': self.get_colors_css()
        }

# Global tenant configuration instance
tenant_config = TenantConfig()