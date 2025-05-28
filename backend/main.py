from src import create_app, socketio
import os

app = create_app()
app.config['DEBUG'] = True

# Get network IP address dynamically
def get_local_ip():
    import socket
    try:
        # Connect to a remote server to get local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return "127.0.0.1"

# Configure SERVER_URL with network IP and HTTPS
local_ip = get_local_ip()
port = int(os.environ.get('PORT', 8080))
use_network_ip = os.environ.get('USE_NETWORK_IP', 'true').lower() == 'true'
network_ip = os.environ.get('NETWORK_IP', local_ip)

# Use explicit network IP if provided, otherwise use detected IP
server_ip = network_ip if use_network_ip else '127.0.0.1'

app.config['SERVER_URL'] = f"https://{server_ip}:{port}"
app.config['LOCAL_IP'] = network_ip
app.config['USE_NETWORK_IP'] = use_network_ip

# Get tenant-specific SSL certificates
tenant_name = os.environ.get('TENANT_NAME', 'TU Berlin')
environment = os.environ.get('ENVIRONMENT', 'local')

# Map tenant names to certificate directories
tenant_mapping = {
    'TU Berlin': 'tu-berlin',
    'FU Berlin': 'fu-berlin'
}

tenant_key = tenant_mapping.get(tenant_name, 'tu-berlin')
cert_dir = f"./instance/{tenant_key}-{environment}"

# SSL certificates
cert = f"{cert_dir}/fullchain.pem"
key = f"{cert_dir}/privkey.pem"

# CA configuration for HAVID §7.3 (CA-assisted DID creation)
app.config['CA_CERT_PATH'] = os.path.join("instance", "certs", "ca", "ca_cert.pem")
app.config['CA_KEY_PATH'] = os.path.join("instance", "certs", "ca", "ca_key.pem")
app.config['CA_KEY_PASSWORD'] = None  # Set to None if the key is not password protected

# Create CA certificate directories if they don't exist
ca_dir = os.path.join("instance", "certs", "ca")
os.makedirs(ca_dir, exist_ok=True)

if __name__ == '__main__':
    # Internal port is always 8080 in Docker containers
    internal_port = 8080
    
    print(f"🚀 Starting {tenant_name} ({environment})")
    print(f"📍 SERVER_URL: {app.config['SERVER_URL']}")
    print(f"🔐 SSL Certificate: {cert}")
    print(f"🔑 SSL Key: {key}")
    
    if os.path.exists(cert) and os.path.exists(key):
        print("✅ Using tenant-specific SSL certificates")
        socketio.run(app, debug=True, port=internal_port,
                     ssl_context=(cert, key), host='0.0.0.0', allow_unsafe_werkzeug=True)
    else:
        print("⚠️  SSL certificates not found, using adhoc certificates")
        socketio.run(app, debug=True, port=internal_port,
                     ssl_context='adhoc', host='0.0.0.0', allow_unsafe_werkzeug=True)
