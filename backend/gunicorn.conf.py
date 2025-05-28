import multiprocessing
import os

# Use gevent worker class for Socket.IO support
worker_class = "gevent"
workers = 1  # Single worker for Socket.IO
worker_connections = 1000

# Dynamic port and SSL configuration
port = os.environ.get('PORT', '8080')
tenant_name = os.environ.get('TENANT_NAME', 'tu-berlin')
environment = os.environ.get('ENVIRONMENT', 'local')

# SSL certificate paths
cert_dir = "/instance/certs"
keyfile = f"{cert_dir}/server.key"
certfile = f"{cert_dir}/server.crt"

# Check if SSL certificates exist
ssl_enabled = os.path.exists(keyfile) and os.path.exists(certfile)

bind = f"0.0.0.0:{port}"

if ssl_enabled:
    keyfile = keyfile
    certfile = certfile
    print(f"SSL enabled for {tenant_name}-{environment} on port {port}")
    print(f"Using keyfile: {keyfile}")
    print(f"Using certfile: {certfile}")
else:
    print(f"SSL certificates not found at {keyfile} or {certfile}")
    print(f"Running HTTP on port {port}")
    # Don't set keyfile/certfile if not available

timeout = 90
keepalive = 3600
preload_app = True
