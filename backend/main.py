from src import create_app, socketio
import os

if os.path.exists("instance/database.db"):
    os.remove("instance/database.db")


app = create_app()
app.config['DEBUG'] = True
app.config['SERVER_URL'] = "https://127.0.0.1:8080"

# Default SSL certificates
cert = "./instance/fullchain.pem"
key = "./instance/privkey.pem"

# CA configuration for HAVID §7.3 (CA-assisted DID creation)
app.config['CA_CERT_PATH'] = os.path.join("instance", "certs", "ca", "ca_cert.pem")
app.config['CA_KEY_PATH'] = os.path.join("instance", "certs", "ca", "ca_key.pem")
app.config['CA_KEY_PASSWORD'] = None  # Set to None if the key is not password protected

# Create CA certificate directories if they don't exist
ca_dir = os.path.join("instance", "certs", "ca")
os.makedirs(ca_dir, exist_ok=True)

if __name__ == '__main__':
    if os.path.exists(cert) and os.path.exists(key):
        socketio.run(app, debug=True, port=8080,
                     ssl_context=(cert, key), host='0.0.0.0', allow_unsafe_werkzeug=True)
    else:
        socketio.run(app, debug=True, port=8080,
                     ssl_context='adhoc', host='0.0.0.0', allow_unsafe_werkzeug=True)
