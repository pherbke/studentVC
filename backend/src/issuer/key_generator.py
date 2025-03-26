from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import os
from flask import current_app as app
import logging
import base58
import base64
import importlib.util

bbs_core_path = os.path.join(os.path.dirname(
    __file__), "..", "..", "bbs-core", "python", "bbs_core.py")
bbs_core_path = os.path.abspath(bbs_core_path)
spec = importlib.util.spec_from_file_location("bbs_core", bbs_core_path)
bbs_core = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bbs_core)

logger = logging.getLogger(__name__)


def load_or_generate_bbs_keys():
    private_key_path = os.path.join(
        app.config['INSTANCE_FOLDER_PATH'], 'bbs_private.pem')
    public_key_path = os.path.join(
        app.config['INSTANCE_FOLDER_PATH'], 'bbs_public.pem')
    # Check if the private and public keys already exist
    if os.path.exists(private_key_path) and os.path.exists(public_key_path):
        return load_existing_bbs_keys()
    return generate_bbs_keys()


def generate_bbs_keys():
    key_pair = bbs_core.GenerateKeyPair().generate_key_pair()
    dpub_key_bytes = key_pair.dpub_key_bytes
    priv_key_bytes = key_pair.priv_key_bytes
    with open(os.path.join(app.config['INSTANCE_FOLDER_PATH'], 'bbs_private.pem'), "wb") as private_file:
        private_file.write(base64.b64encode(priv_key_bytes))

    with open(os.path.join(app.config['INSTANCE_FOLDER_PATH'], 'bbs_public.pem'), "wb") as public_file:
        public_file.write(base64.b64encode(dpub_key_bytes))

    return priv_key_bytes, dpub_key_bytes


def load_existing_bbs_keys():
    private_key_path = os.path.join(
        app.config['INSTANCE_FOLDER_PATH'], 'bbs_private.pem')
    public_key_path = os.path.join(
        app.config['INSTANCE_FOLDER_PATH'], 'bbs_public.pem')
    logger.debug("Keys exist. Loading keys...")
    # Load the existing private key
    with open(private_key_path, "rb") as private_file:
        private_key = base64.b64decode(private_file.read().decode('utf-8'))

    # Load the existing public key
    with open(public_key_path, "rb") as public_file:
        public_key = base64.b64decode(public_file.read().decode('utf-8'))

    return private_key, public_key


def load_or_generate_keys():
    private_key_path = os.path.join(
        app.config['INSTANCE_FOLDER_PATH'], 'private.pem')
    public_key_path = os.path.join(
        app.config['INSTANCE_FOLDER_PATH'], 'public.pem')
    # Check if the private and public keys already exist
    if os.path.exists(private_key_path) and os.path.exists(public_key_path):
        return load_existing_keys()
    return generate_keys()


def generate_keys():
    private_key_path = os.path.join(
        app.config['INSTANCE_FOLDER_PATH'], 'private.pem')
    public_key_path = os.path.join(
        app.config['INSTANCE_FOLDER_PATH'], 'public.pem')
    logger.debug("Keys do not exist. Generating keys...")
    # Generate a new EC private key
    private_key = ec.generate_private_key(ec.SECP256R1())

    # Serialize and save the private key
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(private_key_path, "wb") as private_file:
        private_file.write(private_pem)

    logger.debug(f"Private key saved to {private_key_path}")

    # Get the public key from the private key
    public_key = private_key.public_key()

    # Serialize and save the public key
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(public_key_path, "wb") as public_file:
        public_file.write(public_pem)

    logger.debug(f"Public key saved to {public_key_path}")
    return private_key, public_pem.decode("utf-8")


def load_existing_keys():
    private_key_path = os.path.join(
        app.config['INSTANCE_FOLDER_PATH'], 'private.pem')
    public_key_path = os.path.join(
        app.config['INSTANCE_FOLDER_PATH'], 'public.pem')
    logger.debug("Keys exist. Loading keys...")
    # Load the existing private key
    with open(private_key_path, "rb") as private_file:
        private_key = serialization.load_pem_private_key(
            private_file.read(), password=None)

    # Load the existing public key
    with open(public_key_path, "rb") as public_file:
        public_key = public_file.read().decode("utf-8")

    return private_key, public_key


def generate_did(public_key_pem):
    public_key_pem = public_key_pem.encode("utf-8")
    logger.info(f"Generating DID from public key {public_key_pem}")
    # Decode the PEM-encoded public key to extract the raw key material
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend

    # Load the public key from PEM
    public_key = serialization.load_pem_public_key(
        public_key_pem, backend=default_backend())

    # Get the raw public key bytes (in uncompressed form)
    raw_key_material = public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )

    # Prepend the multicodec prefix for P-256 keys (0x1200)
    multicodec_prefix = b'\x12\x00'
    multicodec_key = multicodec_prefix + raw_key_material

    # Encode the multicodec key in base58
    encoded_key = base58.b58encode(multicodec_key)

    # Construct the DID key
    did = f'did:key:z{encoded_key.decode()}'
    logger.info(f"Generated DID: {did}")
    return did


def generate_kid(did):
    # Append a fragment identifier to the DID
    kid = f"{did}#key-1"
    return kid
