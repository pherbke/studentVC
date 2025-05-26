import segno
import io
import base64
import hashlib
from functools import lru_cache


@lru_cache(maxsize=128)
def generate_qr_code_cached(data_hash, data):
    """Generate QR code with caching for performance"""
    qr = segno.make(data, error='m')  # Use medium error correction for better performance
    buf = io.BytesIO()
    qr.save(buf, scale=8, kind="png", border=2)  # Reduced scale for faster generation
    buf.seek(0)
    val = buf.getvalue()
    img_data = base64.b64encode(val).decode('utf-8')
    return img_data


def generate_qr_code(data):
    """Generate QR code with optimized performance"""
    # Create a hash of the data for caching
    data_hash = hashlib.md5(data.encode('utf-8')).hexdigest()
    return generate_qr_code_cached(data_hash, data)
