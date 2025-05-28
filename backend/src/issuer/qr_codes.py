import segno
import io
import base64
import hashlib
import logging
from functools import lru_cache

logger = logging.getLogger(__name__)


def generate_qr_code_cached(data):
    """Generate QR code with optimized settings"""
    try:
        # Input validation
        if not data or not isinstance(data, str):
            raise ValueError("QR code data must be a non-empty string")
        if len(data) > 4000:
            raise ValueError(f"QR code data too long ({len(data)} characters)")
        
        # Generate QR code
        qr = segno.make(data, error='M')  # Medium error correction
        
        # Generate PNG
        buf = io.BytesIO()
        qr.save(
            buf, 
            scale=8,
            kind="png", 
            border=4,
            dark='#000000', 
            light='#FFFFFF'
        )
        
        buf.seek(0)
        png_data = buf.getvalue()
        
        if not png_data:
            raise ValueError("QR code generation produced empty data")
        
        # Encode to base64
        img_data = base64.b64encode(png_data).decode('utf-8')
        
        if not img_data:
            raise ValueError("Base64 encoding failed")
        
        return img_data
        
    except Exception as e:
        logger.error(f"QR code generation failed: {str(e)}")
        raise ValueError(f"QR code generation error: {str(e)}") from e


@lru_cache(maxsize=50)  # Optimized cache size for credential issuance
def generate_qr_code_with_cache(data_hash, data):
    """Generate QR code with optimized caching"""
    return generate_qr_code_cached(data)


def generate_qr_code(data):
    """Generate QR code with simple error handling"""
    if not data:
        raise ValueError("Cannot generate QR code: data is empty")
    
    try:
        result = generate_qr_code_cached(data)
        logger.info(f"QR code generated successfully - data length: {len(data)}")
        return result
        
    except Exception as e:
        logger.error(f"QR generation failed: {str(e)}")
        clear_qr_cache()
        raise ValueError(f"QR code generation failed: {str(e)}") from e


def clear_qr_cache():
    """Clear the QR code cache"""
    generate_qr_code_with_cache.cache_clear()
    logger.info("QR code cache cleared")
