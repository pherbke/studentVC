import os
import base64
from io import BytesIO
from PIL import Image
from functools import lru_cache


def preprocess_image(path, resolution, keep_aspect_ratio=False):
    """Fast image preprocessing with optimization and robust error handling"""
    try:
        # Handle both file paths and FileStorage objects
        if hasattr(path, 'read'):
            # It's a FileStorage object
            img = Image.open(path)
        else:
            # It's a file path
            img = Image.open(path)

        # Convert to RGB if needed
        if img.mode != "RGB":
            img = img.convert("RGB")

        # Validate image size (prevent DoS attacks)
        max_pixels = 50 * 1024 * 1024  # 50MP max
        if img.size[0] * img.size[1] > max_pixels:
            raise ValueError("Image too large")

        # Resize image
        if keep_aspect_ratio:
            original_width, original_height = img.size
            max_height = resolution[1]
            scale_factor = max_height / original_height
            new_width = int(original_width * scale_factor)
            img = img.resize((new_width, max_height), Image.LANCZOS)
        else:
            img = img.resize(resolution, Image.LANCZOS)

        # Encode as base64 JPEG with optimized quality
        buffered = BytesIO()
        img.save(buffered, format="JPEG", quality=85, optimize=True)
        img_data = base64.b64encode(buffered.getvalue()).decode("utf-8")
        
        # Validate the encoded data
        if not img_data or len(img_data) == 0:
            raise ValueError("Image encoding failed")
        
        return img_data

    except Exception as e:
        raise ValueError(f"Image processing failed: {str(e)}") from e


@lru_cache(maxsize=4)
def get_placeholders():
    """Cached placeholder generation for performance"""
    placeholder_path = os.path.join(os.path.dirname(__file__), "..", "static")
    logo_path = os.path.join(placeholder_path, "logo.png")
    profile_path = os.path.join(placeholder_path, "profile.jpg")

    # Only process if files exist
    if not os.path.exists(logo_path) or not os.path.exists(profile_path):
        return "", ""

    logo = preprocess_image(logo_path, (762, 152), keep_aspect_ratio=True)
    profile = preprocess_image(profile_path, (561, 722))

    return logo, profile


if __name__ == "__main__":
    print(get_placeholders())
