import os
import base64
from io import BytesIO
from PIL import Image
from functools import lru_cache


def preprocess_image(path, resolution, keep_aspect_ratio=False):
    """Fast image preprocessing with optimization"""
    img = Image.open(path)

    if img.mode != "RGB":
        img = img.convert("RGB")

    if keep_aspect_ratio:
        original_width, original_height = img.size
        max_height = resolution[1]
        scale_factor = max_height / original_height
        new_width = int(original_width * scale_factor)
        img = img.resize((new_width, max_height), Image.LANCZOS)
    else:
        img = img.resize(resolution, Image.LANCZOS)

    # base 64 encode the image as jpg with optimized quality
    buffered = BytesIO()
    img.save(buffered, format="JPEG", quality=85, optimize=True)
    img = base64.b64encode(buffered.getvalue()).decode("utf-8")

    return img


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
