import os
import base64
from io import BytesIO
from PIL import Image


def preprocess_image(path, resolution, keep_aspect_ratio=False):
    img = Image.open(path)

    if img.mode != "RGB":
        img = img.convert("RGB")

    if keep_aspect_ratio:
        original_width, original_height = img.size
        max_height = resolution[1]
        scale_factor = max_height / original_height
        new_width = int(original_width * scale_factor)
        img = img.resize((new_width, max_height))
    else:
        img = img.resize(resolution)

    # base 64 encode the image as jpg
    buffered = BytesIO()
    img.save(buffered, format="JPEG")
    img = base64.b64encode(buffered.getvalue()).decode("utf-8")

    return img


def get_placeholders():
    placeholder_path = os.path.join(os.path.dirname(__file__), "..", "static")
    logo_path = os.path.join(placeholder_path, "logo.png")
    profile_path = os.path.join(placeholder_path, "profile.jpg")

    logo = preprocess_image(logo_path, (762, 152), keep_aspect_ratio=True)
    profile = preprocess_image(profile_path, (561, 722))

    return logo, profile


if __name__ == "__main__":
    print(get_placeholders())
