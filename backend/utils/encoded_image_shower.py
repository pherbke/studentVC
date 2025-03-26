import os
import base64
from io import BytesIO
from PIL import Image


img = ""


def show_encoded_image(img_data):
    img_bytes = base64.b64decode(img_data)
    img = Image.open(BytesIO(img_bytes))
    img.show()

    return img


if __name__ == "__main__":
    show_encoded_image(img)
