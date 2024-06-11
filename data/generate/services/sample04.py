import os

dependencies = [
    "pip install -q Flask==3.0.3",
    "apt-get update --fix-missing && apt-get install -y --no-install-recommends cmake ghostscript git libegl-dev libffi-dev libfreetype6-dev libfribidi-dev libharfbuzz-dev libimagequant-dev libjpeg-turbo-progs libjpeg8-dev liblcms2-dev libopengl-dev libopenjp2-7-dev libssl-dev libtiff5-dev libwebp-dev libxcb-cursor0 libxcb-icccm4 libxcb-image0 libxcb-keysyms1 libxcb-randr0 libxcb-render-util0 libxkbcommon-x11-0 meson netpbm python3-dev python3-numpy python3-setuptools python3-tk sudo tcl8.6-dev tk8.6-dev virtualenv wget xvfb zlib1g-dev # required by Pillow",
    "pip install -q Pillow==10.3.0"
]

for command in dependencies:
    os.system(command)

import json
import base64
import io
from flask import Flask, jsonify, request, send_file
from PIL import Image, ImageDraw, ImageFont

config_str = '''{
    "device_map": {
        "cuda:0": "10GiB",
        "cpu": "30GiB"
    },
    "required_python_version": "cp312",
    "functions": [
        {
            "name": "generate_image",
            "display_name": "Generate Image",
            "description": "This function generates an image with a given background color and resolution.",
            "parameters": {
                "type": "object",
                "properties": {
                    "color": { "type": "string", "description": "The background color of the image" },
                    "width": { "type": "number", "description": "The width of the image" },
                    "height": { "type": "number", "description": "The height of the image" }
                },
                "required": ["color", "width", "height"]
            },
            "input_type": "application/json",
            "return_type": "application/json"
        },
        {
            "name": "generate_image_with_text",
            "display_name": "Generate Image with Text",
            "description": "This function generates an image with a given background color, resolution and text.",
            "parameters": {
                "type": "object",
                "properties": {
                    "color": { "type": "string", "description": "The background color of the image" },
                    "width": { "type": "number", "description": "The width of the image" },
                    "height": { "type": "number", "description": "The height of the image" },
                    "text": { "type": "string", "description": "The text to place on the image" }
                },
                "required": ["color", "width", "height", "text"]
            },
            "input_type": "application/json",
            "return_type": "application/json"
        }
    ]
}'''

config = json.loads(config_str)
app = Flask(__name__)

@app.route('/v1/setup', methods=['POST'])
def setup():
    response = {
        "setup": "Performed"
    }
    return jsonify(response), 201

@app.route('/v1/generate_image', methods=['POST'])
def generate_image():
    data = request.json
    color = data.get("color", None)
    width = data.get("width", None)
    height = data.get("height", None)

    if not color or not width or not height or width <= 0 or height <= 0:
        return jsonify({"error": "Invalid input. 'color' must be a string, 'width' and 'height' must be positive numbers."}), 400

    image = Image.new('RGB', (width, height), color)
    img_io = io.BytesIO()
    image.save(img_io, 'PNG')
    img_io.seek(0)
    encoded_content = base64.b64encode(img_io.read()).decode('utf-8')

    response = {
        "file_attachments": [
            {
                "content": encoded_content,
                "file_name": "generated_image.png",
                "media_type": "image/png"
            }
        ]
    }
    return jsonify(response), 201

@app.route('/v1/generate_image_with_text', methods=['POST'])
def generate_image_with_text():
    data = request.json
    color = data.get("color", None)
    width = data.get("width", None)
    height = data.get("height", None)
    text = data.get("text", None)

    if not color or not width or not height or not text or width <= 0 or height <= 0:
        return jsonify({"error": "Invalid input. 'color' and 'text' must be strings, 'width' and 'height' must be positive numbers."}), 400

    image = Image.new('RGB', (width, height), color)
    draw = ImageDraw.Draw(image)
    font = ImageFont.load_default()
    text_position = (width // 2, height // 2)
    draw.text(text_position, text, fill="black", font=font, anchor='mm')

    img_io = io.BytesIO()
    image.save(img_io, 'PNG')
    img_io.seek(0)
    encoded_content = base64.b64encode(img_io.read()).decode('utf-8')

    response = {
        "file_attachments": [
            {
                "content": encoded_content,
                "file_name": "generated_image_with_text.png",
                "media_type": "image/png"
            }
        ]
    }
    return jsonify(response), 201

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, threaded=True)
