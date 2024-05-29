import os

dependencies = [
    'pip install -q Flask==3.0.3',
    'pip install -q easyocr==1.7.1',
    'apt-get update --fix-missing && apt-get install -y --no-install-recommends cmake ghostscript git libegl-dev libffi-dev libfreetype6-dev libfribidi-dev libharfbuzz-dev libimagequant-dev libjpeg-turbo-progs libjpeg8-dev liblcms2-dev libopengl-dev libopenjp2-7-dev libssl-dev libtiff5-dev libwebp-dev libxcb-cursor0 libxcb-icccm4 libxcb-image0 libxcb-keysyms1 libxcb-randr0 libxcb-render-util0 libxkbcommon-x11-0 meson netpbm python3-dev python3-numpy python3-setuptools python3-tk sudo tcl8.6-dev tk8.6-dev virtualenv wget xvfb zlib1g-dev # required by Pillow',
    'pip install -q pillow==9.1.1',
    'pip install -q requests==2.31.0',
    'pip install -q torch==2.3.0'
]

for command in dependencies:
    os.system(command)

import io, json, base64, requests, subprocess, torch
from flask import Flask, jsonify, request
from PIL import Image, ImageDraw
import easyocr

config_str = '''{
    "device_map": {
        "cuda:0": "10GiB",
        "cpu": "30GiB"
    },
    "required_python_version": "cp311",
    "functions": [
        {
            "name": "perform_ocr",
            "display_name": "Perform OCR",
            "description": "This function performs OCR on the given image using specified language.",
            "parameters": {
                "type": "object",
                "properties": {
                    "image_url": { "type": "string", "description": "The URL of the image for OCR" },
                    "language": { "type": "array", "items": {"type": "string"},"description": "List of languages to use for OCR" }
                },
                "required": ["image_url", "language"]
            },
            "input_type": "application/json",
            "return_type": "application/json"
        }
    ]
}'''

config = json.loads(config_str)
app = Flask(__name__)

def select_device_with_larger_free_memory(available_devices):
    device = None
    memory = 0

    for available_device in available_devices:
        id = available_device.split(":")
        id = id[-1]
        free_memory = int(subprocess.check_output(f"nvidia-smi --query-gpu=memory.free --format=csv,nounits,noheader --id={id}", shell=True).decode('utf-8').strip())
        if free_memory > memory:
            memory = free_memory
            device = available_device

    return device if device else "cpu"

def select_device():
    if not torch.cuda.is_available():
        return "cpu"

    device_map = config.get('device_map', {})
    available_devices = list(device_map.keys())
    return select_device_with_larger_free_memory(available_devices)

device = select_device()

@app.route("/v1/setup", methods=["POST"])
def setup():
    response = {"setup": "Performed"}
    return jsonify(response), 201

@app.route("/v1/perform_ocr", methods=["POST"])
def perform_ocr():
    data = request.json
    image_url = data.get("image_url")
    languages = data.get("language")

    if not image_url or not isinstance(image_url, str):
        return jsonify({"error": "Invalid or missing 'image_url'."}), 400

    if not languages or not isinstance(languages, list) or not all(isinstance(lang, str) for lang in languages):
        return jsonify({"error": "Invalid or missing 'language'."}), 400

    response = requests.get(image_url)
    if response.status_code != 200:
        return jsonify({"error": "Unable to fetch the image from URL."}), 400

    image_data = response.content
    image = Image.open(io.BytesIO(image_data))
    image_path = "/tmp/image.png"
    image.save(image_path)

    reader = easyocr.Reader(languages, gpu=(device != "cpu"))
    results = reader.readtext(image_path)

    extracted_text = " ".join([result[1] for result in results])

    response = {
        "response": extracted_text
    }
    return jsonify(response), 201

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, threaded=True)
