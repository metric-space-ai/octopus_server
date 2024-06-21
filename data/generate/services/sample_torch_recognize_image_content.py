import os

dependencies = [
    "pip install -q flash-attn==2.5.8",
    "pip install -q Flask==3.0.3",
    "pip install -q torch==2.3.1",
    "pip install -q torchvision==0.18.1",
    "pip install -q accelerate==0.31.0",
    "pip install -q transformers==4.41.2",
    "apt-get update --fix-missing && apt-get install -y --no-install-recommends cmake ghostscript git libegl-dev libffi-dev libfreetype6-dev libfribidi-dev libharfbuzz-dev libimagequant-dev libjpeg-turbo-progs libjpeg8-dev liblcms2-dev libopengl-dev libopenjp2-7-dev libssl-dev libtiff5-dev libwebp-dev libxcb-cursor0 libxcb-icccm4 libxcb-image0 libxcb-keysyms1 libxcb-randr0 libxcb-render-util0 libxkbcommon-x11-0 meson netpbm python3-dev python3-numpy python3-setuptools python3-tk sudo tcl8.6-dev tk8.6-dev virtualenv wget xvfb zlib1g-dev # required by Pillow",
    "pip install -q Pillow==10.3.0",
    "pip install -q requests==2.32.3"
]

for command in dependencies:
    os.system(command)

import json
import base64
import subprocess
import time
from flask import Flask, jsonify, request
from PIL import Image
from io import BytesIO
import requests
import torch
from transformers import AutoModelForCausalLM, AutoProcessor, TextIteratorStreamer
from threading import Thread

config_str = '''{
    "device_map": {
        "cuda:0": "16GiB",
        "cuda:1": "16GiB",
        "cpu": "32GiB"
    },
    "required_python_version": "cp312",
    "models": {
        "model": "microsoft/Phi-3-vision-128k-instruct"
    },
    "functions": [
        {
            "name": "recognize_image_content",
            "display_name": "Recognize Image Content",
            "description": "Recognize the content of the images provided by a URL and give user answers about the content.",
            "parameters": {
                "type": "object",
                "properties": {
                    "image_url": { "type": "string", "description": "URL of the image to process" },
                    "question": { "type": "string", "description": "The question about the image content" }
                },
                "required": ["image_url", "question"]
            },
            "input_type": "application/json",
            "return_type": "application/json"
        }
    ]
}'''

config = json.loads(config_str)
app = Flask(__name__)

def command_result_as_int(command):
    return int(subprocess.check_output(command, shell=True).decode('utf-8').strip())

def select_device_with_larger_free_memory(available_devices):
    device = None
    memory = 0

    for available_device in available_devices:
        id = available_device.split(":")
        id = id[-1]
        free_memory = command_result_as_int(f"nvidia-smi --query-gpu=memory.free --format=csv,nounits,noheader --id={id}")
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

model = None
processor = None

@app.route("/v1/setup", methods=["POST"])
def setup():
    global model, processor
    model_id = config["models"]["model"]
    model = AutoModelForCausalLM.from_pretrained(model_id, trust_remote_code=True, torch_dtype="auto")
    processor = AutoProcessor.from_pretrained(model_id, trust_remote_code=True)
    model.to(device)
    response = {"setup": "Performed"}
    return jsonify(response), 201

@app.route('/v1/recognize_image_content', methods=['POST'])
def recognize_image_content():
    data = request.json
    image_url = data.get('image_url')
    question = data.get('question')

    if not image_url or not isinstance(image_url, str) or not image_url.strip():
        return jsonify({ "error": "Invalid image URL." }), 400
    if not question or not isinstance(question, str) or not question.strip():
        return jsonify({ "error": "Invalid question." }), 400

    response = requests.get(image_url)
    if response.status_code != 200:
        return jsonify({"error": "Unable to fetch the image from URL."}), 400

    image = Image.open(BytesIO(response.content))
    prompt = processor.tokenizer.apply_chat_template([{"role": "user", "content": f"<|image_1|>\n{question}"}], tokenize=False, add_generation_prompt=True)
    inputs = processor(prompt, image, return_tensors="pt").to(device)

    streamer = TextIteratorStreamer(processor, skip_special_tokens=True, skip_prompt=True, clean_up_tokenization_spaces=False)
    generation_kwargs = dict(inputs, streamer=streamer, max_new_tokens=1024, do_sample=False, temperature=0.0, eos_token_id=processor.tokenizer.eos_token_id)

    thread = Thread(target=model.generate, kwargs=generation_kwargs)
    thread.start()

    buffer = ""
    for new_text in streamer:
        buffer += new_text

    response = {
        "response": buffer
    }
    return jsonify(response), 201

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, threaded=True)
