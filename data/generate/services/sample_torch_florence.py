import os

dependencies = [
    "pip install -q einops==0.8.0",
    "pip install -q flash-attn==2.7.3",
    "pip install -q timm==1.0.14",
    "pip install -q Flask==3.1.0",
    "pip install -q torch==2.6.0",
    "pip install -q transformers==4.48.2",
    "pip install -q requests==2.32.3",
    "pip install -q Pillow==11.1.0"
]

for command in dependencies:
    os.system(command)

import json
import requests
from flask import Flask, jsonify, request
from PIL import Image
import torch
import subprocess
from transformers import AutoProcessor, AutoModelForCausalLM

config_str = '''{
    "device_map": {
        "cuda:0": "16GiB",
        "cpu": "32GiB"
    },
    "required_python_version": "cp312",
    "models": {
        "model": "microsoft/Florence-2-large-ft"
    },
    "functions": [
        {
            "name": "generate_image_response",
            "display_name": "Generate Image Response",
            "description": "This function generates a response for a given image URL and prompt using Florence-2 model.",
            "parameters": {
                "type": "object",
                "properties": {
                    "image_url": { "type": "string", "description": "URL of the image" },
                    "prompt": { "type": "string", "description": "Prompt to specify the task" }
                },
                "required": ["image_url", "prompt"]
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

@app.route("/v1/setup", methods=["POST"])
def setup():
    global model, processor
    model_id = config["models"]["model"]
    model = AutoModelForCausalLM.from_pretrained(model_id, trust_remote_code=True)
    processor = AutoProcessor.from_pretrained(model_id, trust_remote_code=True)
    model.to(device)
    response = {"setup": "Performed"}
    return jsonify(response), 201

@app.route('/v1/generate_image_response', methods=['POST'])
def generate_image_response():
    data = request.json
    image_url = data.get("image_url", None)
    prompt = data.get("prompt", None)

    if not image_url or not isinstance(image_url, str) or not image_url.strip():
        return jsonify({"error": "Please provide a valid image URL."}), 400
    if not prompt or not isinstance(prompt, str) or not prompt.strip():
        return jsonify({"error": "Please provide a valid prompt."}), 400

    response = requests.get(image_url)
    if response.status_code != 200:
        return jsonify({"error": "Unable to fetch the image from URL."}), 400

    image = Image.open(requests.get(image_url, stream=True).raw)
    inputs = processor(text=prompt, images=image, return_tensors="pt").to(device)
    generated_ids = model.generate(
        input_ids=inputs["input_ids"],
        pixel_values=inputs["pixel_values"],
        max_new_tokens=1024,
        do_sample=False,
        num_beams=3
    )
    generated_text = processor.batch_decode(generated_ids, skip_special_tokens=False)[0]
    parsed_answer = processor.post_process_generation(generated_text, task=prompt, image_size=(image.width, image.height))

    response = {"response": str(parsed_answer)}
    return jsonify(response), 201

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, threaded=True)
