import os

dependencies = [
    "pip install -q Flask==3.1.0",
    "pip install -q requests==2.32.3",
    "pip install -q ollama==0.4.7",
    "pip install -q python-dotenv==1.0.1"
]

for command in dependencies:
    os.system(command)

import json
import time
import threading
import queue
from flask import Flask, request, jsonify
from dotenv import load_dotenv
from ollama import chat

load_dotenv()

config_str = '''{
    "device_map": {
        "cuda:0": "10GiB",
        "cpu": "30GiB"
    },
    "required_python_version": "cp312",
    "models": [
        { "name": "ollama:llama3.1:8b" },
        { "name": "ollama:qwen2.5:7b" }
    ],
    "functions": [
        {
            "name": "ask_ollama",
            "display_name": "Ask Ollama Model",
            "description": "Send a prompt to desired Ollama model.",
            "parameters": {
                "type": "object",
                "properties": {
                    "model": { "type": "string", "description": "Name of the Ollama model" },
                    "prompt": { "type": "string", "description": "Prompt or question to send" }
                },
                "required": ["model", "prompt"]
            },
            "input_type": "application/json",
            "return_type": "application/json"
        }
    ]
}'''

config = json.loads(config_str)
app = Flask(__name__)

OLLAMA_HOST = os.getenv('OLLAMA_HOST')

def get_ollama_response(model, prompt):
    response_queue = queue.Queue()

    def process_chat():
        messages = [{'role': 'user', 'content': prompt}]
        try:
            for part in chat(model, messages=messages, stream=True):
                token = part['message']['content']
                response_queue.put(token)
        finally:
            response_queue.put(None)  # Sentinel to mark the end of the stream

    thread = threading.Thread(target=process_chat)
    thread.start()

    return response_queue

@app.route('/v1/ask_ollama', methods=['POST'])
def ask_ollama():
    data = request.json
    model = data.get("model")
    prompt = data.get("prompt")

    if not model or not prompt:
        return jsonify({'error': 'Parameters "model" and "prompt" are required'}), 400

    response_queue = get_ollama_response(model, prompt)
    timeout = 10  # 10 seconds timeout
    end_time = time.time() + timeout

    response_text = ""
    while time.time() < end_time:
        try:
            token = response_queue.get(timeout=0.1)
            if token is None:
                break
            response_text += token
        except queue.Empty:
            continue

    return jsonify({"response": response_text}), 201

@app.route("/v1/setup", methods=["POST"])
def setup():
    response = {"setup": "Performed"}
    return jsonify(response), 201

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, threaded=True)
