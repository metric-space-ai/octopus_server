import os

dependencies = [
    "pip install -q Flask==3.0.3",
    "pip install -q requests==2.32.3",
    "pip install -q ollama==0.2.1",
    "pip install -q python-dotenv==1.0.1"
]

for command in dependencies:
    os.system(command)

import json
import requests
from flask import Flask, jsonify, request
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
        { "name": "ollama:llama3:8b" },
        { "name": "ollama:qwen2:7b" }
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

@app.route('/v1/ask_ollama', methods=['POST'])
def ask_ollama():
    data = request.json
    model = data.get('model')
    prompt = data.get('prompt')

    if not model or not prompt:
        return jsonify({'error': 'Model and prompt are required.'}), 400

    messages = [
        {
            'role': 'user',
            'content': prompt,
        },
    ]

    try:
        response = chat(model, messages=messages)
        answer = response['message']['content']
        return jsonify({"response": answer}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route("/v1/setup", methods=["POST"])
def setup():
    response = {"setup": "Performed"}
    return jsonify(response), 201

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, threaded=True)
