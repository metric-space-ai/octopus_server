import os

dependencies = [
    "pip install -q Flask==3.1.0",
    "pip install -q lorem_text==2.1",
]

for command in dependencies:
    os.system(command)

import json
import base64
import io
from flask import Flask, jsonify, request, send_file
from lorem_text import lorem

config_str = '''{
    "device_map": {
        "cuda:0": "10GiB",
        "cpu": "30GiB"
    },
    "required_python_version": "cp312",
    "functions": [
        {
            "name": "generate_lorem_text",
            "display_name": "Generate Lorem Ipsum Text",
            "description": "This function generates a lorem ipsum string of a given length and returns it as a text.",
            "parameters": {
                "type": "object",
                "properties": {
                    "length": { "type": "integer", "description": "The length of the lorem ipsum text to generate" }
                },
                "required": ["length"]
            },
            "input_type": "application/json",
            "return_type": "application/json"
        },
        {
            "name": "generate_lorem_file",
            "display_name": "Generate Lorem Ipsum File",
            "description": "This function generates a lorem ipsum string of a given length and returns it as a file.",
            "parameters": {
                "type": "object",
                "properties": {
                    "length": { "type": "integer", "description": "The length of the lorem ipsum text to generate" }
                },
                "required": ["length"]
            },
            "input_type": "application/json",
            "return_type": "application/json"
        }
    ]
}'''

config = json.loads(config_str)
app = Flask(__name__)

def generate_lorem_ipsum(length):
    return lorem.words(length)

@app.route('/v1/generate_lorem_text', methods=['POST'])
def generate_lorem_text():
    data = request.json
    length = data.get("length", None)

    if length is None or not isinstance(length, int) or length <= 0:
        return jsonify({"error": "Invalid input. It must be a positive integer."}), 400

    lorem_text = generate_lorem_ipsum(length)
    response = {
        "response": lorem_text,
    }
    return jsonify(response), 201

@app.route('/v1/generate_lorem_file', methods=['POST'])
def generate_lorem_file():
    data = request.json
    length = data.get("length", None)

    if length is None or not isinstance(length, int) or length <= 0:
        return jsonify({"error": "Invalid input. It must be a positive integer."}), 400

    lorem_text = generate_lorem_ipsum(length)
    buffer = io.BytesIO()
    buffer.write(lorem_text.encode())
    buffer.seek(0)
    encoded_content = base64.b64encode(buffer.read()).decode('utf-8')

    response = {
        "file_attachments": [
            {
                "content": encoded_content,
                "file_name": "lorem_ipsum.txt",
                "media_type": "text/plain"
            }
        ]
    }
    return jsonify(response), 201

@app.route("/v1/setup", methods=["POST"])
def setup():
    response = {
        "setup": "Performed"
    }
    return jsonify(response), 201

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, threaded=True)
