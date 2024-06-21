import os

dependencies = [
    "pip install -q Flask==3.0.3",
    "pip install -q requests==2.32.3",
    "apt-get update --fix-missing && apt-get install -y --no-install-recommends pandoc"
]

for command in dependencies:
    os.system(command)

import json
import subprocess
import base64
import requests
from flask import Flask, jsonify, request

config_str = '''{
    "device_map": {
        "cuda:0": "10GiB",
        "cpu": "30GiB"
    },
    "required_python_version": "cp312",
    "functions": [
        {
            "name": "convert_to_markdown",
            "display_name": "Convert Document to Markdown",
            "description": "This function converts a document from a given URL into Markdown format.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": { "type": "string", "description": "The URL of the document to convert" }
                },
                "required": ["url"]
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
    response = {"setup": "Performed"}
    return jsonify(response), 201

@app.route('/v1/convert_to_markdown', methods=['POST'])
def convert_to_markdown():
    data = request.json
    doc_url = data.get("url", None)

    if doc_url is None or not isinstance(doc_url, str) or not doc_url.strip():
        return jsonify({"error": "Please provide a valid URL."}), 400

    try:
        response = requests.get(doc_url)
        response.raise_for_status()
    except requests.RequestException as e:
        return jsonify({"error": f"Failed to fetch document: {str(e)}"}), 400

    temp_input_path = f"/tmp/document_{os.urandom(8).hex()}"
    output_file_path = f"{temp_input_path}.md"
    temp_input_path += os.path.splitext(doc_url)[1]  # Use the same extension as the original document

    with open(temp_input_path, 'wb') as f:
        f.write(response.content)

    try:
        subprocess.run(['pandoc', temp_input_path, '-o', output_file_path], check=True)
        with open(output_file_path, 'r') as f:
            markdown_content = f.read()
        os.remove(temp_input_path)
        os.remove(output_file_path)
    except subprocess.CalledProcessError as e:
        return jsonify({"error": f"Conversion failed: {str(e)}"}), 500

    response_json = {
        "response": markdown_content
    }
    return jsonify(response_json), 201

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, threaded=True)
