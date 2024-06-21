import os

dependencies = [
    "pip install -q Flask==3.0.3",
    "pip install -q requests==2.32.3",
    "pip install -q marker-pdf==0.2.14"
]

for command in dependencies:
    os.system(command)

import json
import requests
from flask import Flask, request, jsonify
from marker.convert import convert_single_pdf
from marker.logger import configure_logging
from marker.models import load_all_models

app = Flask(__name__)
configure_logging()
model_lst = load_all_models()

config_str = '''{
    "device_map": {
        "cuda:0": "10GiB",
        "cpu": "30GiB"
    },
    "required_python_version": "cp312",
    "functions": [
        {
            "name": "convert_pdf_to_md",
            "display_name": "Convert PDF to Markdown",
            "description": "This function converts a PDF from a given URL into Markdown format.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": { "type": "string", "description": "URL of the PDF to convert" }
                },
                "required": ["url"]
            },
            "input_type": "application/json",
            "return_type": "application/json"
        }
    ]
}'''

config = json.loads(config_str)

@app.route('/v1/setup', methods=['POST'])
def setup():
    response = {"setup": "Performed"}
    return jsonify(response), 201

@app.route('/v1/convert_pdf_to_md', methods=['POST'])
def convert_pdf_to_md():
    data = request.json
    pdf_url = data.get("url")

    if not pdf_url or not isinstance(pdf_url, str):
        return jsonify({"error": "Invalid URL."}), 400

    try:
        response = requests.get(pdf_url)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        return jsonify({"error": str(e)}), 500

    temp_pdf_path = f"/tmp/temp_{os.urandom(8).hex()}.pdf"
    with open(temp_pdf_path, 'wb') as temp_pdf:
        temp_pdf.write(response.content)

    try:
        full_text, images, out_meta = convert_single_pdf(temp_pdf_path, model_lst)
        markdown_content = full_text
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    response = {
        "response": markdown_content
    }
    return jsonify(response), 201

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, threaded=True)
