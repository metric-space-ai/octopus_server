import os

dependencies = [
    "pip install -q Flask==3.1.0",
    "pip install -q requests==2.32.3",
    "pip install -q marker-pdf==1.3.4"
]

for command in dependencies:
    os.system(command)

import json
import requests
from flask import Flask, request, jsonify
from marker.converters.pdf import PdfConverter
from marker.models import create_model_dict
from marker.config.parser import ConfigParser
from marker.renderers.markdown import MarkdownOutput
from marker.logger import configure_logging

app = Flask(__name__)
configure_logging()

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

    config = {
        "output_format": "markdown"
    }

    config_parser = ConfigParser(config)
    converter = PdfConverter(
        config=config_parser.generate_config_dict(),
        artifact_dict=create_model_dict(),
        processor_list=config_parser.get_processors(),
        renderer=config_parser.get_renderer()
    )

    try:
        markdown_output: MarkdownOutput = converter(temp_pdf_path)
        markdown = markdown_output.markdown
        markdown_content = markdown
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    response = {
        "response": markdown_content
    }
    return jsonify(response), 201

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, threaded=True)
