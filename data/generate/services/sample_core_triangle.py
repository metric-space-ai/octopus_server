import os

dependencies = [
    "pip install -q Flask==3.1.0"
]

for command in dependencies:
    os.system(command)

import json
import math
import io
import base64
from flask import Flask, jsonify, request

config_str = '''{
    "device_map": {
        "cuda:0": "10GiB",
        "cpu": "30GiB"
    },
    "required_python_version": "cp312",
    "functions": [
        {
            "name": "calculate_triangle_area",
            "display_name": "Calculate Triangle Area",
            "description": "This function calculates the area of a triangle given its three side lengths.",
            "parameters": {
                "type": "object",
                "properties": {
                    "side1": { "type": "number", "description": "The length of the first side of the triangle" },
                    "side2": { "type": "number", "description": "The length of the second side of the triangle" },
                    "side3": { "type": "number", "description": "The length of the third side of the triangle" }
                },
                "required": ["side1", "side2", "side3"]
            },
            "input_type": "application/json",
            "return_type": "application/json"
        },
        {
            "name": "calculate_triangle_perimeter",
            "display_name": "Calculate Triangle Perimeter",
            "description": "This function calculates the perimeter of a triangle given its three side lengths.",
            "parameters": {
                "type": "object",
                "properties": {
                    "side1": { "type": "number", "description": "The length of the first side of the triangle" },
                    "side2": { "type": "number", "description": "The length of the second side of the triangle" },
                    "side3": { "type": "number", "description": "The length of the third side of the triangle" }
                },
                "required": ["side1", "side2", "side3"]
            },
            "input_type": "application/json",
            "return_type": "application/json"
        }
    ]
}'''

config = json.loads(config_str)
app = Flask(__name__)

def calculate_triangle_area(side1, side2, side3):
    s = (side1 + side2 + side3) / 2
    return math.sqrt(s * (s - side1) * (s - side2) * (s - side3))

def calculate_triangle_perimeter(side1, side2, side3):
    return side1 + side2 + side3

@app.route('/v1/calculate_triangle_area', methods=['POST'])
def calculate_triangle_area_endpoint():
    data = request.json
    side1 = data.get("side1")
    side2 = data.get("side2")
    side3 = data.get("side3")

    if not all(isinstance(x, (int, float)) and x > 0 for x in [side1, side2, side3]):
        return jsonify({"error": "Invalid input. All sides must be positive numbers."}), 400

    area = calculate_triangle_area(side1, side2, side3)
    result_text = f"The area of the triangle is {area:.2f}."
    
    buffer = io.BytesIO()
    buffer.write(result_text.encode())
    buffer.seek(0)
    encoded_content = base64.b64encode(buffer.read()).decode('utf-8')
    
    response = {
        "response": result_text,
        "file_attachments": [
            {
                "content": encoded_content,
                "file_name": "triangle_area.txt",
                "media_type": "text/plain"
            }
        ]
    }
    return jsonify(response), 201

@app.route('/v1/calculate_triangle_perimeter', methods=['POST'])
def calculate_triangle_perimeter_endpoint():
    data = request.json
    side1 = data.get("side1")
    side2 = data.get("side2")
    side3 = data.get("side3")

    if not all(isinstance(x, (int, float)) and x > 0 for x in [side1, side2, side3]):
        return jsonify({"error": "Invalid input. All sides must be positive numbers."}), 400

    perimeter = calculate_triangle_perimeter(side1, side2, side3)
    result_text = f"The perimeter of the triangle is {perimeter:.2f}."

    buffer = io.BytesIO()
    buffer.write(result_text.encode())
    buffer.seek(0)
    encoded_content = base64.b64encode(buffer.read()).decode('utf-8')

    response = {
        "response": result_text,
        "file_attachments": [
            {
                "content": encoded_content,
                "file_name": "triangle_perimeter.txt",
                "media_type": "text/plain"
            }
        ]
    }
    return jsonify(response), 201

@app.route("/v1/setup", methods=["POST"])
def setup():
    response = {"setup": "Performed"}
    return jsonify(response), 201

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, threaded=True)
