import os

dependencies = [
    "pip install -q Flask==3.1.0",
]

for command in dependencies:
    os.system(command)

import json
from flask import Flask, jsonify, request

config_str = '''{
    "device_map": {
        "cuda:0": "10GiB",
        "cpu": "30GiB"
    },
    "required_python_version": "cp312",
    "functions": [
        {
            "name": "calculate_area",
            "display_name": "Calculate Area of Circle",
            "description": "This function calculates the area of a circle for a given radius.",
            "parameters": {
                "type": "object",
                "properties": {
                    "radius": { "type": "number", "description": "The radius of the circle" }
                },
                "required": ["radius"]
            },
            "input_type": "application/json",
            "return_type": "application/json"
        },
        {
            "name": "calculate_perimeter",
            "display_name": "Calculate Perimeter of Circle",
            "description": "This function calculates the perimeter of a circle for a given radius.",
            "parameters": {
                "type": "object",
                "properties": {
                    "radius": { "type": "number", "description": "The radius of the circle" }
                },
                "required": ["radius"]
            },
            "input_type": "application/json",
            "return_type": "application/json"
        }
    ]
}'''

config = json.loads(config_str)
app = Flask(__name__)

def calculate_area(radius):
    return 3.14159 * radius ** 2

def calculate_perimeter(radius):
    return 2 * 3.14159 * radius

@app.route('/v1/calculate_area', methods=['POST'])
def calculate_area_endpoint():
    data = request.json
    radius = data.get("radius", None)

    if radius is None or not isinstance(radius, (int, float)) or radius < 0:
        return jsonify({"error": "Invalid input. 'radius' must be a non-negative number."}), 400

    area = calculate_area(radius)
    response = {
        "response": str(area),
    }
    return jsonify(response), 201

@app.route('/v1/calculate_perimeter', methods=['POST'])
def calculate_perimeter_endpoint():
    data = request.json
    radius = data.get("radius", None)

    if radius is None or not isinstance(radius, (int, float)) or radius < 0:
        return jsonify({"error": "Invalid input. 'radius' must be a non-negative number."}), 400

    perimeter = calculate_perimeter(radius)
    response = {
        "response": str(perimeter),
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
