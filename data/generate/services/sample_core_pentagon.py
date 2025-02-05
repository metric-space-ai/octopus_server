import os

dependencies = [
    "pip install -q Flask==3.1.0",
]

for command in dependencies:
    os.system(command)

import json
import math
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
            "display_name": "Calculate Area of Pentagon",
            "description": "This function calculates the area of a regular pentagon for a given side length.",
            "parameters": {
                "type": "object",
                "properties": {
                    "side_length": { "type": "number", "description": "The side length of the pentagon" }
                },
                "required": ["side_length"]
            },
            "input_type": "application/json",
            "return_type": "application/json"
        },
        {
            "name": "calculate_perimeter",
            "display_name": "Calculate Perimeter of Pentagon",
            "description": "This function calculates the perimeter of a regular pentagon for a given side length.",
            "parameters": {
                "type": "object",
                "properties": {
                    "side_length": { "type": "number", "description": "The side length of the pentagon" }
                },
                "required": ["side_length"]
            },
            "input_type": "application/json",
            "return_type": "application/json"
        }
    ]
}'''

config = json.loads(config_str)
app = Flask(__name__)

def calculate_pentagon_area(side_length):
    return (1/4) * math.sqrt(5 * (5 + 2 * math.sqrt(5))) * side_length ** 2

def calculate_pentagon_perimeter(side_length):
    return 5 * side_length

@app.route('/v1/calculate_area', methods=['POST'])
def calculate_area():
    data = request.json
    side_length = data.get("side_length", None)

    if side_length is None or not isinstance(side_length, (int, float)) or side_length <= 0:
        return jsonify({"error": "Invalid input. 'side_length' must be a positive number."}), 400

    area = calculate_pentagon_area(side_length)
    response = {
        "response": str(area),
    }
    return jsonify(response), 201

@app.route('/v1/calculate_perimeter', methods=['POST'])
def calculate_perimeter():
    data = request.json
    side_length = data.get("side_length", None)

    if side_length is None or not isinstance(side_length, (int, float)) or side_length <= 0:
        return jsonify({"error": "Invalid input. 'side_length' must be a positive number."}), 400

    perimeter = calculate_pentagon_perimeter(side_length)
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
