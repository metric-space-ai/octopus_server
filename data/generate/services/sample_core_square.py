import os

dependencies = [
    "pip install -q Flask==3.0.3",
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
            "name": "calculate_perimeter",
            "display_name": "Calculate Perimeter",
            "description": "This function calculates the perimeter of a square for a given side length.",
            "parameters": {
                "type": "object",
                "properties": {
                    "side_length": { "type": "number", "description": "The side length of the square" }
                },
                "required": ["side_length"]
            },
            "input_type": "application/json",
            "return_type": "application/json"
        },
        {
            "name": "calculate_area",
            "display_name": "Calculate Area",
            "description": "This function calculates the area of a square for a given side length.",
            "parameters": {
                "type": "object",
                "properties": {
                    "side_length": { "type": "number", "description": "The side length of the square" }
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

class SquareCalculator:
    def __init__(self, side_length):
        self.side_length = side_length

    def calculate_area(self):
        return self.side_length ** 2

    def calculate_perimeter(self):
        return 4 * self.side_length

@app.route('/v1/calculate_area', methods=['POST'])
def calculate_area():
    data = request.json
    side_length = data.get("side_length", None)

    if side_length is None or not isinstance(side_length, (int, float)) or side_length < 0:
        return jsonify({"error": "Invalid input. It must be a non-negative number."}), 400

    calculator = SquareCalculator(side_length)
    result = calculator.calculate_area()
    response = {
        "response": str(result),
    }
    return jsonify(response), 201

@app.route('/v1/calculate_perimeter', methods=['POST'])
def calculate_perimeter():
    data = request.json
    side_length = data.get("side_length", None)

    if side_length is None or not isinstance(side_length, (int, float)) or side_length < 0:
        return jsonify({"error": "Invalid input. It must be a non-negative number."}), 400

    calculator = SquareCalculator(side_length)
    result = calculator.calculate_perimeter()
    response = {
        "response": str(result),
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
