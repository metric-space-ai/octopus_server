import os

dependencies = [
    "pip install -q Flask==3.0.3",
]

for command in dependencies:
    os.system(command)

import json
from functools import lru_cache
from flask import Flask, jsonify, request

config_str = '''{
    "device_map": {
        "cuda:0": "10GiB",
        "cpu": "30GiB"
    },
    "required_python_version": "cp312",
    "functions": [
        {
            "name": "get_factorial",
            "display_name": "Get Factorial",
            "description": "This function returns the factorial for a given integer value.",
            "parameters": {
                "type": "object",
                "properties": {
                    "n": { "type": "integer", "description": "The number to calculate the factorial of" }
                },
                "required": ["n"]
            },
            "input_type": "application/json",
            "return_type": "application/json"
        }
    ]
}'''

config = json.loads(config_str)
app = Flask(__name__)

@lru_cache(maxsize=None)
def factorial(n):
    if n == 0:
        return 1
    return n * factorial(n - 1)

@app.route('/v1/get_factorial', methods=['POST'])
def get_factorial():
    data = request.json
    n = data.get("n", None)

    if n is None or not isinstance(n, int) or n < 0:
        return jsonify({"error": "Invalid input. It must be a non-negative integer."}), 400

    result = factorial(n)
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
