import os

dependencies = [
    "pip install -q Flask==3.0.3",
    "pip install -q openai==1.35.3",
]

for command in dependencies:
    os.system(command)

import json
import os
from flask import Flask, jsonify, request
from openai import OpenAI

config_str = '''{
    "device_map": {
        "cuda:0": "10GiB",
        "cpu": "30GiB"
    },
    "required_python_version": "cp312",
    "models": {
        "model": "gpt-4o-2024-05-13"
    },
    "functions": [
        {
            "name": "get_formula",
            "display_name": "Get Mathematical Formula",
            "description": "This function provides the mathematical formula for calculating a specified thing.",
            "parameters": {
                "type": "object",
                "properties": {
                    "topic": { "type": "string", "description": "The mathematical topic for which the formula is requested" }
                },
                "required": ["topic"]
            },
            "input_type": "application/json",
            "return_type": "application/json"
        }
    ]
}'''

config = json.loads(config_str)
app = Flask(__name__)

client = OpenAI()  # Using the OPENAI_API_KEY environment variable

@app.route('/v1/get_formula', methods=['POST'])
def get_formula():
    data = request.json
    topic = data.get("topic", None)

    if topic is None or not isinstance(topic, str) or not topic.strip():
        return jsonify({"error": "Please provide a valid topic."}), 400

    content = f"Give me the mathematical formula for calculating the {topic}."
    chat_completion = client.chat.completions.create(
        messages=[{
            "role": "user",
            "content": content,
        }],
        model=config["models"]["model"],
    )

    formula = chat_completion.choices[0].message.content.strip()
    response = {
        "response": formula,
    }
    return jsonify(response), 201

@app.route("/v1/setup", methods=["POST"])
def setup():
    response = {"setup": "Performed"}
    return jsonify(response), 201

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, threaded=True)
