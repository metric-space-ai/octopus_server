import os

dependencies = [
    'pip install -q Flask==3.0.3',
    'pip install -q openai==1.30.1',
    'pip install -q requests==2.31.0',
]

for command in dependencies:
    os.system(command)

import json, requests
from flask import Flask, jsonify, request
from openai import OpenAI

config_str = '''{
    "device_map": {
        "cuda:0": "10GiB",
        "cpu": "30GiB"
    },
    "required_python_version": "cp311",
    "models": {
        "model": "gpt-4o-2024-05-13"
    },
    "functions": [
        {
            "name": "summarize_website",
            "display_name": "Summarize Website",
            "description": "This function uses OpenAI API and the octopus_server scraper to make a summary of the given website.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "The URL of the website to summarize"
                    }
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

client = OpenAI()  # Using the OPENAI_API_KEY environment variable

def scrape_content(url):
    scraper_service_url = f"http://localhost:8080/api/v1/scraper-service?url={url}"
    response = requests.get(scraper_service_url)
    if response.status_code == 200:
        return response
    return None

@app.route('/v1/summarize_website', methods=['POST'])
def summarize_website():
    data = request.json
    url = data.get("url", None)

    if url is None or not isinstance(url, str) or not url.strip():
        return jsonify({"error": "Please provide a valid URL."}), 400

    scraped_content = scrape_content(url)
    if not scraped_content:
        return jsonify({"error": "Error scraping the website."}), 500

    content = f"Summarize the following content: {scraped_content.text}"
    chat_completion = client.chat.completions.create(
        messages=[{
            "role": "user",
            "content": content,
        }],
        model=config["models"]["model"],
    )

    summary = chat_completion.choices[0].message.content.strip()
    response = {
        "response": summary,
    }
    return jsonify(response), 201

@app.route("/v1/setup", methods=["POST"])
def setup():
    response = {"setup": "Performed"}
    return jsonify(response), 201

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, threaded=True)
