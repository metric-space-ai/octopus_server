import os

dependencies = [
    "pip install -q Flask==3.0.3",
    "pip install -q nc_py_api==0.13.0",
    "pip install -q python-dotenv==1.0.1"
]

for command in dependencies:
    os.system(command)

import json
import base64
from flask import Flask, jsonify, request
from nc_py_api import Nextcloud
from dotenv import load_dotenv

load_dotenv()

config_str = '''{
    "device_map": {
        "cuda:0": "10GiB",
        "cpu": "30GiB"
    },
    "required_python_version": "cp312",
    "functions": [
        {
            "name": "list_files",
            "display_name": "List Files",
            "description": "This function lists all files in the configured Nextcloud directory.",
            "parameters": {
                "type": "object",
                "properties": {}
            },
            "input_type": "application/json",
            "return_type": "application/json"
        }
    ]
}'''

config = json.loads(config_str)
app = Flask(__name__)

nc_username = os.getenv('NC_USERNAME')
nc_password = os.getenv('NC_PASSWORD')
nc_url = os.getenv('NC_URL')

nc = Nextcloud(nextcloud_url=nc_url, nc_auth_user=nc_username, nc_auth_pass=nc_password)

@app.route('/v1/list_files', methods=['POST'])
def list_files():
    try:
        files = nc.files.listdir("/")
        file_list = [file_info.name for file_info in files]
        response = {
            "response": ', '.join(file_list),
        }
        return jsonify(response), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/v1/setup", methods=["POST"])
def setup():
    response = {"setup": "Performed"}
    return jsonify(response), 201

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, threaded=True)
