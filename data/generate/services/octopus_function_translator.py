import os
#os.environ["FLASK_ENV"] = "development"

### BEGIN USER EDITABLE SECTION ###

dependencies = [
    "pip install -q blinker==1.7.0",
    "pip install -q certifi==2024.2.2",
    "pip install -q charset-normalizer==3.3.2",
    "pip install -q click==8.1.7",
    "pip install -q Cython==3.0.10",
    "pip install -q fasttext-wheel==0.9.2",
    "pip install -q filelock==3.13.4",
    "pip install -q Flask==3.0.3",
    "pip install -q fsspec==2024.3.1",
    "pip install -q huggingface-hub==0.22.2",
    "pip install -q idna==3.7",
    "pip install -q itsdangerous==2.1.2",
    "pip install -q Jinja2==3.1.3",
    "pip install -q joblib==1.4.0",
    "pip install -q MarkupSafe==2.1.5",
    "pip install -q mpmath==1.3.0",
    "pip install -q networkx==3.3",
    "pip install -q nltk==3.8.1",
    "pip install -q numpy==1.26.4",
    "pip install -q nvidia-cublas-cu12==12.1.3.1",
    "pip install -q nvidia-cuda-cupti-cu12==12.1.105",
    "pip install -q nvidia-cuda-nvrtc-cu12==12.1.105",
    "pip install -q nvidia-cuda-runtime-cu12==12.1.105",
    "pip install -q nvidia-cudnn-cu12==8.9.2.26",
    "pip install -q nvidia-cufft-cu12==11.0.2.54",
    "pip install -q nvidia-curand-cu12==10.3.2.106",
    "pip install -q nvidia-cusolver-cu12==11.4.5.107",
    "pip install -q nvidia-cusparse-cu12==12.1.0.106",
    "pip install -q nvidia-nccl-cu12==2.19.3",
    "pip install -q nvidia-nvjitlink-cu12==12.4.127",
    "pip install -q nvidia-nvtx-cu12==12.1.105",
    "pip install -q packaging==24.0",
    "pip install -q pillow==10.3.0",
    "pip install -q pybind11==2.12.0",
    "pip install -q PyYAML==6.0.1",
    "pip install -q regex==2023.12.25",
    "pip install -q requests==2.31.0",
    "pip install -q safetensors==0.4.2",
    "pip install -q sympy==1.12",
    "pip install -q tokenizers==0.15.2",
    "pip install -q torch==2.2.2",
    "pip install -q torchaudio==2.2.2",
    "pip install -q torchvision==0.17.2",
    "pip install -q tqdm==4.66.2",
    "pip install -q transformers==4.39.3",
    "pip install -q triton==2.2.0",
    "pip install -q typing_extensions==4.11.0",
    "pip install -q urllib3==2.2.1",
    "pip install -q Werkzeug==3.0.2"
]

for command in dependencies:
    os.system(command)

### Configuration section
config_str = '''{
    "device_map": {
    "cuda:0": "15GiB",
    "cuda:1": "15GiB",
    "cuda:2": "15GiB",
    "cuda:3": "15GiB"
    },
    "required_python_version": "cp311",
    "model_setup": {
        "file": "lid218e.bin",
        "url": "https://dl.fbaipublicfiles.com/nllb/lid/lid218e.bin",
        "model_call_name": "3.3B",
        "model_real_name": "facebook/nllb-200-3.3B"
    },
    "functions": [
        {
            "name": "function_translator",
            "display_name": "Translator",
            "description": "Translator function",
            "parameters": {
                "type": "object",
                "properties": {
                    "source_language": { "type": "string", "description": "Source language of the text" },
                    "target_language": { "type": "string", "description": "Target language for translation" },
                    "text": { "type": "string", "description": "Translated text" }
                },
                "required": ["source_language", "target_language", "text"]
            },
            "input_type": "json",
            "return_type": "application/json"
        }
    ]}'''
### END USER EDITABLE SECTION ###

import json, uuid
from flask import Flask, jsonify, request

import requests
import torch
import time
from transformers import AutoTokenizer, AutoModelForSeq2SeqLM, pipeline
import fasttext
import nltk
from nltk.tokenize import sent_tokenize
import subprocess

config = json.loads(config_str)
app = Flask(__name__)

### AI function section
file = config["model_setup"]["file"]
url = config["model_setup"]["url"]
flores_codes={'Acehnese (Arabic script)': 'ace_Arab', 'Acehnese (Latin script)': 'ace_Latn', 'Mesopotamian Arabic': 'acm_Arab', 'Ta’izzi-Adeni Arabic': 'acq_Arab', 'Tunisian Arabic': 'aeb_Arab', 'Afrikaans': 'afr_Latn', 'South Levantine Arabic': 'ajp_Arab', 'Akan': 'aka_Latn', 'Amharic': 'amh_Ethi', 'North Levantine Arabic': 'apc_Arab', 'Modern Standard Arabic': 'arb_Arab', 'Modern Standard Arabic (Romanized)': 'arb_Latn', 'Najdi Arabic': 'ars_Arab', 'Moroccan Arabic': 'ary_Arab', 'Egyptian Arabic': 'arz_Arab', 'Assamese': 'asm_Beng', 'Asturian': 'ast_Latn', 'Awadhi': 'awa_Deva', 'Central Aymara': 'ayr_Latn', 'South Azerbaijani': 'azb_Arab', 'North Azerbaijani': 'azj_Latn', 'Bashkir': 'bak_Cyrl', 'Bambara': 'bam_Latn', 'Balinese': 'ban_Latn', 'Belarusian': 'bel_Cyrl', 'Bemba': 'bem_Latn', 'Bengali': 'ben_Beng', 'Bhojpuri': 'bho_Deva', 'Banjar (Arabic script)': 'bjn_Arab', 'Banjar (Latin script)': 'bjn_Latn', 'Standard Tibetan': 'bod_Tibt', 'Bosnian': 'bos_Latn', 'Buginese': 'bug_Latn', 'Bulgarian': 'bul_Cyrl', 'Catalan': 'cat_Latn', 'Cebuano': 'ceb_Latn', 'Czech': 'ces_Latn', 'Chokwe': 'cjk_Latn', 'Central Kurdish': 'ckb_Arab', 'Crimean Tatar': 'crh_Latn', 'Welsh': 'cym_Latn', 'Danish': 'dan_Latn', 'German': 'deu_Latn', 'Southwestern Dinka': 'dik_Latn', 'Dyula': 'dyu_Latn', 'Dzongkha': 'dzo_Tibt', 'Greek': 'ell_Grek', 'English': 'eng_Latn', 'Esperanto': 'epo_Latn', 'Estonian': 'est_Latn', 'Basque': 'eus_Latn', 'Ewe': 'ewe_Latn', 'Faroese': 'fao_Latn', 'Fijian': 'fij_Latn', 'Finnish': 'fin_Latn', 'Fon': 'fon_Latn', 'French': 'fra_Latn', 'Friulian': 'fur_Latn', 'Nigerian Fulfulde': 'fuv_Latn', 'Scottish Gaelic': 'gla_Latn', 'Irish': 'gle_Latn', 'Galician': 'glg_Latn', 'Guarani': 'grn_Latn', 'Gujarati': 'guj_Gujr', 'Haitian Creole': 'hat_Latn', 'Hausa': 'hau_Latn', 'Hebrew': 'heb_Hebr', 'Hindi': 'hin_Deva', 'Chhattisgarhi': 'hne_Deva', 'Croatian': 'hrv_Latn', 'Hungarian': 'hun_Latn', 'Armenian': 'hye_Armn', 'Igbo': 'ibo_Latn', 'Ilocano': 'ilo_Latn', 'Indonesian': 'ind_Latn', 'Icelandic': 'isl_Latn', 'Italian': 'ita_Latn', 'Javanese': 'jav_Latn', 'Japanese': 'jpn_Jpan', 'Kabyle': 'kab_Latn', 'Jingpho': 'kac_Latn', 'Kamba': 'kam_Latn', 'Kannada': 'kan_Knda', 'Kashmiri (Arabic script)': 'kas_Arab', 'Kashmiri (Devanagari script)': 'kas_Deva', 'Georgian': 'kat_Geor', 'Central Kanuri (Arabic script)': 'knc_Arab', 'Central Kanuri (Latin script)': 'knc_Latn', 'Kazakh': 'kaz_Cyrl', 'Kabiyè': 'kbp_Latn', 'Kabuverdianu': 'kea_Latn', 'Khmer': 'khm_Khmr', 'Kikuyu': 'kik_Latn', 'Kinyarwanda': 'kin_Latn', 'Kyrgyz': 'kir_Cyrl', 'Kimbundu': 'kmb_Latn', 'Northern Kurdish': 'kmr_Latn', 'Kikongo': 'kon_Latn', 'Korean': 'kor_Hang', 'Lao': 'lao_Laoo', 'Ligurian': 'lij_Latn', 'Limburgish': 'lim_Latn', 'Lingala': 'lin_Latn', 'Lithuanian': 'lit_Latn', 'Lombard': 'lmo_Latn', 'Latgalian': 'ltg_Latn', 'Luxembourgish': 'ltz_Latn', 'Luba-Kasai': 'lua_Latn', 'Ganda': 'lug_Latn', 'Luo': 'luo_Latn', 'Mizo': 'lus_Latn', 'Standard Latvian': 'lvs_Latn', 'Magahi': 'mag_Deva', 'Maithili': 'mai_Deva', 'Malayalam': 'mal_Mlym', 'Marathi': 'mar_Deva', 'Minangkabau (Arabic script)': 'min_Arab', 'Minangkabau (Latin script)': 'min_Latn', 'Macedonian': 'mkd_Cyrl', 'Plateau Malagasy': 'plt_Latn', 'Maltese': 'mlt_Latn', 'Meitei (Bengali script)': 'mni_Beng', 'Halh Mongolian': 'khk_Cyrl', 'Mossi': 'mos_Latn', 'Maori': 'mri_Latn', 'Burmese': 'mya_Mymr', 'Dutch': 'nld_Latn', 'Norwegian Nynorsk': 'nno_Latn', 'Norwegian Bokmål': 'nob_Latn', 'Nepali': 'npi_Deva', 'Northern Sotho': 'nso_Latn', 'Nuer': 'nus_Latn', 'Nyanja': 'nya_Latn', 'Occitan': 'oci_Latn', 'West Central Oromo': 'gaz_Latn', 'Odia': 'ory_Orya', 'Pangasinan': 'pag_Latn', 'Eastern Panjabi': 'pan_Guru', 'Papiamento': 'pap_Latn', 'Western Persian': 'pes_Arab', 'Polish': 'pol_Latn', 'Portuguese': 'por_Latn', 'Dari': 'prs_Arab', 'Southern Pashto': 'pbt_Arab', 'Ayacucho Quechua': 'quy_Latn', 'Romanian': 'ron_Latn', 'Rundi': 'run_Latn', 'Russian': 'rus_Cyrl', 'Sango': 'sag_Latn', 'Sanskrit': 'san_Deva', 'Santali': 'sat_Olck', 'Sicilian': 'scn_Latn', 'Shan': 'shn_Mymr', 'Sinhala': 'sin_Sinh', 'Slovak': 'slk_Latn', 'Slovenian': 'slv_Latn', 'Samoan': 'smo_Latn', 'Shona': 'sna_Latn', 'Sindhi': 'snd_Arab', 'Somali': 'som_Latn', 'Southern Sotho': 'sot_Latn', 'Spanish': 'spa_Latn', 'Tosk Albanian': 'als_Latn', 'Sardinian': 'srd_Latn', 'Serbian': 'srp_Cyrl', 'Swati': 'ssw_Latn', 'Sundanese': 'sun_Latn', 'Swedish': 'swe_Latn', 'Swahili': 'swh_Latn', 'Silesian': 'szl_Latn', 'Tamil': 'tam_Taml', 'Tatar': 'tat_Cyrl', 'Telugu': 'tel_Telu', 'Tajik': 'tgk_Cyrl', 'Tagalog': 'tgl_Latn', 'Thai': 'tha_Thai', 'Tigrinya': 'tir_Ethi', 'Tamasheq (Latin script)': 'taq_Latn', 'Tamasheq (Tifinagh script)': 'taq_Tfng', 'Tok Pisin': 'tpi_Latn', 'Tswana': 'tsn_Latn', 'Tsonga': 'tso_Latn', 'Turkmen': 'tuk_Latn', 'Tumbuka': 'tum_Latn', 'Turkish': 'tur_Latn', 'Twi': 'twi_Latn', 'Central Atlas Tamazight': 'tzm_Tfng', 'Uyghur': 'uig_Arab', 'Ukrainian': 'ukr_Cyrl', 'Umbundu': 'umb_Latn', 'Urdu': 'urd_Arab', 'Northern Uzbek': 'uzn_Latn', 'Venetian': 'vec_Latn', 'Vietnamese': 'vie_Latn', 'Waray': 'war_Latn', 'Wolof': 'wol_Latn', 'Xhosa': 'xho_Latn', 'Eastern Yiddish': 'ydd_Hebr', 'Yoruba': 'yor_Latn', 'Yue Chinese': 'yue_Hant', 'Chinese (Simplified)': 'zho_Hans', 'Chinese (Traditional)': 'zho_Hant', 'Standard Malay': 'zsm_Latn', 'Zulu': 'zul_Latn'}
LID = None
model_dict = None
nltk_download = None

def command_result_as_int(command):
    return int(subprocess.check_output(command, shell=True).decode('utf-8').strip())

def select_device_with_larger_free_memory(available_devices):
    device = None
    memory = 0

    for available_device in available_devices:
        id = available_device.split(":")
        id = id[-1]
        free_memory = command_result_as_int(f"nvidia-smi --query-gpu=memory.free --format=csv,nounits,noheader --id={id}")
        if free_memory > memory:
            memory = free_memory
            device = available_device

    return device if device else "cpu"

def select_device():
    if not torch.cuda.is_available():
        return "cpu"

    device_map = config.get('device_map', {})
    available_devices = list(device_map.keys())
    return select_device_with_larger_free_memory(available_devices)

device = select_device()

### BEGIN USER EDITABLE SECTION ###
def load_models():
    call_name = config["model_setup"]["model_call_name"]
    real_name = config["model_setup"]["model_real_name"]

    model_dict = {}
    model = AutoModelForSeq2SeqLM.from_pretrained(real_name, torch_dtype=torch.bfloat16).to(device)
    tokenizer = AutoTokenizer.from_pretrained(real_name)
    model_dict[call_name+'_model'] = model
    model_dict[call_name+'_tokenizer'] = tokenizer

    return model_dict

def translation(model_name, selection_mode, source, target, text):
    start_time = time.time()

    # Determine the source language
    if selection_mode == "Auto-detect": #TODO: "auto" should be a possible source parameter
        predictions = LID.predict(text)
        source_code = predictions[0][0].replace("__label__", "")
    else:
        if source == "Auto-detect":  # Make sure we don't use "Auto-detect" as a key
            return {'error': "Source language cannot be 'Auto-detect' when selection mode is manual."}
        source_code = flores_codes.get(source)
        if not source_code:
            return {'error': f"Source language {source} not found in flores_codes."}

    target_code = flores_codes[target]
    model = model_dict[model_name + '_model']
    tokenizer = model_dict[model_name + '_tokenizer']

    translator = pipeline('translation', model=model, tokenizer=tokenizer, src_lang=source_code, tgt_lang=target_code, device=device)

    sentences = sent_tokenize(text)
    translated_sentences = []
    for sentence in sentences:
        translated_sentence = translator(sentence, max_length=400)[0]['translation_text']
        translated_sentences.append(translated_sentence)
    output = ' '.join(translated_sentences)

    end_time = time.time()

    result = {
        'inference_time': end_time - start_time,
        'source_language': source_code,
        'target_language': target_code,
        'result': output
    }

    return result
### END USER EDITABLE SECTION ###

### AI service section
@app.route('/v1/<function_name>', methods=['POST'])
def generic_route(function_name):
### BEGIN USER EDITABLE SECTION ###
    function_config = config["functions"][0]

    if not function_config:
        return jsonify({"error": "Invalid endpoint"}), 404

    if function_config["input_type"] != "json":
        return jsonify({"error": f"Unsupported input type {function_config['input_type']}"}), 400

    data = request.json
    model_name = config["model_setup"]["model_call_name"]
    selection_mode = "Manually select"
    device_map = data.get("device_map", "")
    source = data.get("source_language", "")
    target = data.get("target_language", "")
    text = data.get("text", "")

    result = translation(model_name, selection_mode, source, target, text)

    response_text = str(result["result"])

    response = {
        "response": response_text,
    }

    return jsonify(response), 201
### END USER EDITABLE SECTION ###

@app.route("/v1/setup", methods=["POST"])
def setup():
### BEGIN USER EDITABLE SECTION ###
    global LID
    global nltk_download
    global model_dict
    data = request.json
    force_setup = data.get("force_setup", False)

    if not os.path.isfile(file) or force_setup:
        response = requests.get(url)
        open(file, "wb").write(response.content)

    if LID == None:
        LID = fasttext.load_model(file)
    if nltk_download == None:
        nltk.download('punkt')
        nltk_download = True
    if model_dict == None:
        model_dict = load_models()
### END USER EDITABLE SECTION ###
    response = {
        "setup": "Performed"
    }

    return jsonify(response), 201
