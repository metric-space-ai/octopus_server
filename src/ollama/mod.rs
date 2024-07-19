use crate::{
    context::Context,
    entity::{OllamaModel, OllamaModelStatus},
    Result,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::time::Duration;

pub mod proxy;

#[derive(Debug, Serialize, Deserialize)]
struct Details1 {
    families: Option<Vec<String>>,
    family: String,
    format: String,
    parameter_size: String,
    parent_model: Option<String>,
    quantization_level: String,
}
#[derive(Debug, Serialize, Deserialize)]
struct Models1 {
    details: Details1,
    digest: String,
    model: String,
    modified_at: String,
    name: String,
    size: i64,
}
#[derive(Debug, Serialize, Deserialize)]
struct Root1 {
    models: Vec<Models1>,
}

pub fn get_models() -> Vec<&'static str> {
    let models = vec![
        "alfred:40b",
        "all-minilm:22m",
        "all-minilm:33m",
        "aya:8b",
        "aya:35b",
        "bakllava:7b",
        "codebooga:34b",
        "codegeex4:9b",
        "codegemma:2b",
        "codegemma:7b",
        "codegemma:7b-code",
        "codegemma:code",
        "codegemma:instruct",
        "codellama:7b",
        "codellama:13b",
        "codellama:34b",
        "codellama:70b",
        "codeqwen:7b",
        "codeqwen:chat",
        "codeqwen:code",
        "codestral:22b",
        "codeup:13b",
        "codeup:13b-llama2",
        "codeup:13b-llama2-chat",
        "command-r:35b",
        "command-r-plus:104b",
        "command-r-plus:104b-q4_0",
        "command-r-plus:104b-q8_0",
        "command-r-plus:104b-q2_K",
        "command-r-plus:104b-fp16",
        "dbrx:132b",
        "dbrx:instruct",
        "deepseek-coder:1.3b",
        "deepseek-coder:6.7b",
        "deepseek-coder:33b",
        "deepseek-coder-v2:16b",
        "deepseek-coder-v2:236b",
        "deepseek-llm:7b",
        "deepseek-llm:67b",
        "deepseek-v2:16b",
        "deepseek-v2:236b",
        "dolphincoder:7b",
        "dolphincoder:15b",
        "dolphin-llama3:8b",
        "dolphin-llama3:70b",
        "dolphin-mistral:7b",
        "dolphin-mixtral:8x7b",
        "dolphin-mixtral:8x22b",
        "dolphin-phi:2.7b",
        "duckdb-nsql:7b",
        "everythinglm:13b",
        "falcon:7b",
        "falcon:40b",
        "falcon:180b",
        "falcon2:11b",
        "gemma:2b",
        "gemma:7b",
        "gemma:instruct",
        "gemma:text",
        "gemma2:9b",
        "gemma2:27b",
        "glm4:9b",
        "goliath:120b-q4_0",
        "granite-code:3b",
        "granite-code:8b",
        "granite-code:20b",
        "granite-code:34b",
        "llama-pro:text",
        "llama-pro:instruct",
        "llama2:7b",
        "llama2:13b",
        "llama2:70b",
        "llama2:chat",
        "llama2:text",
        "llama2-uncensored:7b",
        "llama2-uncensored:70b",
        "llama2-uncensored:70b-chat",
        "llama3-chatqa:8b",
        "llama3-chatqa:70b",
        "llama3:8b",
        "llama3:70b",
        "llama3:instruct",
        "llama3:text",
        "llama3:70b-text",
        "llama3-chatqa:8b",
        "llama3-chatqa:70b",
        "llama3-gradient:8b",
        "llama3-gradient:70b",
        "llava:7b",
        "llava:13b",
        "llava:34b",
        "llava-llama3:8b",
        "llava-phi3:3.8b",
        "magicoder:7b",
        "magicoder:7b-s-cl",
        "mathstral:7b",
        "meditron:7b",
        "meditron:70b",
        "medllama2:7b",
        "megadolphin:120b",
        "mistral:7b",
        "mistral:instruct",
        "mixtral:8x7b",
        "mixtral:8x22b",
        "mixtral:instruct",
        "mixtral:text",
        "mistral-openorca:7b",
        "mistrallite:7b",
        "moondream:1.8b",
        "mxbai-embed-large:335m",
        "neural-chat:7b",
        "nexusraven:13b",
        "nomic-embed-text",
        "notus:7b",
        "notux:8x7b",
        "nous-hermes:7b",
        "nous-hermes:13b",
        "nous-hermes2:10.7b",
        "nous-hermes2:34b",
        "nous-hermes2-mixtral:8x7b",
        "nous-hermes2-mixtral:dpo",
        "openchat:7b",
        "openhermes:v2.5",
        "openhermes:7b-v2.5",
        "open-orca-platypus2:13b",
        "orca-mini:3b",
        "orca-mini:7b",
        "orca-mini:13b",
        "orca-mini:70b",
        "orca2:7b",
        "orca2:13b",
        "phind-codellama:34b",
        "phind-codellama:34b-python",
        "phi:2.7b",
        "phi:chat",
        "phi3:3.8b",
        "phi3:14b",
        "phi3:instruct",
        "phi3:mini",
        "phi3:mini-128k",
        "qwen:7b",
        "qwen:14b",
        "qwen:32b",
        "qwen:72b",
        "qwen:110b",
        "qwen2:0.5b",
        "qwen2:1.5b",
        "qwen2:7b",
        "qwen2:72b",
        "samantha-mistral:7b",
        "samantha-mistral:7b-text",
        "snowflake-arctic-embed:335m",
        "sqlcoder:7b",
        "sqlcoder:15b",
        "solar:10.7b",
        "stable-beluga:7b",
        "stable-beluga:13b",
        "stable-beluga:70b",
        "stable-code:3b",
        "stable-code:code",
        "stable-code:instruct",
        "stablelm-zephyr:3b",
        "stablelm2:1.6b",
        "stablelm2:12b",
        "stablelm2:chat",
        "stablelm2:zephyr",
        "starcoder:1b",
        "starcoder:3b",
        "starcoder:7b",
        "starcoder:15b",
        "starcoder2:3b",
        "starcoder2:7b",
        "starcoder2:15b",
        "starling-lm:7b",
        "tinydolphin:1.1b",
        "tinyllama:1.1b",
        "tinyllama:chat",
        "vicuna:7b",
        "vicuna:13b",
        "vicuna:33b",
        "wizardcoder:python",
        "wizardcoder:33b",
        "wizardlm-uncensored:13b",
        "wizardlm-uncensored:13b-llama2",
        "wizardlm2:7b",
        "wizardlm2:8x22b",
        "wizardlm2:70b",
        "wizard-math:7b",
        "wizard-math:13b",
        "wizard-math:70b",
        "wizard-vicuna:13b",
        "wizard-vicuna-uncensored:7b",
        "wizard-vicuna-uncensored:13b",
        "wizard-vicuna-uncensored:30b",
        "xwinlm:7b",
        "xwinlm:13b",
        "xwinlm:70b-v0.1",
        "yarn-llama2:7b",
        "yarn-llama2:13b",
        "yarn-mistral:7b",
        "yi:6b",
        "yi:9b",
        "yi:34b",
        "zephyr:7b",
        "zephyr:141b",
    ];

    models
}

pub async fn pull(context: Arc<Context>, ollama_model: OllamaModel) -> Result<OllamaModel> {
    let ollama_host = context.get_config().await?.ollama_host;

    if let Some(ollama_host) = ollama_host {
        let client = reqwest::Client::new();

        if !context.get_config().await?.test_mode {
            let url = format!("{ollama_host}/api/pull");
            client
                .post(url.clone())
                .body(
                    serde_json::json!({
                        "name": &ollama_model.name,
                    })
                    .to_string(),
                )
                .timeout(Duration::from_secs(1800))
                .send()
                .await?
                .text()
                .await?;

            let url = format!("{ollama_host}/api/tags");
            let response: Root1 = client
                .get(url.clone())
                .timeout(Duration::from_secs(1800))
                .send()
                .await?
                .json()
                .await?;

            for model in response.models {
                let ollama_model_name_latest = format!("{}:latest", ollama_model.name);

                if model.name == ollama_model_name_latest || model.name == ollama_model.name {
                    let mut transaction = context.octopus_database.transaction_begin().await?;

                    let ollama_model = context
                        .octopus_database
                        .update_ollama_model_pull(
                            &mut transaction,
                            ollama_model.id,
                            &model.name,
                            &model.details.family,
                            model.details.families,
                            &model.details.format,
                            &model.details.parameter_size,
                            model.details.parent_model,
                            &model.details.quantization_level,
                            &model.digest,
                            &model.model,
                            &model.modified_at,
                            &format!("{}", model.size),
                            OllamaModelStatus::Pulled,
                        )
                        .await?;

                    context
                        .octopus_database
                        .transaction_commit(transaction)
                        .await?;

                    return Ok(ollama_model);
                }
            }
        }
    }

    Ok(ollama_model)
}

pub async fn pull_on_start(context: Arc<Context>) -> Result<()> {
    let ollama_models = context.octopus_database.get_ollama_models().await?;

    for ollama_model in ollama_models {
        pull(context.clone(), ollama_model).await?;
    }

    Ok(())
}
