use crate::{
    context::Context,
    entity::{OllamaModel, OllamaModelStatus},
    Result,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::time::Duration;

#[derive(Serialize, Deserialize)]
struct Details1 {
    families: Vec<String>,
    family: String,
    format: String,
    parameter_size: String,
    parent_model: Option<String>,
    quantization_level: String,
}
#[derive(Serialize, Deserialize)]
struct Models1 {
    details: Details1,
    digest: String,
    model: String,
    modified_at: String,
    name: String,
    size: i64,
}
#[derive(Serialize, Deserialize)]
struct Root1 {
    models: Vec<Models1>,
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
                if model.name == ollama_model.name {
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
