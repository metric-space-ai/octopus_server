use crate::{
    ai::{update_chat_message, AiFunctionResponse, BASE_AI_FUNCTION_URL},
    context::Context,
    entity::{AiFunction, ChatMessage},
    error::AppError,
    Result,
};
use axum::http::StatusCode;
use serde::Serialize;
use serde_json::value::Value;
use std::sync::Arc;
use tokio::time::{sleep, Duration};

#[derive(Debug, Serialize)]
pub struct FunctionFooSyncPost {
    pub device_map: serde_json::Value,
    pub value1: String,
    pub value2: String,
}

pub async fn handle_function_foo_sync(
    ai_function: &AiFunction,
    chat_message: &ChatMessage,
    context: Arc<Context>,
    function_args: &Value,
) -> Result<Option<ChatMessage>> {
    let value1 = function_args["value1"].as_str().ok_or(AppError::Casting)?;
    let value2 = function_args["value2"].as_str().ok_or(AppError::Casting)?;
    let mut failed_connection_attempts = 0;

    loop {
        let response = function_foo_sync(ai_function, value1, value2).await?;

        if let Some(response) = response {
            let chat_message =
                update_chat_message(ai_function, &response, context.clone(), chat_message).await?;

            return Ok(Some(chat_message));
        } else {
            failed_connection_attempts += 1;

            if failed_connection_attempts > 10 {
                break;
            }

            sleep(Duration::from_secs(2)).await;
        }
    }

    Ok(None)
}

async fn function_foo_sync(
    ai_function: &AiFunction,
    value1: &str,
    value2: &str,
) -> Result<Option<AiFunctionResponse>> {
    let function_foo_sync_post = FunctionFooSyncPost {
        device_map: ai_function.device_map.clone(),
        value1: value1.to_string(),
        value2: value2.to_string(),
    };

    if let Some(port) = ai_function.port {
        let url = format!("{BASE_AI_FUNCTION_URL}:{}/{}", port, ai_function.name);
        let response = reqwest::Client::new()
            .post(url)
            .json(&function_foo_sync_post)
            .send()
            .await;

        if let Ok(response) = response {
            if response.status() == StatusCode::CREATED {
                let response: AiFunctionResponse = response.json().await?;

                return Ok(Some(response));
            }
        }
    }

    Ok(None)
}
