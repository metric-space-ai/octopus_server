use crate::{
    ai::{update_chat_message_with_file_response, AiFunctionResponseFile},
    context::Context,
    entity::{AiFunction, ChatMessage},
    error::AppError,
    Result,
};
use axum::http::StatusCode;
use http::header::CONTENT_TYPE;
use serde::Serialize;
use serde_json::value::Value;
use std::sync::Arc;
use tokio::time::{sleep, Duration};

#[derive(Debug, Serialize)]
pub struct FunctionTextToImagePost {
    pub device_map: serde_json::Value,
    pub value1: String,
    pub value2: String,
}

pub async fn handle_function_text_to_image(
    ai_function: &AiFunction,
    chat_message: &ChatMessage,
    context: Arc<Context>,
    function_args: &Value,
) -> Result<Option<ChatMessage>> {
    let value1 = function_args["value1"].as_str().ok_or(AppError::Casting)?;
    let value2 = function_args["value2"].as_str().ok_or(AppError::Casting)?;
    let mut failed_connection_attempts = 0;

    loop {
        let response = function_text_to_image(ai_function, value1, value2).await?;
        if let Some(response) = response {
            let chat_message: ChatMessage = update_chat_message_with_file_response(
                ai_function,
                &response,
                context.clone(),
                chat_message,
            )
            .await?;

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

async fn function_text_to_image(
    ai_function: &AiFunction,
    value1: &str,
    value2: &str,
) -> Result<Option<AiFunctionResponseFile>> {
    let function_text_to_image_post = FunctionTextToImagePost {
        device_map: ai_function.device_map.clone(),
        value1: value1.to_string(),
        value2: value2.to_string(),
    };

    let response = reqwest::Client::new()
        .post(ai_function.base_function_url.clone())
        .json(&function_text_to_image_post)
        .send()
        .await;

    if let Ok(response) = response {
        if response.status() == StatusCode::CREATED {
            let headers_map = response.headers();
            let content_type_header = headers_map.get(CONTENT_TYPE).ok_or(AppError::File)?;
            let media_type = content_type_header.to_str()?.to_string();
            let content = response.bytes().await?;

            let ai_function_response_file = AiFunctionResponseFile {
                content,
                media_type,
            };

            return Ok(Some(ai_function_response_file));
        }
    }

    Ok(None)
}
