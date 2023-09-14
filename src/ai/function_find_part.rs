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

pub async fn handle_function_find_part(
    ai_function: &AiFunction,
    chat_message: &ChatMessage,
    context: Arc<Context>,
    function_args: &Value,
) -> Result<Option<ChatMessage>> {
    let mut failed_connection_attempts = 0;

    loop {
        let response = function_find_part(ai_function, function_args).await?;

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

async fn function_find_part(
    ai_function: &AiFunction,
    function_args: &Value,
) -> Result<Option<AiFunctionResponseFile>> {
    let response = reqwest::Client::new()
        .post(ai_function.base_function_url.clone())
        .json(&function_args)
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
