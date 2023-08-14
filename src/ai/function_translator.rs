use crate::{
    ai::{
        function_health_check, function_status, update_chat_message, AiFunctionResponse,
        AiFunctionResponseStatus,
    },
    context::Context,
    entity::{AiFunction, ChatMessage},
    error::AppError,
    Result,
};
use axum::http::StatusCode;
use chrono::Utc;
use serde::Serialize;
use serde_json::value::Value;
use std::sync::Arc;
use tokio::time::{sleep, Duration};

#[derive(Debug, Serialize)]
pub struct FunctionTranslatorPost {
    pub device_map: serde_json::Value,
    pub source_language: String,
    pub target_language: String,
    pub text: String,
}

pub async fn handle_function_translator(
    ai_function: &AiFunction,
    chat_message: &ChatMessage,
    context: Arc<Context>,
    function_args: &Value,
) -> Result<Option<ChatMessage>> {
    let source_language = function_args["source_language"]
        .as_str()
        .ok_or(AppError::Casting)?;
    let target_language = function_args["target_language"]
        .as_str()
        .ok_or(AppError::Casting)?;
    let text = function_args["text"].as_str().ok_or(AppError::Casting)?;
    let mut failed_connection_attempts = 0;

    loop {
        let response =
            function_translator(ai_function, source_language, target_language, text).await?;
        if let Some(response) = response {
            let mut chat_message =
                update_chat_message(ai_function, &response, context.clone(), chat_message).await?;

            loop {
                let response = function_status(ai_function, &response).await?;

                if let Some(response) = response {
                    chat_message =
                        update_chat_message(ai_function, &response, context.clone(), &chat_message)
                            .await?;

                    if response.status == AiFunctionResponseStatus::Processed {
                        break;
                    }

                    let now = Utc::now();
                    let duration = now.signed_duration_since(response.estimated_response_at);
                    let seconds = if duration.num_seconds().abs() > 2 {
                        duration.num_seconds().abs().try_into()?
                    } else {
                        2
                    };

                    sleep(Duration::from_secs(seconds)).await;
                } else {
                    sleep(Duration::from_secs(2)).await;
                }
            }

            return Ok(Some(chat_message));
        } else {
            failed_connection_attempts += 1;

            if failed_connection_attempts > 10 {
                function_health_check(context.clone(), ai_function).await?;

                break;
            }

            sleep(Duration::from_secs(2)).await;
        }
    }

    Ok(None)
}

async fn function_translator(
    ai_function: &AiFunction,
    source_language: &str,
    target_language: &str,
    text: &str,
) -> Result<Option<AiFunctionResponse>> {
    let function_translator_post = FunctionTranslatorPost {
        device_map: ai_function.device_map.clone(),
        source_language: source_language.to_string(),
        target_language: target_language.to_string(),
        text: text.to_string(),
    };

    let response = reqwest::Client::new()
        .post(ai_function.base_function_url.clone())
        .json(&function_translator_post)
        .send()
        .await;

    if let Ok(response) = response {
        if response.status() == StatusCode::CREATED {
            let response: AiFunctionResponse = response.json().await?;

            return Ok(Some(response));
        }
    }

    Ok(None)
}
