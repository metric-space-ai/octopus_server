use crate::{
    ai::{
        update_chat_message, AiFunctionResponse, AiFunctionResponseResponse,
        AiFunctionResponseStatus, BASE_AI_FUNCTION_URL,
    },
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
use uuid::Uuid;

#[derive(Debug, Serialize)]
pub struct FunctionVisualQuestionsAnsweringPost {
    pub device_map: serde_json::Value,
    pub image: String,
    pub prompt: String,
}

pub async fn handle_function_visual_questions_answering(
    ai_function: &AiFunction,
    chat_message: &ChatMessage,
    context: Arc<Context>,
    function_args: &Value,
) -> Result<Option<ChatMessage>> {
    let image = function_args["image"].as_str().ok_or(AppError::Casting)?;
    let prompt = function_args["prompt"].as_str().ok_or(AppError::Casting)?;
    let mut failed_connection_attempts = 0;

    loop {
        let response = function_visual_questions_answering(ai_function, image, prompt).await?;
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

async fn function_visual_questions_answering(
    ai_function: &AiFunction,
    image: &str,
    prompt: &str,
) -> Result<Option<AiFunctionResponse>> {
    let function_visual_questions_answering_post = FunctionVisualQuestionsAnsweringPost {
        device_map: ai_function.device_map.clone(),
        image: image.to_string(),
        prompt: prompt.to_string(),
    };

    if let Some(port) = ai_function.port {
        let url = format!("{BASE_AI_FUNCTION_URL}:{}/{}", port, ai_function.name);
        let response = reqwest::Client::new()
            .post(url)
            .json(&function_visual_questions_answering_post)
            .send()
            .await;

        if let Ok(response) = response {
            if response.status() == StatusCode::CREATED {
                let response = response.text().await?;

                let ai_function_response: AiFunctionResponse = AiFunctionResponse {
                    id: Uuid::new_v4(),
                    progress: 100,
                    status: AiFunctionResponseStatus::Processed,
                    response: Some(AiFunctionResponseResponse::String(response)),
                    file_attachements: vec![],
                };

                return Ok(Some(ai_function_response));
            }
        }
    }

    Ok(None)
}
