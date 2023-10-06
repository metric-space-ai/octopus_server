use crate::{
    ai::{service_health_check, BASE_AI_FUNCTION_URL, PUBLIC_DIR},
    context::Context,
    entity::{
        AiFunction, AiFunctionResponseContentType, AiService, ChatMessage, ChatMessageStatus,
    },
    error::AppError,
    Result,
};
use axum::http::StatusCode;
use base64::{alphabet, engine, Engine};
use http::header::CONTENT_TYPE;
use serde::{Deserialize, Serialize};
use serde_json::value::Value;
use std::{fs::File, io::Write, sync::Arc};
use tokio::time::{sleep, Duration};
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
pub enum AiFunctionResponse {
    Error(AiFunctionErrorResponse),
    File(AiFunctionFileResponse),
    Text(AiFunctionTextResponse),
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
pub struct AiFunctionErrorResponse {
    pub error: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
pub struct AiFunctionFileResponse {
    pub content: String,
    pub media_type: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
pub struct AiFunctionTextResponse {
    pub response: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
pub struct ResponseText {
    pub response: Option<ResponseTextResponse>,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
#[serde(untagged)]
pub enum ResponseTextResponse {
    Array(Vec<String>),
    String(String),
}

pub async fn handle_function_call(
    ai_function: &AiFunction,
    ai_service: &AiService,
    chat_message: &ChatMessage,
    context: Arc<Context>,
    function_args: &Value,
) -> Result<Option<ChatMessage>> {
    let mut failed_connection_attempts = 0;

    loop {
        let response = function_call(ai_function, ai_service, function_args).await?;

        if let Some(response) = response {
            let chat_message =
                update_chat_message(ai_function, &response, context.clone(), chat_message).await?;

            return Ok(Some(chat_message));
        } else {
            failed_connection_attempts += 1;

            if failed_connection_attempts > 10 {
                service_health_check(ai_service.id, context.clone(), ai_service.port).await?;

                break;
            }

            sleep(Duration::from_secs(2)).await;
        }
    }

    Ok(None)
}

pub async fn function_call(
    ai_function: &AiFunction,
    ai_service: &AiService,
    function_args: &Value,
) -> Result<Option<AiFunctionResponse>> {
    let url = format!(
        "{BASE_AI_FUNCTION_URL}:{}/{}",
        ai_service.port, ai_function.name
    );

    let response = reqwest::Client::new()
        .post(url)
        .json(&function_args)
        .send()
        .await;

    if let Ok(response) = response {
        if response.status() == StatusCode::CREATED {
            let ai_function_response = match ai_function.response_content_type {
                AiFunctionResponseContentType::ApplicationJson => {
                    let response_text = response.text().await?;
                    let response: ResponseText = serde_json::from_str(&response_text)?;

                    let response = match response.response {
                        Some(ResponseTextResponse::Array(array)) => {
                            let string = array.into_iter().collect::<String>();

                            Some(string)
                        }
                        Some(ResponseTextResponse::String(string)) => Some(string),
                        None => Some(response_text),
                    };

                    let ai_function_text_response = AiFunctionTextResponse { response };

                    AiFunctionResponse::Text(ai_function_text_response)
                }
                AiFunctionResponseContentType::TextPlain => {
                    let response = response.text().await?;

                    let ai_function_text_response = AiFunctionTextResponse {
                        response: Some(response),
                    };

                    AiFunctionResponse::Text(ai_function_text_response)
                }
                AiFunctionResponseContentType::ImageJpeg
                | AiFunctionResponseContentType::ImagePng => {
                    let headers_map = response.headers();
                    let content_type_header =
                        headers_map.get(CONTENT_TYPE).ok_or(AppError::File)?;
                    let media_type = content_type_header.to_str()?.to_string();
                    let content = response.bytes().await?;

                    let engine = engine::GeneralPurpose::new(
                        &alphabet::URL_SAFE,
                        engine::general_purpose::PAD,
                    );
                    let content = engine.encode(content);

                    let ai_function_file_response = AiFunctionFileResponse {
                        content,
                        media_type,
                    };

                    AiFunctionResponse::File(ai_function_file_response)
                }
            };

            return Ok(Some(ai_function_response));
        } else {
            let response = response.text().await?;

            let ai_function_error_response = AiFunctionErrorResponse {
                error: Some(response),
            };

            return Ok(Some(AiFunctionResponse::Error(ai_function_error_response)));
        }
    }

    Ok(None)
}

pub async fn update_chat_message(
    ai_function: &AiFunction,
    ai_function_response: &AiFunctionResponse,
    context: Arc<Context>,
    chat_message: &ChatMessage,
) -> Result<ChatMessage> {
    match ai_function_response {
        AiFunctionResponse::Error(ai_function_error_response) => {
            let chat_message = context
                .octopus_database
                .update_chat_message_from_function_error(
                    chat_message.id,
                    ai_function.id,
                    ai_function_error_response.error.clone(),
                    ChatMessageStatus::Answered,
                    100,
                )
                .await?;

            Ok(chat_message)
        }
        AiFunctionResponse::File(ai_function_file_response) => {
            let chat_message = context
                .octopus_database
                .update_chat_message_from_function(
                    chat_message.id,
                    ai_function.id,
                    ChatMessageStatus::Answered,
                    100,
                    None,
                )
                .await?;

            let engine =
                engine::GeneralPurpose::new(&alphabet::URL_SAFE, engine::general_purpose::PAD);
            let data = engine.decode(ai_function_file_response.content.clone())?;

            let kind = infer::get(&data).ok_or(AppError::File)?;
            let extension = kind.extension();

            let file_name = format!("{}.{}", Uuid::new_v4(), extension);
            let path = format!("{PUBLIC_DIR}/{file_name}");

            let mut file = File::create(path)?;
            file.write_all(&data)?;

            context
                .octopus_database
                .insert_chat_message_file(
                    chat_message.id,
                    &file_name,
                    &ai_function_file_response.media_type,
                )
                .await?;

            Ok(chat_message)
        }
        AiFunctionResponse::Text(ai_function_text_response) => {
            let chat_message = context
                .octopus_database
                .update_chat_message_from_function(
                    chat_message.id,
                    ai_function.id,
                    ChatMessageStatus::Answered,
                    100,
                    ai_function_text_response.response.clone(),
                )
                .await?;

            Ok(chat_message)
        }
    }
}
