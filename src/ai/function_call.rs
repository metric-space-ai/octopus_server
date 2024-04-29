use crate::{
    ai::{service::service_health_check, BASE_AI_FUNCTION_URL, PUBLIC_DIR},
    context::Context,
    entity::{
        AiFunction, AiFunctionResponseContentType, AiService, ChatMessage, ChatMessageStatus,
    },
    error::AppError,
    Result,
};
use async_recursion::async_recursion;
use base64::{alphabet, engine, Engine};
use reqwest::{header::CONTENT_TYPE, StatusCode};
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
    Mixed(Vec<AiFunctionResponse>),
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
    pub original_file_name: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
pub struct AiFunctionTextResponse {
    pub response: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
pub struct ResponseText {
    pub file_attachments: Option<Vec<FileAttachmentResponse>>,
    pub response: Option<TextResponse>,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
pub struct FileAttachmentResponse {
    pub content: String,
    pub file_name: String,
    pub media_type: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
#[serde(untagged)]
pub enum TextResponse {
    Array(Vec<String>),
    String(String),
}

#[allow(clippy::module_name_repetitions)]
pub async fn handle_function_call(
    ai_function: &AiFunction,
    ai_service: &AiService,
    chat_message: &ChatMessage,
    context: Arc<Context>,
    function_args: &Value,
) -> Result<ChatMessage> {
    let mut failed_connection_attempts = 0;

    loop {
        let response = function_call(ai_function, ai_service, function_args).await?;

        if let Some(response) = response {
            let chat_message =
                update_chat_message(ai_function, &response, context.clone(), chat_message).await?;

            return Ok(chat_message);
        }

        failed_connection_attempts += 1;

        if failed_connection_attempts > 10 {
            service_health_check(ai_service.id, context.clone(), ai_service.port).await?;

            break;
        }

        sleep(Duration::from_secs(2)).await;
    }

    Ok(chat_message.clone())
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
                    let mut ai_function_responses = vec![];

                    let response_text = response.text().await?;
                    let response: ResponseText = serde_json::from_str(&response_text)?;

                    let response_str = match response.response {
                        Some(TextResponse::Array(array)) => {
                            let string = array.into_iter().collect::<String>();

                            Some(string)
                        }
                        Some(TextResponse::String(string)) => Some(string),
                        None => None,
                    };

                    if let Some(response_str) = response_str {
                        let ai_function_text_response = AiFunctionTextResponse {
                            response: Some(response_str),
                        };

                        let ai_function_response =
                            AiFunctionResponse::Text(ai_function_text_response);
                        ai_function_responses.push(ai_function_response);
                    }

                    if let Some(file_attachments) = response.file_attachments {
                        for file_attachment in file_attachments {
                            let ai_function_file_response = AiFunctionFileResponse {
                                content: file_attachment.content,
                                media_type: file_attachment.media_type,
                                original_file_name: Some(file_attachment.file_name),
                            };
                            let ai_function_response =
                                AiFunctionResponse::File(ai_function_file_response);

                            ai_function_responses.push(ai_function_response);
                        }
                    }

                    AiFunctionResponse::Mixed(ai_function_responses)
                }
                AiFunctionResponseContentType::TextHtml => {
                    let content = response.text().await?;
                    let media_type = "text/html".to_string();

                    let engine = engine::GeneralPurpose::new(
                        &alphabet::URL_SAFE,
                        engine::general_purpose::PAD,
                    );
                    let content = engine.encode(content);

                    let ai_function_file_response = AiFunctionFileResponse {
                        content,
                        media_type,
                        original_file_name: None,
                    };

                    AiFunctionResponse::File(ai_function_file_response)
                }
                AiFunctionResponseContentType::TextPlain => {
                    let response = response.text().await?;

                    let ai_function_text_response = AiFunctionTextResponse {
                        response: Some(response),
                    };

                    AiFunctionResponse::Text(ai_function_text_response)
                }
                AiFunctionResponseContentType::ApplicationPdf
                | AiFunctionResponseContentType::AudioMpeg
                | AiFunctionResponseContentType::ImageJpeg
                | AiFunctionResponseContentType::ImagePng
                | AiFunctionResponseContentType::VideoMp4 => {
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
                        original_file_name: None,
                    };

                    AiFunctionResponse::File(ai_function_file_response)
                }
            };

            return Ok(Some(ai_function_response));
        }

        let response = response.text().await?;

        let ai_function_error_response = AiFunctionErrorResponse {
            error: Some(response),
        };

        return Ok(Some(AiFunctionResponse::Error(ai_function_error_response)));
    }

    Ok(None)
}

#[async_recursion]
pub async fn update_chat_message(
    ai_function: &AiFunction,
    ai_function_response: &AiFunctionResponse,
    context: Arc<Context>,
    chat_message: &ChatMessage,
) -> Result<ChatMessage> {
    let mut transaction = context.octopus_database.transaction_begin().await?;

    match ai_function_response {
        AiFunctionResponse::Error(ai_function_error_response) => {
            let chat_message = context
                .octopus_database
                .update_chat_message_from_function_error(
                    &mut transaction,
                    chat_message.id,
                    ai_function.id,
                    ai_function_error_response.error.clone(),
                    ChatMessageStatus::Answered,
                    100,
                )
                .await?;

            context
                .octopus_database
                .transaction_commit(transaction)
                .await?;

            Ok(chat_message)
        }
        AiFunctionResponse::File(ai_function_file_response) => {
            let chat_message = context
                .octopus_database
                .update_chat_message_from_function_status(
                    &mut transaction,
                    chat_message.id,
                    ai_function.id,
                    ChatMessageStatus::Answered,
                    100,
                )
                .await?;

            let mut data = None;

            let engine =
                engine::GeneralPurpose::new(&alphabet::URL_SAFE, engine::general_purpose::PAD);
            let result = engine.decode(ai_function_file_response.content.clone());

            if let Ok(result) = result {
                data = Some(result);
            }

            if data.is_none() {
                let engine =
                    engine::GeneralPurpose::new(&alphabet::STANDARD, engine::general_purpose::PAD);
                let result = engine.decode(ai_function_file_response.content.clone());

                if let Ok(result) = result {
                    data = Some(result);
                }
            }

            if let Some(data) = data {
                let mut extension = None;
                let kind = infer::get(&data).ok_or(AppError::File);
                if let Ok(kind) = kind {
                    extension = Some(kind.extension());
                }

                if extension.is_none() && data.len() >= 4 {
                    if data[0] == 103 && data[1] == 108 && data[2] == 84 && data[3] == 70 {
                        extension = Some("glb");
                    } else if data[0] == 25 && data[1] == 50 && data[2] == 44 && data[3] == 46 {
                        extension = Some("pdf");
                    } else {
                        extension = Some("txt");
                    }
                } else if extension.is_none() {
                    extension = Some("txt");
                }

                if let Some(extension) = extension {
                    let file_name = format!("{}.{}", Uuid::new_v4(), extension);
                    let path = format!("{PUBLIC_DIR}/{file_name}");
                    let mut file = File::create(path)?;
                    file.write_all(&data)?;

                    context
                        .octopus_database
                        .insert_chat_message_file(
                            &mut transaction,
                            chat_message.id,
                            &file_name,
                            &ai_function_file_response.media_type,
                            ai_function_file_response.original_file_name.clone(),
                        )
                        .await?;
                }
            }

            context
                .octopus_database
                .transaction_commit(transaction)
                .await?;

            Ok(chat_message)
        }
        AiFunctionResponse::Mixed(ai_function_responses) => {
            let mut chat_message = chat_message.clone();
            for ai_function_response_tmp in ai_function_responses {
                chat_message = update_chat_message(
                    ai_function,
                    ai_function_response_tmp,
                    context.clone(),
                    &chat_message,
                )
                .await?;
            }

            Ok(chat_message)
        }
        AiFunctionResponse::Text(ai_function_text_response) => {
            let chat_message = context
                .octopus_database
                .update_chat_message_from_function(
                    &mut transaction,
                    chat_message.id,
                    ai_function.id,
                    ChatMessageStatus::Answered,
                    100,
                    ai_function_text_response.response.clone(),
                )
                .await?;

            context
                .octopus_database
                .transaction_commit(transaction)
                .await?;

            Ok(chat_message)
        }
    }
}
