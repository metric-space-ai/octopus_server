use crate::{
    context::Context,
    entity::{
        AiFunction, AiFunctionHealthCheckStatus, AiFunctionSetupStatus, AiFunctionWarmupStatus,
        ChatMessage, ChatMessageStatus,
    },
    error::AppError,
    Result, PUBLIC_DIR,
};
use async_openai::{
    types::{
        ChatCompletionFunctionsArgs, ChatCompletionRequestMessageArgs,
        CreateChatCompletionRequestArgs, Role,
    },
    Client,
};
use axum::http::StatusCode;
use base64::{alphabet, engine, Engine};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{fs::File, io::Write, sync::Arc};
use uuid::Uuid;

mod function_bar_async;
mod function_foo_sync;
mod function_translator;

#[derive(Debug, Deserialize)]
pub struct AiFunctionResponseFileAttachement {
    pub content: String,
    pub file_name: String,
    pub media_type: String,
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
pub enum AiFunctionResponseStatus {
    Initial,
    Processed,
    Processing,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
pub enum AiFunctionResponseResponse {
    Array(Vec<String>),
    String(String),
}

#[derive(Debug, Deserialize)]
pub struct AiFunctionResponse {
    pub id: Uuid,
    pub estimated_response_at: DateTime<Utc>,
    pub progress: i32,
    pub status: AiFunctionResponseStatus,
    pub response: Option<AiFunctionResponseResponse>,
    pub file_attachements: Vec<AiFunctionResponseFileAttachement>,
}

#[derive(Debug, Deserialize)]
pub struct HealthCheckResponse {
    pub status: AiFunctionHealthCheckStatus,
}

#[derive(Debug, Serialize)]
pub struct SetupPost {
    pub force_setup: bool,
}

#[derive(Debug, Deserialize)]
pub struct SetupResponse {
    pub setup: AiFunctionSetupStatus,
}

#[derive(Debug, Deserialize)]
pub struct WarmupResponse {
    pub warmup: AiFunctionWarmupStatus,
}

pub async fn function_health_check(
    context: Arc<Context>,
    ai_function: &AiFunction,
) -> Result<AiFunction> {
    let start = Utc::now();

    let response = reqwest::Client::new()
        .get(ai_function.health_check_url.clone())
        .send()
        .await;

    let end = Utc::now();

    let health_check_execution_time = (end - start).num_seconds() as i32;

    if let Ok(response) = response {
        if response.status() == StatusCode::OK {
            let response: HealthCheckResponse = response.json().await?;

            let result = context
                .octopus_database
                .update_ai_function_health_check_status(
                    ai_function.id,
                    health_check_execution_time,
                    response.status,
                )
                .await?;

            return Ok(result);
        }
    }

    let result = context
        .octopus_database
        .update_ai_function_health_check_status(
            ai_function.id,
            health_check_execution_time,
            AiFunctionHealthCheckStatus::NotWorking,
        )
        .await?;

    Ok(result)
}

pub async fn function_prepare(
    context: Arc<Context>,
    ai_function: AiFunction,
) -> Result<AiFunction> {
    if ai_function.is_available && ai_function.is_enabled {
        let perform_health_check = match ai_function.health_check_status {
            AiFunctionHealthCheckStatus::NotWorking => true,
            AiFunctionHealthCheckStatus::Ok => {
                let mut result = false;
                let last_valid_health_check_date = Utc::now() - Duration::minutes(30);

                if let Some(health_check_at) = ai_function.health_check_at {
                    if health_check_at < last_valid_health_check_date {
                        result = true;
                    }
                }

                result
            }
        };
        let ai_function = if perform_health_check {
            function_health_check(context.clone(), &ai_function).await?
        } else {
            ai_function
        };

        let perform_setup = match ai_function.setup_status {
            AiFunctionSetupStatus::NotPerformed => true,
            AiFunctionSetupStatus::Performed => {
                let mut result = false;
                let response = reqwest::Client::new()
                    .get(format!("{}/setup", ai_function.base_function_url))
                    .send()
                    .await;

                if let Ok(response) = response {
                    if response.status() == StatusCode::OK {
                        let response: SetupResponse = response.json().await?;

                        if let AiFunctionSetupStatus::NotPerformed = response.setup {
                            result = true;
                        }
                    }
                }

                result
            }
        };

        if let AiFunctionHealthCheckStatus::Ok = ai_function.health_check_status {
            let ai_function = if perform_setup {
                function_setup(context.clone(), &ai_function).await?
            } else {
                ai_function
            };

            let perform_warmup = match ai_function.warmup_status {
                AiFunctionWarmupStatus::NotPerformed => true,
                AiFunctionWarmupStatus::Performed => {
                    let mut result = false;
                    let response = reqwest::Client::new()
                        .get(format!("{}/warmup", ai_function.base_function_url))
                        .send()
                        .await;

                    if let Ok(response) = response {
                        if response.status() == StatusCode::OK {
                            let response: WarmupResponse = response.json().await?;

                            if let AiFunctionWarmupStatus::NotPerformed = response.warmup {
                                result = true;
                            }
                        }
                    }

                    result
                }
            };

            if let AiFunctionSetupStatus::Performed = ai_function.setup_status {
                let ai_function = if perform_warmup {
                    function_warmup(context.clone(), &ai_function).await?
                } else {
                    ai_function
                };

                return Ok(ai_function);
            }

            return Ok(ai_function);
        }

        return Ok(ai_function);
    }

    Ok(ai_function)
}

pub async fn function_setup(context: Arc<Context>, ai_function: &AiFunction) -> Result<AiFunction> {
    let start = Utc::now();

    let setup_post = SetupPost { force_setup: false };
    let response = reqwest::Client::new()
        .post(format!("{}/setup", ai_function.base_function_url))
        .json(&setup_post)
        .send()
        .await;

    let end = Utc::now();
    let setup_execution_time = (end - start).num_seconds() as i32;

    if let Ok(response) = response {
        if response.status() == StatusCode::CREATED {
            let response: SetupResponse = response.json().await?;

            let result = context
                .octopus_database
                .update_ai_function_setup_status(
                    ai_function.id,
                    setup_execution_time,
                    response.setup,
                )
                .await?;

            return Ok(result);
        }
    }

    let result = context
        .octopus_database
        .update_ai_function_setup_status(
            ai_function.id,
            setup_execution_time,
            AiFunctionSetupStatus::NotPerformed,
        )
        .await?;

    Ok(result)
}

pub async fn function_status(
    ai_function: &AiFunction,
    ai_function_response: &AiFunctionResponse,
) -> Result<Option<AiFunctionResponse>> {
    let response = reqwest::Client::new()
        .get(format!(
            "{}/{}",
            ai_function.base_function_url, ai_function_response.id
        ))
        .send()
        .await;

    if let Ok(response) = response {
        if response.status() == StatusCode::OK {
            let response: AiFunctionResponse = response.json().await?;

            return Ok(Some(response));
        }
    }

    Ok(None)
}

pub async fn function_warmup(
    context: Arc<Context>,
    ai_function: &AiFunction,
) -> Result<AiFunction> {
    let start = Utc::now();

    let response = reqwest::Client::new()
        .post(format!("{}/warmup", ai_function.base_function_url))
        .send()
        .await;

    let end = Utc::now();
    let warmup_execution_time = (end - start).num_seconds() as i32;

    if let Ok(response) = response {
        if response.status() == StatusCode::CREATED {
            let response: WarmupResponse = response.json().await?;

            let result = context
                .octopus_database
                .update_ai_function_warmup_status(
                    ai_function.id,
                    warmup_execution_time,
                    response.warmup,
                )
                .await?;

            return Ok(result);
        }
    }

    let result = context
        .octopus_database
        .update_ai_function_warmup_status(
            ai_function.id,
            warmup_execution_time,
            AiFunctionWarmupStatus::NotPerformed,
        )
        .await?;

    Ok(result)
}

pub async fn open_ai_request(
    context: Arc<Context>,
    chat_message: ChatMessage,
) -> Result<ChatMessage> {
    let client = Client::new();

    let mut messages = vec![];

    let chat = context
        .octopus_database
        .try_get_chat_by_id(chat_message.chat_id)
        .await?;

    if let Some(chat) = chat {
        if chat.name.is_none() {
            context
                .octopus_database
                .update_chat(chat.id, &chat_message.message)
                .await?;
        }
    }

    let chat_messages = context
        .octopus_database
        .get_chat_messages_by_chat_id(chat_message.chat_id)
        .await?;

    for chat_message_tmp in chat_messages {
        let chat_completion_request_message = ChatCompletionRequestMessageArgs::default()
            .role(Role::User)
            .content(chat_message_tmp.message.clone())
            .build()?;

        messages.push(chat_completion_request_message);

        if let Some(response) = chat_message_tmp.response {
            let chat_completion_request_message = ChatCompletionRequestMessageArgs::default()
                .role(Role::Assistant)
                .content(response)
                .build()?;

            messages.push(chat_completion_request_message);
        }
    }

    let mut functions = vec![];

    let ai_functions = context
        .octopus_database
        .get_ai_functions_for_request()
        .await?;

    for ai_function in ai_functions {
        let function = ChatCompletionFunctionsArgs::default()
            .name(ai_function.name)
            .description(ai_function.description)
            .parameters(json!(ai_function.parameters))
            .build()?;

        functions.push(function);
    }

    if functions.is_empty() {
        let function = ChatCompletionFunctionsArgs::default()
            .name("dummy-function")
            .description("This is a dummy function that should not be used")
            .parameters(json!({
                "type": "object",
                "properties": {
                    "parameter1": {
                        "type": "string",
                        "description": "This parameter should not be used",
                    },
                    "parameter2": {
                        "type": "string",
                        "description": "This parameter should not be used",
                    },
                    "parameter3": {
                        "type": "string",
                        "description": "This parameter should not be used",
                    },
                },
                "required": ["parameter1", "parameter2", "parameter3"],
            }))
            .build()?;

        functions.push(function);
    }

    let request = CreateChatCompletionRequestArgs::default()
        .max_tokens(512u16)
        .model("gpt-3.5-turbo-0613")
        .messages(messages)
        .functions(functions)
        .function_call("auto")
        .build()?;

    let response_message = client
        .chat()
        .create(request)
        .await?
        .choices
        .get(0)
        .ok_or(AppError::BadResponse)?
        .message
        .clone();

    if let Some(function_call) = response_message.function_call {
        let function_name = function_call.name;
        let function_args: serde_json::Value = function_call.arguments.parse()?;
        let ai_function = context
            .octopus_database
            .try_get_ai_function_by_name(&function_name)
            .await?;

        if let Some(ai_function) = ai_function {
            if function_name == "function_bar_async" {
                function_bar_async::handle_function_bar_async(
                    &ai_function,
                    &chat_message,
                    context.clone(),
                    &function_args,
                )
                .await?;
            } else if function_name == "function_foo_sync" {
                function_foo_sync::handle_function_foo_sync(
                    &ai_function,
                    &chat_message,
                    context.clone(),
                    &function_args,
                )
                .await?;
            } else if function_name == "function_translator" {
                function_translator::handle_function_translator(
                    &ai_function,
                    &chat_message,
                    context.clone(),
                    &function_args,
                )
                .await?;
            }
        }
    }

    if let Some(content) = response_message.content {
        let chat_message = context
            .octopus_database
            .update_chat_message(chat_message.id, 100, &content, ChatMessageStatus::Answered)
            .await?;

        return Ok(chat_message);
    }

    Ok(chat_message)
}

pub async fn update_chat_message(
    ai_function: &AiFunction,
    ai_function_response: &AiFunctionResponse,
    context: Arc<Context>,
    chat_message: &ChatMessage,
) -> Result<ChatMessage> {
    let status = match ai_function_response.status {
        AiFunctionResponseStatus::Processed => ChatMessageStatus::Answered,
        _ => ChatMessageStatus::Asked,
    };

    let response = match ai_function_response.response.clone() {
        Some(AiFunctionResponseResponse::Array(array)) => {
            let string = array.into_iter().collect::<String>();

            Some(string)
        }
        Some(AiFunctionResponseResponse::String(string)) => Some(string),
        None => None,
    };

    let chat_message = context
        .octopus_database
        .update_chat_message_from_function(
            chat_message.id,
            ai_function.id,
            ai_function_response.estimated_response_at,
            status,
            ai_function_response.progress,
            response,
        )
        .await?;

    if !ai_function_response.file_attachements.is_empty() {
        let engine = engine::GeneralPurpose::new(&alphabet::URL_SAFE, engine::general_purpose::PAD);

        for file_attachement in &ai_function_response.file_attachements {
            let content = file_attachement
                .content
                .strip_prefix("b'")
                .ok_or(AppError::InternalError)?
                .to_string();
            let content = content.strip_suffix('\'').ok_or(AppError::InternalError)?;
            let data = engine.decode(content)?;
            let extension = (file_attachement
                .file_name
                .split('.')
                .collect::<Vec<&str>>()
                .last()
                .ok_or(AppError::File)?)
            .to_string();

            let file_name = format!("{}.{}", Uuid::new_v4(), extension);
            let path = format!("{PUBLIC_DIR}/{file_name}");

            let mut file = File::create(path)?;
            file.write_all(&data)?;

            context
                .octopus_database
                .insert_chat_message_file(chat_message.id, &file_name, &file_attachement.media_type)
                .await?;
        }
    }

    Ok(chat_message)
}
