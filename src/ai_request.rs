use crate::{
    context::Context,
    entity::{AiFunction, ChatMessage, ChatMessageStatus},
    error::AppError,
    Result,
};
use async_openai::{
    types::{
        ChatCompletionFunctionsArgs, ChatCompletionRequestMessageArgs,
        CreateChatCompletionRequestArgs, Role,
    },
    Client,
};
use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use tokio::time::{sleep, Duration};
use uuid::Uuid;

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

#[derive(Debug, Deserialize)]
pub struct AiFunctionResponse {
    pub id: Uuid,
    pub estimated_response_at: DateTime<Utc>,
    pub progress: i32,
    pub status: AiFunctionResponseStatus,
    pub response: Option<String>,
    pub file_attachements: Vec<AiFunctionResponseFileAttachement>,
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
                let value1 = function_args["value1"].as_str().ok_or(AppError::Casting)?;
                let value2 = function_args["value2"].as_str().ok_or(AppError::Casting)?;

                let response = function_bar_async(&ai_function, value1, value2).await?;

                if let Some(response) = response {
                    let mut chat_message =
                        update_chat_message(&response, context.clone(), &chat_message).await?;

                    loop {
                        let response = check_function_status(&ai_function, &response).await?;

                        if let Some(response) = response {
                            chat_message =
                                update_chat_message(&response, context.clone(), &chat_message)
                                    .await?;

                            loop {
                                let now = Utc::now();
                                if now > response.estimated_response_at {
                                    break;
                                }
                                sleep(Duration::from_secs(1)).await;
                            }

                            if response.status == AiFunctionResponseStatus::Processed {
                                break;
                            }
                        }
                    }
                }
            } else if function_name == "function_foo_sync" {
                let value1 = function_args["value1"].as_str().ok_or(AppError::Casting)?;
                let value2 = function_args["value2"].as_str().ok_or(AppError::Casting)?;

                let response = function_foo_sync(&ai_function, value1, value2).await?;

                if let Some(response) = response {
                    let mut chat_message =
                        update_chat_message(&response, context.clone(), &chat_message).await?;

                    loop {
                        let response = check_function_status(&ai_function, &response).await?;

                        if let Some(response) = response {
                            chat_message =
                                update_chat_message(&response, context.clone(), &chat_message)
                                    .await?;

                            loop {
                                let now = Utc::now();
                                if now > response.estimated_response_at {
                                    break;
                                }
                                sleep(Duration::from_secs(1)).await;
                            }

                            if response.status == AiFunctionResponseStatus::Processed {
                                break;
                            }
                        }
                    }
                }
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

async fn check_function_status(
    ai_function: &AiFunction,
    ai_function_response: &AiFunctionResponse,
) -> Result<Option<AiFunctionResponse>> {
    let response = reqwest::Client::new()
        .get(format!(
            "{}/{}",
            ai_function.base_function_url, ai_function_response.id
        ))
        .send()
        .await?;

    if response.status() == StatusCode::OK {
        let response: AiFunctionResponse = response.json().await?;

        return Ok(Some(response));
    }

    Ok(None)
}

#[derive(Debug, Serialize)]
pub struct FunctionFooAsyncPost {
    pub value1: String,
    pub value2: String,
}

async fn function_bar_async(
    ai_function: &AiFunction,
    value1: &str,
    value2: &str,
) -> Result<Option<AiFunctionResponse>> {
    let function_bar_async_post = FunctionFooAsyncPost {
        value1: value1.to_string(),
        value2: value2.to_string(),
    };

    let response = reqwest::Client::new()
        .post(ai_function.base_function_url.clone())
        .json(&function_bar_async_post)
        .send()
        .await?;

    if response.status() == StatusCode::CREATED {
        let response: AiFunctionResponse = response.json().await?;

        return Ok(Some(response));
    }

    Ok(None)
}

#[derive(Debug, Serialize)]
pub struct FunctionFooSyncPost {
    pub value1: String,
    pub value2: String,
}

async fn function_foo_sync(
    ai_function: &AiFunction,
    value1: &str,
    value2: &str,
) -> Result<Option<AiFunctionResponse>> {
    let function_foo_sync_post = FunctionFooSyncPost {
        value1: value1.to_string(),
        value2: value2.to_string(),
    };

    let response = reqwest::Client::new()
        .post(ai_function.base_function_url.clone())
        .json(&function_foo_sync_post)
        .send()
        .await?;

    if response.status() == StatusCode::CREATED {
        let response: AiFunctionResponse = response.json().await?;

        return Ok(Some(response));
    }

    Ok(None)
}

async fn update_chat_message(
    ai_function_response: &AiFunctionResponse,
    context: Arc<Context>,
    chat_message: &ChatMessage,
) -> Result<ChatMessage> {
    let status = match ai_function_response.status {
        AiFunctionResponseStatus::Processed => ChatMessageStatus::Answered,
        _ => ChatMessageStatus::Asked,
    };

    let chat_message = context
        .octopus_database
        .update_chat_message_full(
            chat_message.id,
            ai_function_response.estimated_response_at,
            &chat_message.message,
            status,
            ai_function_response.progress,
            ai_function_response.response.clone(),
        )
        .await?;

    Ok(chat_message)
}
