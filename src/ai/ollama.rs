use crate::{
    ai::{self, ChatAuditTrail},
    context::Context,
    entity::{ChatMessage, ChatMessageStatus, User},
    error::AppError,
    get_pwd, Result,
};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use sqlx::{Postgres, Transaction};
use std::{fs::read_to_string, path::Path, sync::Arc};
use tokio::time::Duration;

pub const MAIN_LLM_OLLAMA_MODEL: &str = "llama3:70b";

#[derive(Debug, Deserialize, Serialize)]
pub struct ChatRequest {
    pub messages: Vec<Message>,
    pub model: String,
    pub stream: bool,
}

#[derive(Serialize, Deserialize)]
struct ChatResponse {
    created_at: String,
    done: bool,
    eval_count: i64,
    eval_duration: i64,
    load_duration: i64,
    message: Message,
    model: String,
    prompt_eval_count: i64,
    prompt_eval_duration: i64,
    total_duration: i64,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Message {
    pub content: String,
    pub role: String,
}

pub async fn get_messages(
    context: Arc<Context>,
    transaction: &mut Transaction<'_, Postgres>,
    chat_message: &ChatMessage,
) -> Result<Vec<Message>> {
    let mut chat_audit_trails = vec![];
    let mut messages = vec![];

    let ai_system_prompt = context.get_config().await?.get_parameter_ai_system_prompt();

    if let Some(ai_system_prompt) = ai_system_prompt {
        let message = Message {
            content: ai_system_prompt,
            role: "system".to_string(),
        };

        messages.push(message);
    }

    let chat_messages = context
        .octopus_database
        .get_chat_messages_extended_by_chat_id(chat_message.chat_id)
        .await?;

    for chat_message_tmp in chat_messages {
        if !chat_message_tmp.is_sensitive
            || chat_message.is_anonymized
            || chat_message.is_marked_as_not_sensitive
        {
            let suggested_ai_function_id = chat_message.suggested_ai_function_id;
            let suggested_ai_function =
                if let Some(suggested_ai_function_id) = suggested_ai_function_id {
                    context
                        .octopus_database
                        .try_get_ai_function_by_id(suggested_ai_function_id)
                        .await?
                } else {
                    None
                };

            if let Some(suggested_ai_function) = suggested_ai_function {
                let suggested_ai_function_message = format!("User wants to trigger {} function for the next request. Try to match the arguments and make a function call.", suggested_ai_function.name);

                let message = Message {
                    content: suggested_ai_function_message.clone(),
                    role: "system".to_string(),
                };

                messages.push(message);

                let chat_audit_trail = ChatAuditTrail {
                    id: chat_message_tmp.id,
                    content: suggested_ai_function_message,
                    role: "system".to_string(),
                    created_at: chat_message_tmp.created_at,
                };
                chat_audit_trails.push(chat_audit_trail);
            }

            let message = Message {
                content: chat_message_tmp.message.clone(),
                role: "user".to_string(),
            };

            messages.push(message);

            let chat_audit_trail = ChatAuditTrail {
                id: chat_message_tmp.id,
                content: chat_message_tmp.message.clone(),
                role: "user".to_string(),
                created_at: chat_message_tmp.created_at,
            };
            chat_audit_trails.push(chat_audit_trail);

            if let Some(response) = chat_message_tmp.response {
                let message = Message {
                    content: response.clone(),
                    role: "assistant".to_string(),
                };

                messages.push(message);

                let chat_audit_trail = ChatAuditTrail {
                    id: chat_message_tmp.id,
                    content: response,
                    role: "assistant".to_string(),
                    created_at: chat_message_tmp.created_at,
                };
                chat_audit_trails.push(chat_audit_trail);
            }

            if !chat_message_tmp.chat_message_files.is_empty() {
                let mut urls = String::new();
                let octopus_api_url = context.get_config().await?.get_parameter_octopus_api_url();

                if let Some(octopus_api_url) = octopus_api_url {
                    let api_url = if octopus_api_url.ends_with('/') {
                        octopus_api_url
                            .strip_suffix('/')
                            .ok_or(AppError::Parsing)?
                            .to_string()
                    } else {
                        octopus_api_url
                    };

                    for chat_message_file in &chat_message_tmp.chat_message_files {
                        urls.push_str(&format!("{api_url}/{} ", chat_message_file.file_name));
                    }
                }

                if !urls.is_empty() {
                    let message = Message {
                        content: urls.clone(),
                        role: "user".to_string(),
                    };

                    messages.push(message);

                    let chat_audit_trail = ChatAuditTrail {
                        id: chat_message_tmp.id,
                        content: urls,
                        role: "user".to_string(),
                        created_at: chat_message_tmp.created_at,
                    };
                    chat_audit_trails.push(chat_audit_trail);
                };
            }

            if !chat_message_tmp.chat_message_files.is_empty() {
                for chat_message_file in chat_message_tmp.chat_message_files {
                    let pwd = get_pwd()?;
                    let file_path = format!("{pwd}/{}", chat_message_file.file_name);

                    if chat_message_file.media_type == "text/plain" {
                        let file_exists = Path::new(&file_path).is_file();
                        if file_exists {
                            let content = read_to_string(file_path)?;

                            let message = Message {
                                content: content.clone(),
                                role: "user".to_string(),
                            };

                            messages.push(message);

                            let chat_audit_trail = ChatAuditTrail {
                                id: chat_message_tmp.id,
                                content,
                                role: "user".to_string(),
                                created_at: chat_message_tmp.created_at,
                            };
                            chat_audit_trails.push(chat_audit_trail);
                        }
                    }
                }
            }
        }
    }

    let trail = serde_json::to_value(&chat_audit_trails)?;

    context
        .octopus_database
        .insert_chat_audit(
            transaction,
            chat_message.chat_id,
            chat_message.id,
            chat_message.user_id,
            trail,
        )
        .await?;

    Ok(messages)
}

pub async fn ollama_request(
    context: Arc<Context>,
    chat_message: ChatMessage,
    user: User,
) -> Result<ChatMessage> {
    let main_llm_ollama_model = context
        .get_config()
        .await?
        .get_parameter_main_llm_ollama_model()
        .unwrap_or(MAIN_LLM_OLLAMA_MODEL.to_string());

    let ollama_host = context
        .get_config()
        .await?
        .ollama_host
        .unwrap_or("http://localhost:11434".to_string());

    let mut transaction = context.octopus_database.transaction_begin().await?;

    ai::update_chat_name(context.clone(), &mut transaction, &chat_message).await?;

    let chat_message = ai::check_sensitive_information_service(
        context.clone(),
        &mut transaction,
        &chat_message,
        user.id,
    )
    .await?;

    if chat_message.status == ChatMessageStatus::Answered {
        context
            .octopus_database
            .transaction_commit(transaction)
            .await?;

        return Ok(chat_message);
    }

    let messages = get_messages(context.clone(), &mut transaction, &chat_message).await?;

    if !context.get_config().await?.test_mode {
        let chat_request = ChatRequest {
            messages,
            model: main_llm_ollama_model.to_string(),
            stream: false,
        };

        let url = format!("{ollama_host}/api/chat");

        let response = reqwest::ClientBuilder::new()
            .connect_timeout(Duration::from_secs(60))
            .build()?
            .post(url)
            .json(&chat_request)
            .send()
            .await;

        match response {
            Err(e) => {
                let response = format!("OllamaError: {e}");
                let chat_message = context
                    .octopus_database
                    .update_chat_message(
                        &mut transaction,
                        chat_message.id,
                        100,
                        &response,
                        ChatMessageStatus::Answered,
                    )
                    .await?;

                context
                    .octopus_database
                    .transaction_commit(transaction)
                    .await?;

                return Ok(chat_message);
            }
            Ok(response) => {
                if response.status() == StatusCode::CREATED || response.status() == StatusCode::OK {
                    let response_text = response.text().await?;
                    let chat_response: ChatResponse = serde_json::from_str(&response_text)?;

                    let chat_message = context
                        .octopus_database
                        .update_chat_message(
                            &mut transaction,
                            chat_message.id,
                            100,
                            &chat_response.message.content,
                            ChatMessageStatus::Answered,
                        )
                        .await?;

                    context
                        .octopus_database
                        .transaction_commit(transaction)
                        .await?;

                    return Ok(chat_message);
                } else {
                    let response = response.text().await?;

                    let response = format!("OllamaError: {response}");
                    let chat_message = context
                        .octopus_database
                        .update_chat_message(
                            &mut transaction,
                            chat_message.id,
                            100,
                            &response,
                            ChatMessageStatus::Answered,
                        )
                        .await?;

                    context
                        .octopus_database
                        .transaction_commit(transaction)
                        .await?;

                    return Ok(chat_message);
                }
            }
        }
    }

    context
        .octopus_database
        .transaction_commit(transaction)
        .await?;

    Ok(chat_message)
}
