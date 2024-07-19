use crate::{
    ai::{self, function_call, internal_function_call, AiFunctionCall, ChatAuditTrail},
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
use uuid::Uuid;

pub const MAIN_LLM_ANTHROPIC_MODEL: &str = "claude-3-opus-20240229";

#[derive(Debug, Deserialize, Serialize)]
pub struct ChatRequest {
    pub max_tokens: u16,
    pub messages: Vec<Message>,
    pub model: String,
    pub stream: bool,
    pub tools: Option<Vec<Tool>>,
}

#[derive(Debug, Deserialize, Serialize)]
struct ChatResponse {
    id: String,
    content: Vec<Content>,
    model: String,
    role: String,
    stop_reason: String,
    stop_sequence: (),
    r#type: String,
    usage: Usage,
}

#[derive(Debug, Deserialize, Serialize)]
struct Content {
    id: Option<String>,
    input: Option<serde_json::Value>,
    name: Option<String>,
    text: Option<String>,
    r#type: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Message {
    pub content: String,
    pub role: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct Usage {
    input_tokens: i64,
    output_tokens: i64,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Tool {
    pub description: String,
    pub input_schema: serde_json::Value,
    pub name: String,
}

pub async fn get_messages(
    context: Arc<Context>,
    transaction: &mut Transaction<'_, Postgres>,
    chat_message: &ChatMessage,
) -> Result<Vec<Message>> {
    let mut chat_audit_trails = vec![];
    let mut messages = vec![];

    let ai_system_prompt = context
        .get_config()
        .await?
        .get_parameter_main_llm_system_prompt();

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

pub async fn get_tools_ai_functions(context: Arc<Context>, user_id: Uuid) -> Result<Vec<Tool>> {
    let mut tools = vec![];

    let ai_functions = context
        .octopus_database
        .get_ai_functions_for_request(user_id)
        .await?;

    for ai_function in ai_functions {
        if ai_function.formatted_name != "anonymization"
            && ai_function.formatted_name != "google_search"
            && ai_function.formatted_name != "querycontent"
            && ai_function.formatted_name != "scrape_url"
            && ai_function.formatted_name != "sensitive_information"
        {
            let description = ai_function
                .generated_description
                .unwrap_or(ai_function.description);

            let tool = Tool {
                description,
                input_schema: ai_function.parameters,
                name: ai_function.name,
            };

            tools.push(tool);
        }
    }

    Ok(tools)
}

pub async fn get_tools_all(context: Arc<Context>, user_id: Uuid) -> Result<Vec<Tool>> {
    let mut tools = vec![];

    let mut internal_functions_tools = get_tools_internal_functions().await?;
    tools.append(&mut internal_functions_tools);

    let mut ai_functions_tools = get_tools_ai_functions(context.clone(), user_id).await?;
    tools.append(&mut ai_functions_tools);

    let mut simple_apps_tools = get_tools_simple_apps(context.clone()).await?;
    tools.append(&mut simple_apps_tools);

    let mut wasp_apps_tools = get_tools_wasp_apps(context.clone(), user_id).await?;
    tools.append(&mut wasp_apps_tools);

    Ok(tools)
}

pub async fn get_tools_internal_functions() -> Result<Vec<Tool>> {
    let mut tools = vec![];

    let input_schema = r#"{
        "type": "object",
        "properties": {},
        "required": []
    }"#;
    let tool = Tool {
        description: "List user files function returns a comma-separated list of the files that belong to the user.".to_string(),
        input_schema: serde_json::from_str(input_schema)?,
        name: "os_internal_list_user_files".to_string(),
    };

    tools.push(tool);

    Ok(tools)
}

pub async fn get_tools_simple_apps(context: Arc<Context>) -> Result<Vec<Tool>> {
    let mut tools = vec![];

    let simple_apps = context
        .octopus_database
        .get_simple_apps_for_request()
        .await?;

    for simple_app in simple_apps {
        let input_schema = r#"{
            "type": "object",
            "properties": {
                "title": {
                    "type": "string",
                    "description": "Simple app title"
                }
            },
            "required": ["title"]
        }"#;
        let tool = Tool {
            description: simple_app.description,
            input_schema: serde_json::from_str(input_schema)?,
            name: simple_app.formatted_name,
        };

        tools.push(tool);
    }

    Ok(tools)
}

pub async fn get_tools_wasp_apps(context: Arc<Context>, user_id: Uuid) -> Result<Vec<Tool>> {
    let mut tools = vec![];

    let wasp_apps = context
        .octopus_database
        .get_wasp_apps_for_request(user_id)
        .await?;

    for wasp_app in wasp_apps {
        let input_schema = r#"{
            "type": "object",
            "properties": {
                "title": {
                    "type": "string",
                    "description": "Wasp app title"
                }
            },
            "required": ["title"]
        }"#;
        let tool = Tool {
            description: wasp_app.description,
            input_schema: serde_json::from_str(input_schema)?,
            name: wasp_app.formatted_name,
        };

        tools.push(tool);
    }

    Ok(tools)
}

pub async fn anthropic_request(
    context: Arc<Context>,
    chat_message: ChatMessage,
    user: User,
) -> Result<ChatMessage> {
    let main_llm_anthropic_api_key = context
        .get_config()
        .await?
        .get_parameter_main_llm_anthropic_api_key()
        .ok_or(AppError::Config)?;
    let main_llm_anthropic_model = context
        .get_config()
        .await?
        .get_parameter_main_llm_anthropic_model()
        .unwrap_or(MAIN_LLM_ANTHROPIC_MODEL.to_string());

    let mut transaction = context.octopus_database.transaction_begin().await?;

    let chat_message = context
        .octopus_database
        .update_chat_message_llm_model(
            &mut transaction,
            chat_message.id,
            Some("anthropic".to_string()),
            Some(main_llm_anthropic_model.clone()),
        )
        .await?;

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
        let tools = get_tools_all(context.clone(), user.id).await?;

        let mut chat_request = ChatRequest {
            max_tokens: 4096,
            messages,
            model: main_llm_anthropic_model.to_string(),
            stream: false,
            tools: None,
        };

        if !tools.is_empty() {
            chat_request.tools = Some(tools);
        }

        let response = reqwest::ClientBuilder::new()
            .connect_timeout(Duration::from_secs(60))
            .build()?
            .post("https://api.anthropic.com/v1/messages")
            .header(
                reqwest::header::CONTENT_TYPE,
                mime::APPLICATION_JSON.as_ref(),
            )
            .header("x-api-key".to_string(), main_llm_anthropic_api_key)
            .header("anthropic-beta".to_string(), "tools-2024-04-04".to_string())
            .header("anthropic-version".to_string(), "2023-06-01".to_string())
            .json(&chat_request)
            .send()
            .await;

        match response {
            Err(e) => {
                let response = format!("AnthropicError: {e}");
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

                    let content = chat_response.content.last();

                    match content {
                        None => {
                            let response = "BadResponse";
                            context
                                .octopus_database
                                .update_chat_message(
                                    &mut transaction,
                                    chat_message.id,
                                    100,
                                    response,
                                    ChatMessageStatus::Answered,
                                )
                                .await?;

                            context
                                .octopus_database
                                .transaction_commit(transaction)
                                .await?;

                            return Ok(chat_message);
                        }
                        Some(content) => {
                            if content.r#type == "text" {
                                if let Some(text) = content.text.clone() {
                                    let chat_message = context
                                        .octopus_database
                                        .update_chat_message(
                                            &mut transaction,
                                            chat_message.id,
                                            100,
                                            &text,
                                            ChatMessageStatus::Answered,
                                        )
                                        .await?;

                                    context
                                        .octopus_database
                                        .transaction_commit(transaction)
                                        .await?;

                                    return Ok(chat_message);
                                }
                            } else if content.r#type == "tool_use" {
                                if let (Some(function_args), Some(function_name)) =
                                    (content.input.clone(), content.name.clone())
                                {
                                    let ai_function_call = AiFunctionCall {
                                        arguments: function_args.clone(),
                                        name: function_name.clone(),
                                    };
                                    let ai_function_call = serde_json::to_value(ai_function_call)?;
                                    let chat_message = context
                                        .octopus_database
                                        .update_chat_message_ai_function_call(
                                            &mut transaction,
                                            chat_message.id,
                                            ai_function_call,
                                        )
                                        .await?;

                                    if function_name.starts_with("os_internal_") {
                                        context
                                            .octopus_database
                                            .transaction_commit(transaction)
                                            .await?;

                                        let chat_message =
                                            internal_function_call::handle_internal_function_call(
                                                &chat_message,
                                                context.clone(),
                                                &function_args,
                                                &function_name,
                                            )
                                            .await?;

                                        return Ok(chat_message);
                                    }

                                    let ai_function = context
                                        .octopus_database
                                        .try_get_ai_function_by_name(&function_name)
                                        .await?;

                                    let ai_function = if let Some(ai_function) = ai_function {
                                        Some(ai_function)
                                    } else {
                                        context
                                            .octopus_database
                                            .try_get_ai_function_by_formatted_name(&function_name)
                                            .await?
                                    };

                                    let ai_function = if let Some(ai_function) = ai_function {
                                        Some(ai_function)
                                    } else {
                                        let new_function_name = function_name.replace('-', "_");
                                        context
                                            .octopus_database
                                            .try_get_ai_function_by_formatted_name(
                                                &new_function_name,
                                            )
                                            .await?
                                    };

                                    if let Some(ai_function) = ai_function {
                                        let ai_service = context
                                            .octopus_database
                                            .try_get_ai_service_by_id(ai_function.ai_service_id)
                                            .await?;

                                        if let Some(ai_service) = ai_service {
                                            context
                                                .octopus_database
                                                .transaction_commit(transaction)
                                                .await?;

                                            let chat_message = function_call::handle_function_call(
                                                &ai_function,
                                                &ai_service,
                                                &chat_message,
                                                context.clone(),
                                                &function_args,
                                            )
                                            .await?;

                                            return Ok(chat_message);
                                        } else {
                                            tracing::error!(
                                                "Function call error: AI Service not available {:?}", ai_function.ai_service_id
                                            );
                                        }
                                    } else {
                                        tracing::error!(
                                            "Function call error: AI Function not available {:?}",
                                            function_name
                                        );
                                    }

                                    let simple_app = context
                                        .octopus_database
                                        .try_get_simple_app_by_formatted_name(&function_name)
                                        .await?;

                                    if let Some(simple_app) = simple_app {
                                        let chat_message = context
                                            .octopus_database
                                            .update_chat_message_simple_app_id(
                                                &mut transaction,
                                                chat_message.id,
                                                100,
                                                simple_app.id,
                                                ChatMessageStatus::Answered,
                                            )
                                            .await?;

                                        context
                                            .octopus_database
                                            .transaction_commit(transaction)
                                            .await?;

                                        return Ok(chat_message);
                                    }

                                    let wasp_app = context
                                        .octopus_database
                                        .try_get_wasp_app_by_formatted_name(&function_name)
                                        .await?;

                                    if let Some(wasp_app) = wasp_app {
                                        let chat_message = context
                                            .octopus_database
                                            .update_chat_message_wasp_app_id(
                                                &mut transaction,
                                                chat_message.id,
                                                100,
                                                wasp_app.id,
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
                    }
                } else {
                    let response = response.text().await?;

                    let response = format!("AnthropicError: {response}");
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
