use crate::{
    context::Context,
    entity::{
        AiService, AiServiceHealthCheckStatus, AiServiceSetupStatus, AiServiceStatus, ChatMessage,
        ChatMessageStatus, User,
    },
    error::AppError,
    Result, DOMAIN, PUBLIC_DIR,
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
use uuid::Uuid;

pub mod function_call;

pub const BASE_AI_FUNCTION_URL: &str = "http://127.0.0.1";
pub const MODEL: &str = "gpt-4-0613";

#[derive(Debug, Deserialize, Serialize)]
pub struct AiFunctionCall {
    pub arguments: serde_json::Value,
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct HealthCheckResponse {
    pub status: AiServiceHealthCheckStatus,
}

#[derive(Debug, Serialize)]
pub struct SetupPost {
    pub force_setup: bool,
}

#[derive(Debug, Deserialize)]
pub struct SetupResponse {
    pub setup: AiServiceSetupStatus,
}

pub async fn service_health_check(
    ai_service_id: Uuid,
    context: Arc<Context>,
    port: i32,
) -> Result<AiService> {
    context
        .octopus_database
        .update_ai_service_health_check_status(
            ai_service_id,
            0,
            AiServiceHealthCheckStatus::NotWorking,
        )
        .await?;

    let start = Utc::now();

    let url = format!("{BASE_AI_FUNCTION_URL}:{port}/health-check");

    let response = reqwest::Client::new().get(url).send().await;

    let end = Utc::now();

    let health_check_execution_time = (end - start).num_seconds() as i32;

    if let Ok(response) = response {
        if response.status() == StatusCode::OK {
            let response: HealthCheckResponse = response.json().await?;

            let ai_service = context
                .octopus_database
                .update_ai_service_health_check_status(
                    ai_service_id,
                    health_check_execution_time,
                    response.status,
                )
                .await?;

            return Ok(ai_service);
        }
    }

    let ai_service = context
        .octopus_database
        .update_ai_service_health_check_status(
            ai_service_id,
            health_check_execution_time,
            AiServiceHealthCheckStatus::NotWorking,
        )
        .await?;

    Ok(ai_service)
}

pub async fn service_prepare(ai_service: AiService, context: Arc<Context>) -> Result<AiService> {
    if ai_service.is_enabled {
        let ai_service =
            service_health_check(ai_service.id, context.clone(), ai_service.port).await?;

        if ai_service.health_check_status == AiServiceHealthCheckStatus::Ok {
            let ai_service = service_setup(ai_service.id, context.clone(), ai_service.port).await?;

            return Ok(ai_service);
        }

        return Ok(ai_service);
    }

    Ok(ai_service)
}

pub async fn service_setup(
    ai_service_id: Uuid,
    context: Arc<Context>,
    port: i32,
) -> Result<AiService> {
    context
        .octopus_database
        .update_ai_service_setup_status(ai_service_id, 0, AiServiceSetupStatus::NotPerformed)
        .await?;

    context
        .octopus_database
        .update_ai_service_status(ai_service_id, 50, AiServiceStatus::Setup)
        .await?;

    let start = Utc::now();

    let setup_post = SetupPost { force_setup: false };

    let url = format!("{BASE_AI_FUNCTION_URL}:{port}/setup");

    let response: std::result::Result<reqwest::Response, reqwest::Error> = reqwest::Client::new()
        .post(url)
        .json(&setup_post)
        .send()
        .await;

    let end = Utc::now();
    let setup_execution_time = (end - start).num_seconds() as i32;

    if let Ok(response) = response {
        if response.status() == StatusCode::CREATED {
            let response: SetupResponse = response.json().await?;

            let ai_service = context
                .octopus_database
                .update_ai_service_setup_status(ai_service_id, setup_execution_time, response.setup)
                .await?;

            return Ok(ai_service);
        }
    }

    let ai_service = context
        .octopus_database
        .update_ai_service_setup_status(
            ai_service_id,
            setup_execution_time,
            AiServiceSetupStatus::NotPerformed,
        )
        .await?;

    Ok(ai_service)
}

#[derive(Clone, Debug, Serialize)]
pub struct ChatAuditTrail {
    pub id: Uuid,
    pub content: String,
    pub role: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct FunctionSensitiveInformationPost {
    pub value1: String,
}

#[derive(Debug, Deserialize)]
pub struct FunctionSensitiveInformationResponse {
    pub is_sensitive: bool,
    pub sensitive_part: Option<String>,
}

pub async fn open_ai_code_check(code: &str) -> Result<bool> {
    let client = Client::new();

    let mut messages = vec![];

    let content = format!("Check if the following code contains sections that looks malicious and provide YES or NO answer {code}");

    let chat_completion_request_message = ChatCompletionRequestMessageArgs::default()
        .role(Role::User)
        .content(content)
        .build()?;

    messages.push(chat_completion_request_message);

    let request = CreateChatCompletionRequestArgs::default()
        .max_tokens(512u16)
        .model(MODEL)
        .messages(messages)
        .build();

    match request {
        Err(e) => {
            tracing::info!("OpenAIError: {e}");
        }
        Ok(request) => {
            let response_message = client.chat().create(request).await;

            match response_message {
                Err(e) => {
                    tracing::info!("OpenAIError: {e}");
                }
                Ok(response_message) => {
                    let response_message = response_message.choices.get(0);

                    match response_message {
                        None => {
                            tracing::info!("BadResponse");
                        }
                        Some(response_message) => {
                            let response_message = response_message.message.clone();

                            if let Some(content) = response_message.content {
                                if content == "YES" {
                                    return Ok(true);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(false)
}

pub async fn open_ai_request(
    context: Arc<Context>,
    chat_message: ChatMessage,
    user: User,
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

    let mut content_safety_enabled = true;

    let inspection_disabling = context
        .octopus_database
        .try_get_inspection_disabling_by_user_id(user.id)
        .await?;

    if let Some(inspection_disabling) = inspection_disabling {
        if inspection_disabling.content_safety_disabled_until > Utc::now() {
            content_safety_enabled = false;
        } else {
            context
                .octopus_database
                .try_delete_inspection_disabling_by_user_id(user.id)
                .await?;
        }
    }

    if content_safety_enabled
        && !chat_message.bypass_sensitive_information_filter
        && !chat_message.is_anonymized
    {
        let ai_function = context
            .octopus_database
            .try_get_ai_function_for_direct_call("sensitive_information")
            .await?;

        if let Some(ai_function) = ai_function {
            let ai_service = context
                .octopus_database
                .try_get_ai_service_by_id(ai_function.ai_service_id)
                .await?;

            if let Some(ai_service) = ai_service {
                if ai_function.is_enabled
                    && ai_service.is_enabled
                    && ai_service.health_check_status == AiServiceHealthCheckStatus::Ok
                    && ai_service.setup_status == AiServiceSetupStatus::Performed
                    && ai_service.status == AiServiceStatus::Running
                {
                    let function_sensitive_information_post = FunctionSensitiveInformationPost {
                        value1: chat_message.message.clone(),
                    };
                    let url = format!(
                        "{BASE_AI_FUNCTION_URL}:{}/{}",
                        ai_service.port, ai_function.name
                    );
                    let response = reqwest::Client::new()
                        .post(url)
                        .json(&function_sensitive_information_post)
                        .send()
                        .await;

                    if let Ok(response) = response {
                        if response.status() == StatusCode::CREATED {
                            let function_sensitive_information_response: FunctionSensitiveInformationResponse = response.json().await?;

                            if function_sensitive_information_response.is_sensitive {
                                let chat_message = context
                                    .octopus_database
                                    .update_chat_message_is_sensitive(
                                        chat_message.id,
                                        true,
                                        ChatMessageStatus::Answered,
                                        100,
                                    )
                                    .await?;

                                return Ok(chat_message);
                            }
                        }
                    }
                }
            }
        }
    }

    let mut chat_audit_trails = vec![];

    let chat_messages = context
        .octopus_database
        .get_chat_messages_extended_by_chat_id(chat_message.chat_id)
        .await?;

    for chat_message_tmp in chat_messages {
        if !chat_message_tmp.is_sensitive || chat_message.is_anonymized {
            let chat_completion_request_message = ChatCompletionRequestMessageArgs::default()
                .role(Role::User)
                .content(chat_message_tmp.message.clone())
                .build()?;

            messages.push(chat_completion_request_message);

            let chat_audit_trail = ChatAuditTrail {
                id: chat_message_tmp.id,
                content: chat_message_tmp.message.clone(),
                role: "user".to_string(),
                created_at: chat_message_tmp.created_at,
            };
            chat_audit_trails.push(chat_audit_trail);

            if let Some(response) = chat_message_tmp.response {
                let chat_completion_request_message = ChatCompletionRequestMessageArgs::default()
                    .role(Role::Assistant)
                    .content(response.clone())
                    .build()?;

                messages.push(chat_completion_request_message);

                let chat_audit_trail = ChatAuditTrail {
                    id: chat_message_tmp.id,
                    content: response,
                    role: "assistant".to_string(),
                    created_at: chat_message_tmp.created_at,
                };
                chat_audit_trails.push(chat_audit_trail);
            } else if !chat_message_tmp.chat_message_files.is_empty() {
                let mut urls = String::new();
                for chat_message_file in chat_message_tmp.chat_message_files {
                    urls.push_str(&format!("https://{DOMAIN}/{}", chat_message_file.file_name));
                }

                if !urls.is_empty() {
                    let chat_completion_request_message =
                        ChatCompletionRequestMessageArgs::default()
                            .role(Role::Assistant)
                            .content(urls.clone())
                            .build()?;

                    messages.push(chat_completion_request_message);

                    let chat_audit_trail = ChatAuditTrail {
                        id: chat_message_tmp.id,
                        content: urls,
                        role: "assistant".to_string(),
                        created_at: chat_message_tmp.created_at,
                    };
                    chat_audit_trails.push(chat_audit_trail);
                };
            }
        }
    }

    let mut functions = vec![];

    let ai_functions = context
        .octopus_database
        .get_ai_functions_for_request()
        .await?;

    for ai_function in ai_functions {
        if ai_function.formatted_name != "sensitive_information" {
            let function = ChatCompletionFunctionsArgs::default()
                .name(ai_function.name)
                .description(ai_function.description)
                .parameters(json!(ai_function.parameters))
                .build()?;

            functions.push(function);
        }
    }

    let trail = serde_json::to_value(&chat_audit_trails)?;

    context
        .octopus_database
        .insert_chat_audit(
            chat_message.chat_id,
            chat_message.id,
            chat_message.user_id,
            trail,
        )
        .await?;

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
        .model(MODEL)
        .messages(messages)
        .functions(functions)
        .function_call("auto")
        .build();

    match request {
        Err(e) => {
            let content = format!("OpenAIError: {e}");
            let chat_message = context
                .octopus_database
                .update_chat_message(chat_message.id, 100, &content, ChatMessageStatus::Answered)
                .await?;

            return Ok(chat_message);
        }
        Ok(request) => {
            let response_message = client.chat().create(request).await;

            match response_message {
                Err(e) => {
                    let content = format!("OpenAIError: {e}");
                    let chat_message = context
                        .octopus_database
                        .update_chat_message(
                            chat_message.id,
                            100,
                            &content,
                            ChatMessageStatus::Answered,
                        )
                        .await?;

                    return Ok(chat_message);
                }
                Ok(response_message) => {
                    let response_message = response_message.choices.get(0);

                    match response_message {
                        None => {
                            let content = "BadResponse";
                            context
                                .octopus_database
                                .update_chat_message(
                                    chat_message.id,
                                    100,
                                    content,
                                    ChatMessageStatus::Answered,
                                )
                                .await?;

                            return Err(Box::new(AppError::BadResponse));
                        }
                        Some(response_message) => {
                            let response_message = response_message.message.clone();

                            if let Some(function_call) = response_message.function_call {
                                let function_name = function_call.name;
                                let function_args: serde_json::Value =
                                    function_call.arguments.parse()?;
                                let ai_function_call = AiFunctionCall {
                                    arguments: function_args.clone(),
                                    name: function_name.clone(),
                                };
                                let ai_function_call = serde_json::to_value(ai_function_call)?;
                                let chat_message = context
                                    .octopus_database
                                    .update_chat_message_ai_function_call(
                                        chat_message.id,
                                        ai_function_call,
                                    )
                                    .await?;
                                let ai_function = context
                                    .octopus_database
                                    .try_get_ai_function_by_name(&function_name)
                                    .await?;

                                if let Some(ai_function) = ai_function {
                                    let ai_service = context
                                        .octopus_database
                                        .try_get_ai_service_by_id(ai_function.ai_service_id)
                                        .await?;

                                    if let Some(ai_service) = ai_service {
                                        function_call::handle_function_call(
                                            &ai_function,
                                            &ai_service,
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
                                    .update_chat_message(
                                        chat_message.id,
                                        100,
                                        &content,
                                        ChatMessageStatus::Answered,
                                    )
                                    .await?;

                                return Ok(chat_message);
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(chat_message)
}
