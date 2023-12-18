use crate::{
    context::Context,
    entity::{
        AiServiceHealthCheckStatus, AiServiceSetupStatus, AiServiceStatus, ChatMessage,
        ChatMessageStatus, User,
    },
    error::AppError,
    Result, PUBLIC_DIR,
};
use async_openai::{
    config::{AzureConfig, OpenAIConfig},
    types::{
        ChatCompletionFunctions, ChatCompletionFunctionsArgs,
        ChatCompletionRequestAssistantMessageArgs, ChatCompletionRequestMessage,
        ChatCompletionRequestUserMessageArgs, ChatCompletionTool, ChatCompletionToolArgs,
        ChatCompletionToolType, CreateChatCompletionRequestArgs,
    },
    Client,
};
use chrono::{DateTime, Utc};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::{Postgres, Transaction};
use std::sync::Arc;
use uuid::Uuid;

pub mod code_tools;
pub mod function_call;
pub mod service;

pub const AZURE_OPENAI_API_VERSION: &str = "2023-12-01-preview";
pub const AZURE_OPENAI_BASE_URL: &str = "https://metricspace2.openai.azure.com/";
pub const BASE_AI_FUNCTION_URL: &str = "http://127.0.0.1";
pub const MODEL: &str = "gpt-4-1106-preview";

#[derive(Debug, Deserialize, Serialize)]
pub struct AiFunctionCall {
    pub arguments: serde_json::Value,
    pub name: String,
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

#[derive(Debug, Serialize)]
pub struct InformationRetrievalPost {
    pub prompt: String,
}

#[derive(Debug, Deserialize)]
pub struct InformationRetrievalResponse {
    pub result: Option<String>,
}

#[derive(Clone, Debug)]
pub enum AiClient {
    Azure(Client<AzureConfig>),
    OpenAI(Client<OpenAIConfig>),
}

pub async fn check_information_retrieval_service(
    context: Arc<Context>,
    transaction: &mut Transaction<'_, Postgres>,
    chat_message: &ChatMessage,
) -> Result<ChatMessage> {
    let ai_function = context
        .octopus_database
        .try_get_ai_function_for_direct_call("querycontent")
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
                let information_retrieval_post = InformationRetrievalPost {
                    prompt: chat_message.message.clone(),
                };
                let url = format!(
                    "{BASE_AI_FUNCTION_URL}:{}/{}",
                    ai_service.port, ai_function.name
                );
                let response = reqwest::Client::new()
                    .post(url)
                    .json(&information_retrieval_post)
                    .send()
                    .await;

                if let Ok(response) = response {
                    if response.status() == StatusCode::CREATED {
                        let information_retrieval_response: InformationRetrievalResponse =
                            response.json().await?;

                        if let Some(result) = information_retrieval_response.result {
                            let chat_message = context
                                .octopus_database
                                .update_chat_message_from_function(
                                    transaction,
                                    chat_message.id,
                                    ai_function.id,
                                    ChatMessageStatus::Answered,
                                    100,
                                    Some(result),
                                )
                                .await?;

                            return Ok(chat_message);
                        }
                    }
                }
            }
        }
    }

    Ok(chat_message.clone())
}

pub async fn check_sensitive_information_service(
    context: Arc<Context>,
    transaction: &mut Transaction<'_, Postgres>,
    chat_message: &ChatMessage,
    user_id: Uuid,
) -> Result<ChatMessage> {
    let mut content_safety_enabled = true;
    let mut is_not_checked_by_system = false;

    let inspection_disabling = context
        .octopus_database
        .try_get_inspection_disabling_by_user_id(user_id)
        .await?;

    if let Some(inspection_disabling) = inspection_disabling {
        if inspection_disabling.content_safety_disabled_until > Utc::now() {
            content_safety_enabled = false;
        } else {
            context
                .octopus_database
                .try_delete_inspection_disabling_by_user_id(transaction, user_id)
                .await?;
        }
    }

    if !chat_message.bypass_sensitive_information_filter
        && !chat_message.is_anonymized
        && !chat_message.is_marked_as_not_sensitive
        && !chat_message.is_sensitive
        && content_safety_enabled
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
                                        transaction,
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
                } else {
                    is_not_checked_by_system = true;
                }
            }
        } else {
            is_not_checked_by_system = true;
        }
    } else {
        is_not_checked_by_system = true;
    }

    let chat_message = if is_not_checked_by_system {
        context
            .octopus_database
            .update_chat_message_is_not_checked_by_system(transaction, chat_message.id, true)
            .await?
    } else {
        chat_message.clone()
    };

    Ok(chat_message)
}

pub async fn get_functions_ai_functions(
    context: Arc<Context>,
    user_id: Uuid,
) -> Result<Vec<ChatCompletionFunctions>> {
    let mut functions = vec![];

    let ai_functions = context
        .octopus_database
        .get_ai_functions_for_request(user_id)
        .await?;

    for ai_function in ai_functions {
        if ai_function.formatted_name != "anonymization"
            && ai_function.formatted_name != "querycontent"
            && ai_function.formatted_name != "sensitive_information"
        {
            let function = ChatCompletionFunctionsArgs::default()
                .name(ai_function.name)
                .description(ai_function.description)
                .parameters(json!(ai_function.parameters))
                .build()?;

            functions.push(function);
        }
    }

    Ok(functions)
}

pub async fn get_functions_all(
    context: Arc<Context>,
    user_id: Uuid,
) -> Result<Vec<ChatCompletionFunctions>> {
    let mut functions = vec![];

    let mut ai_functions_tools = get_functions_ai_functions(context.clone(), user_id).await?;
    functions.append(&mut ai_functions_tools);

    let mut simple_apps_tools = get_functions_simple_apps(context.clone()).await?;
    functions.append(&mut simple_apps_tools);

    let mut wasp_apps_tools = get_functions_wasp_apps(context.clone(), user_id).await?;
    functions.append(&mut wasp_apps_tools);

    Ok(functions)
}

pub async fn get_functions_simple_apps(
    context: Arc<Context>,
) -> Result<Vec<ChatCompletionFunctions>> {
    let mut functions = vec![];

    let simple_apps = context
        .octopus_database
        .get_simple_apps_for_request()
        .await?;

    for simple_app in simple_apps {
        let function = ChatCompletionFunctionsArgs::default()
            .name(simple_app.formatted_name)
            .description(simple_app.description)
            .parameters(json!({
                "type": "object",
                "properties": {
                    "title": {
                        "type": "string",
                        "description": "Simple app title",
                    },
                },
                "required": ["title"],
            }))
            .build()?;

        functions.push(function);
    }

    Ok(functions)
}

pub async fn get_functions_wasp_apps(
    context: Arc<Context>,
    user_id: Uuid,
) -> Result<Vec<ChatCompletionFunctions>> {
    let mut functions = vec![];

    let wasp_apps = context
        .octopus_database
        .get_wasp_apps_for_request(user_id)
        .await?;

    for wasp_app in wasp_apps {
        let function = ChatCompletionFunctionsArgs::default()
            .name(wasp_app.formatted_name)
            .description(wasp_app.description)
            .parameters(json!({
                "type": "object",
                "properties": {
                    "title": {
                        "type": "string",
                        "description": "Wasp app title",
                    },
                },
                "required": ["title"],
            }))
            .build()?;

        functions.push(function);
    }

    Ok(functions)
}

pub async fn get_messages(
    context: Arc<Context>,
    transaction: &mut Transaction<'_, Postgres>,
    chat_message: &ChatMessage,
) -> Result<Vec<ChatCompletionRequestMessage>> {
    let mut chat_audit_trails = vec![];
    let mut messages = vec![];

    let chat_messages = context
        .octopus_database
        .get_chat_messages_extended_by_chat_id(chat_message.chat_id)
        .await?;

    for chat_message_tmp in chat_messages {
        if !chat_message_tmp.is_sensitive
            || chat_message.is_anonymized
            || chat_message.is_marked_as_not_sensitive
        {
            let chat_completion_request_message = ChatCompletionRequestUserMessageArgs::default()
                .content(chat_message_tmp.message.clone())
                .build()?;

            messages.push(ChatCompletionRequestMessage::User(
                chat_completion_request_message,
            ));

            let chat_audit_trail = ChatAuditTrail {
                id: chat_message_tmp.id,
                content: chat_message_tmp.message.clone(),
                role: "user".to_string(),
                created_at: chat_message_tmp.created_at,
            };
            chat_audit_trails.push(chat_audit_trail);

            if let Some(response) = chat_message_tmp.response {
                let chat_completion_request_message =
                    ChatCompletionRequestAssistantMessageArgs::default()
                        .content(response.clone())
                        .build()?;

                messages.push(ChatCompletionRequestMessage::Assistant(
                    chat_completion_request_message,
                ));

                let chat_audit_trail = ChatAuditTrail {
                    id: chat_message_tmp.id,
                    content: response,
                    role: "assistant".to_string(),
                    created_at: chat_message_tmp.created_at,
                };
                chat_audit_trails.push(chat_audit_trail);
            } else if !chat_message_tmp.chat_message_files.is_empty() {
                let mut urls = String::new();
                let octopus_api_url = context.get_config().await?.get_parameter_octopus_api_url();

                if let Some(octopus_api_url) = octopus_api_url {
                    let api_url = octopus_api_url
                        .strip_suffix('/')
                        .ok_or(AppError::Parsing)?
                        .to_string();

                    for chat_message_file in chat_message_tmp.chat_message_files {
                        urls.push_str(&format!("{api_url}/{}", chat_message_file.file_name));
                    }
                }

                if !urls.is_empty() {
                    let chat_completion_request_message =
                        ChatCompletionRequestAssistantMessageArgs::default()
                            .content(urls.clone())
                            .build()?;

                    messages.push(ChatCompletionRequestMessage::Assistant(
                        chat_completion_request_message,
                    ));

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

pub async fn get_tools_ai_functions(
    context: Arc<Context>,
    user_id: Uuid,
) -> Result<Vec<ChatCompletionTool>> {
    let mut tools = vec![];

    let ai_functions = context
        .octopus_database
        .get_ai_functions_for_request(user_id)
        .await?;

    for ai_function in ai_functions {
        if ai_function.formatted_name != "anonymization"
            && ai_function.formatted_name != "querycontent"
            && ai_function.formatted_name != "sensitive_information"
        {
            let tool = ChatCompletionToolArgs::default()
                .r#type(ChatCompletionToolType::Function)
                .function(
                    ChatCompletionFunctionsArgs::default()
                        .name(ai_function.name)
                        .description(ai_function.description)
                        .parameters(json!(ai_function.parameters))
                        .build()?,
                )
                .build()?;

            tools.push(tool);
        }
    }

    Ok(tools)
}

pub async fn get_tools_all(
    context: Arc<Context>,
    user_id: Uuid,
) -> Result<Vec<ChatCompletionTool>> {
    let mut tools = vec![];

    let mut ai_functions_tools = get_tools_ai_functions(context.clone(), user_id).await?;
    tools.append(&mut ai_functions_tools);

    let mut simple_apps_tools = get_tools_simple_apps(context.clone()).await?;
    tools.append(&mut simple_apps_tools);

    let mut wasp_apps_tools = get_tools_wasp_apps(context.clone(), user_id).await?;
    tools.append(&mut wasp_apps_tools);

    Ok(tools)
}

pub async fn get_tools_simple_apps(context: Arc<Context>) -> Result<Vec<ChatCompletionTool>> {
    let mut tools = vec![];

    let simple_apps = context
        .octopus_database
        .get_simple_apps_for_request()
        .await?;

    for simple_app in simple_apps {
        let tool = ChatCompletionToolArgs::default()
            .r#type(ChatCompletionToolType::Function)
            .function(
                ChatCompletionFunctionsArgs::default()
                    .name(simple_app.formatted_name)
                    .description(simple_app.description)
                    .parameters(json!({
                        "type": "object",
                        "properties": {
                            "title": {
                                "type": "string",
                                "description": "Simple app title",
                            },
                        },
                        "required": ["title"],
                    }))
                    .build()?,
            )
            .build()?;

        tools.push(tool);
    }

    Ok(tools)
}

pub async fn get_tools_wasp_apps(
    context: Arc<Context>,
    user_id: Uuid,
) -> Result<Vec<ChatCompletionTool>> {
    let mut tools = vec![];

    let wasp_apps = context
        .octopus_database
        .get_wasp_apps_for_request(user_id)
        .await?;

    for wasp_app in wasp_apps {
        let tool = ChatCompletionToolArgs::default()
            .r#type(ChatCompletionToolType::Function)
            .function(
                ChatCompletionFunctionsArgs::default()
                    .name(wasp_app.formatted_name)
                    .description(wasp_app.description)
                    .parameters(json!({
                        "type": "object",
                        "properties": {
                            "title": {
                                "type": "string",
                                "description": "Wasp app title",
                            },
                        },
                        "required": ["title"],
                    }))
                    .build()?,
            )
            .build()?;

        tools.push(tool);
    }

    Ok(tools)
}

pub async fn open_ai_get_client(context: Arc<Context>) -> Result<AiClient> {
    let azure_openai_enabled = context
        .get_config()
        .await?
        .get_parameter_azure_openai_enabled();

    let ai_client = if azure_openai_enabled {
        let api_key = context
            .get_config()
            .await?
            .get_parameter_azure_openai_api_key()
            .ok_or(AppError::Config)?;
        let deployment_id = context
            .get_config()
            .await?
            .get_parameter_azure_openai_deployment_id()
            .ok_or(AppError::Config)?;
        let config = AzureConfig::new()
            .with_api_base(AZURE_OPENAI_BASE_URL)
            .with_api_key(api_key)
            .with_deployment_id(deployment_id)
            .with_api_version(AZURE_OPENAI_API_VERSION);

        AiClient::Azure(Client::with_config(config))
    } else {
        let api_key = context
            .get_config()
            .await?
            .get_parameter_openai_api_key()
            .ok_or(AppError::Config)?;
        let config = OpenAIConfig::new().with_api_key(api_key);

        AiClient::OpenAI(Client::with_config(config))
    };

    Ok(ai_client)
}

pub async fn open_ai_request(
    context: Arc<Context>,
    chat_message: ChatMessage,
    user: User,
) -> Result<ChatMessage> {
    let ai_client = open_ai_get_client(context.clone()).await?;

    let mut transaction = context.octopus_database.transaction_begin().await?;

    update_chat_name(context.clone(), &mut transaction, &chat_message).await?;

    let chat_message =
        check_information_retrieval_service(context.clone(), &mut transaction, &chat_message)
            .await?;

    if chat_message.status == ChatMessageStatus::Answered {
        context
            .octopus_database
            .transaction_commit(transaction)
            .await?;

        return Ok(chat_message);
    }

    let chat_message = check_sensitive_information_service(
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
        let request = match &ai_client {
            AiClient::Azure(_ai_client) => {
                let functions = get_functions_all(context.clone(), user.id).await?;

                if functions.is_empty() {
                    CreateChatCompletionRequestArgs::default()
                        .max_tokens(512u16)
                        .model(MODEL)
                        .messages(messages)
                        .build()
                } else {
                    CreateChatCompletionRequestArgs::default()
                        .max_tokens(512u16)
                        .model(MODEL)
                        .messages(messages)
                        .functions(functions)
                        .build()
                }
            }
            AiClient::OpenAI(_ai_client) => {
                let tools = get_tools_all(context.clone(), user.id).await?;

                if tools.is_empty() {
                    CreateChatCompletionRequestArgs::default()
                        .max_tokens(512u16)
                        .model(MODEL)
                        .messages(messages)
                        .build()
                } else {
                    CreateChatCompletionRequestArgs::default()
                        .max_tokens(512u16)
                        .model(MODEL)
                        .messages(messages)
                        .tools(tools)
                        .build()
                }
            }
        };

        match request {
            Err(e) => {
                let content = format!("OpenAIError: {e}");
                let chat_message = context
                    .octopus_database
                    .update_chat_message(
                        &mut transaction,
                        chat_message.id,
                        100,
                        &content,
                        ChatMessageStatus::Answered,
                    )
                    .await?;

                context
                    .octopus_database
                    .transaction_commit(transaction)
                    .await?;

                return Ok(chat_message);
            }
            Ok(request) => {
                let response_message = match ai_client.clone() {
                    AiClient::Azure(ai_client) => ai_client.chat().create(request).await,
                    AiClient::OpenAI(ai_client) => ai_client.chat().create(request).await,
                };

                match response_message {
                    Err(e) => {
                        let content = format!("OpenAIError: {e}");
                        let chat_message = context
                            .octopus_database
                            .update_chat_message(
                                &mut transaction,
                                chat_message.id,
                                100,
                                &content,
                                ChatMessageStatus::Answered,
                            )
                            .await?;

                        context
                            .octopus_database
                            .transaction_commit(transaction)
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
                                        &mut transaction,
                                        chat_message.id,
                                        100,
                                        content,
                                        ChatMessageStatus::Answered,
                                    )
                                    .await?;

                                context
                                    .octopus_database
                                    .transaction_commit(transaction)
                                    .await?;

                                return Ok(chat_message);
                            }
                            Some(response_message) => {
                                let response_message = response_message.message.clone();

                                let (function_args, function_name) = match ai_client {
                                    AiClient::Azure(_ai_client) => {
                                        #[allow(deprecated)]
                                        if let Some(function_call) = response_message.function_call
                                        {
                                            let function_name = function_call.name;
                                            let function_args: serde_json::Value =
                                                function_call.arguments.parse()?;

                                            (Some(function_args), Some(function_name))
                                        } else {
                                            (None, None)
                                        }
                                    }
                                    AiClient::OpenAI(_ai_client) => {
                                        if let Some(function_calls) = response_message.tool_calls {
                                            if let Some(function_call) = function_calls.first() {
                                                let function_name =
                                                    function_call.function.name.clone();
                                                let function_args: serde_json::Value =
                                                    function_call.function.arguments.parse()?;

                                                (Some(function_args), Some(function_name))
                                            } else {
                                                (None, None)
                                            }
                                        } else {
                                            (None, None)
                                        }
                                    }
                                };

                                if let (Some(function_args), Some(function_name)) =
                                    (function_args, function_name)
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
                                        }
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

                                if let Some(content) = response_message.content {
                                    let chat_message = context
                                        .octopus_database
                                        .update_chat_message(
                                            &mut transaction,
                                            chat_message.id,
                                            100,
                                            &content,
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
            }
        }
    }

    context
        .octopus_database
        .transaction_commit(transaction)
        .await?;

    Ok(chat_message)
}

pub async fn update_chat_name(
    context: Arc<Context>,
    transaction: &mut Transaction<'_, Postgres>,
    chat_message: &ChatMessage,
) -> Result<()> {
    let chat = context
        .octopus_database
        .try_get_chat_by_id(chat_message.chat_id)
        .await?;

    if let Some(chat) = chat {
        if chat.name.is_none() {
            context
                .octopus_database
                .update_chat(transaction, chat.id, &chat_message.message)
                .await?;
        }
    }

    Ok(())
}
