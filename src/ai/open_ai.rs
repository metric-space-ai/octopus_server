use crate::{
    Result,
    ai::{self, AiFunctionCall, ChatAuditTrail, function_call, internal_function_call, tasks},
    context::Context,
    entity::{ChatMessage, ChatMessageStatus, ChatType, User},
    error::AppError,
    get_pwd,
};
use async_openai::{
    Client,
    config::{AzureConfig, OpenAIConfig},
    types::{
        ChatCompletionRequestAssistantMessageArgs, ChatCompletionRequestFunctionMessageArgs,
        ChatCompletionRequestMessage, ChatCompletionRequestMessageContentPartImageArgs,
        ChatCompletionRequestSystemMessageArgs, ChatCompletionRequestUserMessageArgs,
        ChatCompletionTool, ChatCompletionToolArgs, ChatCompletionToolType,
        CreateChatCompletionRequestArgs, FunctionObjectArgs, ImageDetail, ImageUrlArgs,
    },
};
use base64::{Engine, alphabet, engine};
use serde_json::json;
use sqlx::{Postgres, Transaction};
use std::{
    fs::{read, read_to_string},
    path::Path,
    sync::Arc,
};
use tracing::error;
use uuid::Uuid;

pub const AZURE_OPENAI: &str = "azure_openai";
pub const AZURE_OPENAI_API_VERSION: &str = "2024-05-01-preview";
pub const OPENAI: &str = "openai";
pub const PRIMARY_MODEL: &str = "gpt-4o-mini-2024-07-18";
pub const SECONDARY_MODEL: &str = "gpt-4o-2024-08-06";

#[allow(clippy::module_name_repetitions)]
#[derive(Clone, Debug)]
pub enum AiClient {
    Azure(Client<AzureConfig>),
    OpenAI(Client<OpenAIConfig>),
}

pub async fn get_messages(
    context: Arc<Context>,
    transaction: &mut Transaction<'_, Postgres>,
    chat_message: &ChatMessage,
) -> Result<Vec<ChatCompletionRequestMessage>> {
    let mut chat_audit_trails = vec![];
    let mut messages = vec![];
    let main_llm_openai_primary_model = context
        .get_config()
        .await?
        .get_parameter_main_llm_openai_primary_model()
        .unwrap_or(PRIMARY_MODEL.to_string());
    let mut suggested_model = chat_message
        .suggested_model
        .clone()
        .unwrap_or(main_llm_openai_primary_model);

    if chat_message.suggested_secondary_model {
        suggested_model = context
            .get_config()
            .await?
            .get_parameter_main_llm_openai_secondary_model()
            .unwrap_or(SECONDARY_MODEL.to_string());
    }

    let ai_system_prompt = context
        .get_config()
        .await?
        .get_parameter_main_llm_system_prompt();

    if let Some(ai_system_prompt) = ai_system_prompt {
        let chat_completion_request_system_message =
            ChatCompletionRequestSystemMessageArgs::default()
                .content(ai_system_prompt)
                .build()?;

        messages.push(ChatCompletionRequestMessage::System(
            chat_completion_request_system_message,
        ));
    }

    if chat_message.suggested_secondary_model {
        let system_prompt = "Here is the chat history so far from an other model. User is not satisfied with last answer. Analyse the problem. What needs do be done to give a better answer in the meaning of strategy. Now try to provide a better answer to the user last prompt.".to_string();
        let chat_completion_request_system_message =
            ChatCompletionRequestSystemMessageArgs::default()
                .content(system_prompt)
                .build()?;

        messages.push(ChatCompletionRequestMessage::System(
            chat_completion_request_system_message,
        ));
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

            let function_name = if let Some(ai_function_id) = chat_message_tmp.ai_function_id {
                ai_function_id.to_string()
            } else {
                "unknown".to_string()
            };

            if let Some(suggested_ai_function) = suggested_ai_function {
                let suggested_ai_function_message = format!(
                    "User wants to trigger {} function for the next request. Try to match the arguments and make a function call.",
                    suggested_ai_function.name
                );
                let chat_completion_request_message =
                    ChatCompletionRequestSystemMessageArgs::default()
                        .content(suggested_ai_function_message.clone())
                        .build()?;

                messages.push(ChatCompletionRequestMessage::System(
                    chat_completion_request_message,
                ));

                let chat_audit_trail = ChatAuditTrail {
                    id: chat_message_tmp.id,
                    content: suggested_ai_function_message,
                    role: "system".to_string(),
                    created_at: chat_message_tmp.created_at,
                };
                chat_audit_trails.push(chat_audit_trail);
            }

            let suggested_simple_app_id = chat_message.suggested_simple_app_id;
            let suggested_simple_app =
                if let Some(suggested_simple_app_id) = suggested_simple_app_id {
                    context
                        .octopus_database
                        .try_get_simple_app_by_id(suggested_simple_app_id)
                        .await?
                } else {
                    None
                };

            if let Some(suggested_simple_app) = suggested_simple_app {
                let suggested_simple_app_message = format!(
                    "User wants to trigger {} function for the next request. Try to match the arguments and make a function call.",
                    suggested_simple_app.name
                );
                let chat_completion_request_message =
                    ChatCompletionRequestSystemMessageArgs::default()
                        .content(suggested_simple_app_message.clone())
                        .build()?;

                messages.push(ChatCompletionRequestMessage::System(
                    chat_completion_request_message,
                ));

                let chat_audit_trail = ChatAuditTrail {
                    id: chat_message_tmp.id,
                    content: suggested_simple_app_message,
                    role: "system".to_string(),
                    created_at: chat_message_tmp.created_at,
                };
                chat_audit_trails.push(chat_audit_trail);
            }

            let suggested_wasp_app_id = chat_message.suggested_wasp_app_id;
            let suggested_wasp_app = if let Some(suggested_wasp_app_id) = suggested_wasp_app_id {
                context
                    .octopus_database
                    .try_get_wasp_app_by_id(suggested_wasp_app_id)
                    .await?
            } else {
                None
            };

            if let Some(suggested_wasp_app) = suggested_wasp_app {
                let suggested_wasp_app_message = format!(
                    "User wants to trigger {} function for the next request. Try to match the arguments and make a function call.",
                    suggested_wasp_app.name
                );
                let chat_completion_request_message =
                    ChatCompletionRequestSystemMessageArgs::default()
                        .content(suggested_wasp_app_message.clone())
                        .build()?;

                messages.push(ChatCompletionRequestMessage::System(
                    chat_completion_request_message,
                ));

                let chat_audit_trail = ChatAuditTrail {
                    id: chat_message_tmp.id,
                    content: suggested_wasp_app_message,
                    role: "system".to_string(),
                    created_at: chat_message_tmp.created_at,
                };
                chat_audit_trails.push(chat_audit_trail);
            }

            if chat_message_tmp.is_task_description {
                let is_task_description_message =
                    format!("{} {}", tasks::PROMPT1, chat_message_tmp.message);
                let chat_completion_request_message =
                    ChatCompletionRequestSystemMessageArgs::default()
                        .content(is_task_description_message.clone())
                        .build()?;

                messages.push(ChatCompletionRequestMessage::System(
                    chat_completion_request_message,
                ));

                let chat_audit_trail = ChatAuditTrail {
                    id: chat_message_tmp.id,
                    content: is_task_description_message,
                    role: "system".to_string(),
                    created_at: chat_message_tmp.created_at,
                };
                chat_audit_trails.push(chat_audit_trail);
            } else {
                let chat_completion_request_message =
                    ChatCompletionRequestUserMessageArgs::default()
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
            }

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
                    let chat_completion_request_message =
                        ChatCompletionRequestFunctionMessageArgs::default()
                            .content(urls.clone())
                            .name(function_name.clone())
                            .build()?;

                    messages.push(ChatCompletionRequestMessage::Function(
                        chat_completion_request_message,
                    ));

                    let chat_audit_trail = ChatAuditTrail {
                        id: chat_message_tmp.id,
                        content: urls,
                        role: "function".to_string(),
                        created_at: chat_message_tmp.created_at,
                    };
                    chat_audit_trails.push(chat_audit_trail);
                };
            }

            if !chat_message_tmp.chat_message_files.is_empty() {
                for chat_message_file in chat_message_tmp.chat_message_files {
                    let pwd = get_pwd()?;
                    let file_path = format!("{pwd}/{}", chat_message_file.file_name);

                    if chat_message_file.media_type == "image/png !disabled"
                        && (suggested_model.contains("4o") || suggested_model.contains("turbo"))
                    {
                        let file_exists = Path::new(&file_path).is_file();
                        if file_exists {
                            let content = read(file_path)?;

                            let engine = engine::GeneralPurpose::new(
                                &alphabet::URL_SAFE,
                                engine::general_purpose::PAD,
                            );
                            let content = engine.encode(content);
                            let image_url =
                                format!("data:{};base64,{}", chat_message_file.media_type, content);

                            let chat_completion_request_message_content_part_image =
                                ChatCompletionRequestMessageContentPartImageArgs::default()
                                    .image_url(
                                        ImageUrlArgs::default()
                                            .url(image_url)
                                            .detail(ImageDetail::High)
                                            .build()?,
                                    )
                                    .build()?
                                    .into();

                            let chat_completion_request_message =
                                ChatCompletionRequestUserMessageArgs::default()
                                    .content(vec![
                                        chat_completion_request_message_content_part_image,
                                    ])
                                    .build()?;

                            messages.push(ChatCompletionRequestMessage::User(
                                chat_completion_request_message,
                            ));

                            let chat_audit_trail = ChatAuditTrail {
                                id: chat_message_tmp.id,
                                content,
                                role: "function".to_string(),
                                created_at: chat_message_tmp.created_at,
                            };
                            chat_audit_trails.push(chat_audit_trail);
                        }
                    } else if chat_message_file.media_type == "text/plain" {
                        let file_exists = Path::new(&file_path).is_file();
                        if file_exists {
                            let content = read_to_string(file_path)?;

                            let chat_completion_request_message =
                                ChatCompletionRequestFunctionMessageArgs::default()
                                    .content(content.clone())
                                    .name(function_name.clone())
                                    .build()?;

                            messages.push(ChatCompletionRequestMessage::Function(
                                chat_completion_request_message,
                            ));

                            let chat_audit_trail = ChatAuditTrail {
                                id: chat_message_tmp.id,
                                content,
                                role: "function".to_string(),
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
            && ai_function.formatted_name != "google_search"
            && ai_function.formatted_name != "querycontent"
            && ai_function.formatted_name != "scrape_url"
            && ai_function.formatted_name != "sensitive_information"
        {
            let description = ai_function
                .generated_description
                .unwrap_or(ai_function.description);
            let tool = ChatCompletionToolArgs::default()
                .r#type(ChatCompletionToolType::Function)
                .function(
                    FunctionObjectArgs::default()
                        .name(ai_function.name)
                        .description(description)
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

    let mut internal_functions_tools = get_tools_internal_functions()?;
    tools.append(&mut internal_functions_tools);

    let mut ai_functions_tools = get_tools_ai_functions(context.clone(), user_id).await?;
    tools.append(&mut ai_functions_tools);

    let mut simple_apps_tools = get_tools_simple_apps(context.clone()).await?;
    tools.append(&mut simple_apps_tools);

    let mut wasp_apps_tools = get_tools_wasp_apps(context.clone(), user_id).await?;
    tools.append(&mut wasp_apps_tools);

    Ok(tools)
}

pub fn get_tools_internal_functions() -> Result<Vec<ChatCompletionTool>> {
    let mut tools = vec![];

    let tool = ChatCompletionToolArgs::default()
        .r#type(ChatCompletionToolType::Function)
        .function(
            FunctionObjectArgs::default()
                .name("os_internal_list_user_files".to_string())
                .description("List user files function. It lists only files created by the user. It doesn't have access to nextcloud. Returns a JSON structured list of the files that belong to the user.".to_string())
                .parameters(json!({
                    "type": "object",
                    "properties": {},
                    "required": [],
                }))
                .build()?,
        )
        .build()?;
    tools.push(tool);

    let tool = ChatCompletionToolArgs::default()
        .r#type(ChatCompletionToolType::Function)
        .function(
            FunctionObjectArgs::default()
                .name("os_internal_markdown_converter".to_string())
                .description("Converts Markdown from JSON file to PDF.".to_string())
                .parameters(json!({
                    "type": "object",
                    "properties": {
                        "url": {
                            "type": "string",
                            "description": "URL of JSON file with Markdown.",
                        },
                    },
                    "required": ["url"],
                }))
                .build()?,
        )
        .build()?;
    tools.push(tool);
    /*
    let tool = ChatCompletionToolArgs::default()
        .r#type(ChatCompletionToolType::Function)
        .function(
            FunctionObjectArgs::default()
                .name("os_internal_create_ai_service".to_string())
                .description("Creates an AI service for the user. User needs to provide a description of the service. Service name can be autogenerated. User may provide a sample code.".to_string())
                .parameters(json!({
                    "type": "object",
                    "properties": {
                        "description": {
                            "type": "string",
                            "description": "AI service description",
                        },
                        "name": {
                            "type": "string",
                            "description": "AI service name",
                        },
                        "sample_code": {
                            "type": "string",
                            "description": "AI service sample_code provided by the user that should be taken into account.",
                        },
                    },
                    "required": ["description", "name"],
                }))
                .build()?,
        )
        .build()?;
    tools.push(tool);

    let tool = ChatCompletionToolArgs::default()
        .r#type(ChatCompletionToolType::Function)
        .function(
            FunctionObjectArgs::default()
                .name("os_internal_delete_ai_service".to_string())
                .description("Delete an AI service for the user.".to_string())
                .parameters(json!({
                    "type": "object",
                    "properties": {
                        "id": {
                            "type": "string",
                            "description": "AI service id",
                        },
                    },
                    "required": ["id"],
                }))
                .build()?,
        )
        .build()?;
    tools.push(tool);

    let tool = ChatCompletionToolArgs::default()
        .r#type(ChatCompletionToolType::Function)
        .function(
            FunctionObjectArgs::default()
                .name("os_internal_deploy_ai_service".to_string())
                .description("Deploy an AI service for the user.".to_string())
                .parameters(json!({
                    "type": "object",
                    "properties": {
                        "id": {
                            "type": "string",
                            "description": "AI service id",
                        },
                    },
                    "required": ["id"],
                }))
                .build()?,
        )
        .build()?;
    tools.push(tool);

    let tool = ChatCompletionToolArgs::default()
        .r#type(ChatCompletionToolType::Function)
        .function(
            FunctionObjectArgs::default()
                .name("os_internal_generate_ai_service".to_string())
                .description("This function triggers a generation of AI service code for the user. By default internet research is performed once. User may want to skip internet research or skip regenerating it if internet research is available.".to_string())
                .parameters(json!({
                    "type": "object",
                    "properties": {
                        "id": {
                            "type": "string",
                            "description": "AI service id",
                        },
                        "skip_internet_research_results": {
                            "type": "boolean",
                            "description": "Determinates if internet research should be performed before AI service generation",
                        },
                        "skip_regenerate_internet_research_results": {
                            "type": "boolean",
                            "description": "Determinates if internet research should be performed again before AI service generation.",
                        },
                    },
                    "required": ["id"],
                }))
                .build()?,
        )
        .build()?;
    tools.push(tool);

    let tool = ChatCompletionToolArgs::default()
        .r#type(ChatCompletionToolType::Function)
        .function(
            FunctionObjectArgs::default()
                .name("os_internal_list_user_generated_ai_services".to_string())
                .description("List user files function returns a JSON structured list of the generated AI services that belong to the user.".to_string())
                .parameters(json!({
                    "type": "object",
                    "properties": {},
                    "required": [],
                }))
                .build()?,
        )
        .build()?;
    tools.push(tool);

    let tool = ChatCompletionToolArgs::default()
        .r#type(ChatCompletionToolType::Function)
        .function(
            FunctionObjectArgs::default()
                .name("os_internal_show_ai_service".to_string())
                .description("Shows an AI service informations.".to_string())
                .parameters(json!({
                    "type": "object",
                    "properties": {
                        "id": {
                            "type": "string",
                            "description": "AI service id",
                        },
                    },
                    "required": ["id"],
                }))
                .build()?,
        )
        .build()?;
    tools.push(tool);

    let tool = ChatCompletionToolArgs::default()
        .r#type(ChatCompletionToolType::Function)
        .function(
            FunctionObjectArgs::default()
                .name("os_internal_show_ai_service_code".to_string())
                .description("Shows an AI service generated source code. It will only show code if it was generated previously.".to_string())
                .parameters(json!({
                    "type": "object",
                    "properties": {
                        "id": {
                            "type": "string",
                            "description": "AI service id",
                        },
                    },
                    "required": ["id"],
                }))
                .build()?,
        )
        .build()?;
    tools.push(tool);

    let tool = ChatCompletionToolArgs::default()
        .r#type(ChatCompletionToolType::Function)
        .function(
            FunctionObjectArgs::default()
                .name("os_internal_update_ai_service".to_string())
                .description("Updates an AI service for the user. User needs to provide a description of the service. Service name can be autogenerated. User may provide a sample code.".to_string())
                .parameters(json!({
                    "type": "object",
                    "properties": {
                        "id": {
                            "type": "string",
                            "description": "AI service id",
                        },
                        "description": {
                            "type": "string",
                            "description": "AI service description",
                        },
                        "name": {
                            "type": "string",
                            "description": "AI service name",
                        },
                        "sample_code": {
                            "type": "string",
                            "description": "AI service sample_code provided by the user that should be taken into account.",
                        },
                    },
                    "required": ["id", "description", "name"],
                }))
                .build()?,
        )
        .build()?;
    tools.push(tool);
    */
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
                FunctionObjectArgs::default()
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
                FunctionObjectArgs::default()
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
        .get_parameter_main_llm_azure_openai_enabled();

    let ai_client = if azure_openai_enabled {
        let api_key = context
            .get_config()
            .await?
            .get_parameter_main_llm_azure_openai_api_key()
            .ok_or(AppError::Config)?;
        let deployment_id = context
            .get_config()
            .await?
            .get_parameter_main_llm_azure_openai_deployment_id()
            .ok_or(AppError::Config)?;
        let url = context
            .get_config()
            .await?
            .get_parameter_main_llm_azure_openai_url()
            .ok_or(AppError::Config)?;
        let config = AzureConfig::new()
            .with_api_base(url)
            .with_api_key(api_key)
            .with_deployment_id(deployment_id)
            .with_api_version(AZURE_OPENAI_API_VERSION);

        AiClient::Azure(Client::with_config(config))
    } else {
        let api_key = context
            .get_config()
            .await?
            .get_parameter_main_llm_openai_api_key()
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

    let main_llm_openai_primary_model = context
        .get_config()
        .await?
        .get_parameter_main_llm_openai_primary_model()
        .unwrap_or(PRIMARY_MODEL.to_string());
    let mut suggested_model = chat_message
        .suggested_model
        .clone()
        .unwrap_or(main_llm_openai_primary_model);

    if chat_message.suggested_secondary_model {
        suggested_model = context
            .get_config()
            .await?
            .get_parameter_main_llm_openai_secondary_model()
            .unwrap_or(SECONDARY_MODEL.to_string());
    }

    let used_llm = match ai_client {
        AiClient::Azure(_) => AZURE_OPENAI.to_string(),
        AiClient::OpenAI(_) => OPENAI.to_string(),
    };

    let mut transaction = context.octopus_database.transaction_begin().await?;

    let chat_message = context
        .octopus_database
        .update_chat_message_llm_model(
            &mut transaction,
            chat_message.id,
            Some(used_llm.clone()),
            Some(suggested_model.clone()),
        )
        .await?;

    let chat = ai::update_chat_name(context.clone(), &mut transaction, &chat_message).await?;

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
        let main_llm_openai_temperature = context
            .get_config()
            .await?
            .get_parameter_main_llm_openai_temperature();

        let tools = get_tools_all(context.clone(), user.id).await?;
        let request = if tools.is_empty() {
            match main_llm_openai_temperature {
                None => CreateChatCompletionRequestArgs::default()
                    .model(suggested_model.clone())
                    .messages(messages)
                    .build(),
                Some(main_llm_openai_temperature) => CreateChatCompletionRequestArgs::default()
                    .model(suggested_model.clone())
                    .messages(messages)
                    .temperature(main_llm_openai_temperature)
                    .build(),
            }
        } else {
            match main_llm_openai_temperature {
                None => CreateChatCompletionRequestArgs::default()
                    .model(suggested_model.clone())
                    .messages(messages)
                    .tools(tools)
                    .build(),
                Some(main_llm_openai_temperature) => CreateChatCompletionRequestArgs::default()
                    .model(suggested_model.clone())
                    .messages(messages)
                    .temperature(main_llm_openai_temperature)
                    .tools(tools)
                    .build(),
            }
        };

        match request {
            Err(e) => {
                let response = format!("OpenAIError: {e}");
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
            Ok(request) => {
                let response_message = match ai_client.clone() {
                    AiClient::Azure(ai_client) => ai_client.chat().create(request).await,
                    AiClient::OpenAI(ai_client) => ai_client.chat().create(request).await,
                };

                match response_message {
                    Err(e) => {
                        let response = format!("OpenAIError: {e}");
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
                    Ok(create_chat_completion_response) => {
                        let response_message = create_chat_completion_response.choices.first();

                        match response_message {
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
                            Some(response_message) => {
                                let response_message = response_message.message.clone();

                                let (function_args, function_name) =
                                    if let Some(function_calls) = response_message.tool_calls {
                                        if let Some(function_call) = function_calls.first() {
                                            let function_name = function_call.function.name.clone();
                                            let function_args: serde_json::Value =
                                                function_call.function.arguments.parse()?;

                                            (Some(function_args), Some(function_name))
                                        } else {
                                            (None, None)
                                        }
                                    } else {
                                        (None, None)
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

                                        if let Some(completion_usage) =
                                            create_chat_completion_response.usage
                                        {
                                            let mut transaction = context
                                                .octopus_database
                                                .transaction_begin()
                                                .await?;

                                            context
                                                .octopus_database
                                                .insert_chat_token_audit(
                                                    &mut transaction,
                                                    chat_message.chat_id,
                                                    chat_message.id,
                                                    user.company_id,
                                                    user.id,
                                                    i64::from(completion_usage.prompt_tokens),
                                                    &used_llm,
                                                    &suggested_model,
                                                    i64::from(completion_usage.completion_tokens),
                                                )
                                                .await?;

                                            context
                                                .octopus_database
                                                .transaction_commit(transaction)
                                                .await?;
                                        }

                                        if let Some(chat) = chat {
                                            if chat.r#type == ChatType::Task {
                                                let cloned_context = context.clone();
                                                tokio::spawn(async move {
                                                    let task = tasks::check_task_result(
                                                        cloned_context,
                                                        chat.id,
                                                    )
                                                    .await;

                                                    if let Err(e) = task {
                                                        error!("Error: {:?}", e);
                                                    }
                                                });
                                            }
                                        }

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

                                            if let Some(completion_usage) =
                                                create_chat_completion_response.usage
                                            {
                                                let mut transaction = context
                                                    .octopus_database
                                                    .transaction_begin()
                                                    .await?;

                                                context
                                                    .octopus_database
                                                    .insert_chat_token_audit(
                                                        &mut transaction,
                                                        chat_message.chat_id,
                                                        chat_message.id,
                                                        user.company_id,
                                                        user.id,
                                                        i64::from(completion_usage.prompt_tokens),
                                                        &used_llm,
                                                        &suggested_model,
                                                        i64::from(
                                                            completion_usage.completion_tokens,
                                                        ),
                                                    )
                                                    .await?;

                                                context
                                                    .octopus_database
                                                    .transaction_commit(transaction)
                                                    .await?;
                                            }

                                            if let Some(chat) = chat {
                                                if chat.r#type == ChatType::Task {
                                                    let cloned_context = context.clone();
                                                    tokio::spawn(async move {
                                                        let task = tasks::check_task_result(
                                                            cloned_context,
                                                            chat.id,
                                                        )
                                                        .await;

                                                        if let Err(e) = task {
                                                            error!("Error: {:?}", e);
                                                        }
                                                    });
                                                }
                                            }

                                            return Ok(chat_message);
                                        } else {
                                            tracing::error!(
                                                "Function call error: AI Service not available {:?}",
                                                ai_function.ai_service_id
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

                                        if let Some(completion_usage) =
                                            create_chat_completion_response.usage
                                        {
                                            context
                                                .octopus_database
                                                .insert_chat_token_audit(
                                                    &mut transaction,
                                                    chat_message.chat_id,
                                                    chat_message.id,
                                                    user.company_id,
                                                    user.id,
                                                    i64::from(completion_usage.prompt_tokens),
                                                    &used_llm,
                                                    &suggested_model,
                                                    i64::from(completion_usage.completion_tokens),
                                                )
                                                .await?;
                                        }

                                        context
                                            .octopus_database
                                            .transaction_commit(transaction)
                                            .await?;

                                        if let Some(chat) = chat {
                                            if chat.r#type == ChatType::Task {
                                                let cloned_context = context.clone();
                                                tokio::spawn(async move {
                                                    let task = tasks::check_task_result(
                                                        cloned_context,
                                                        chat.id,
                                                    )
                                                    .await;

                                                    if let Err(e) = task {
                                                        error!("Error: {:?}", e);
                                                    }
                                                });
                                            }
                                        }

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

                                        if let Some(completion_usage) =
                                            create_chat_completion_response.usage
                                        {
                                            context
                                                .octopus_database
                                                .insert_chat_token_audit(
                                                    &mut transaction,
                                                    chat_message.chat_id,
                                                    chat_message.id,
                                                    user.company_id,
                                                    user.id,
                                                    i64::from(completion_usage.prompt_tokens),
                                                    &used_llm,
                                                    &suggested_model,
                                                    i64::from(completion_usage.completion_tokens),
                                                )
                                                .await?;
                                        }

                                        context
                                            .octopus_database
                                            .transaction_commit(transaction)
                                            .await?;

                                        if let Some(chat) = chat {
                                            if chat.r#type == ChatType::Task {
                                                let cloned_context = context.clone();
                                                tokio::spawn(async move {
                                                    let task = tasks::check_task_result(
                                                        cloned_context,
                                                        chat.id,
                                                    )
                                                    .await;

                                                    if let Err(e) = task {
                                                        error!("Error: {:?}", e);
                                                    }
                                                });
                                            }
                                        }

                                        return Ok(chat_message);
                                    }
                                }

                                if let Some(content) = response_message.content {
                                    let response =
                                        format!("{}\n\nGenerated by {}", content, suggested_model);

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

                                    if let Some(completion_usage) =
                                        create_chat_completion_response.usage
                                    {
                                        context
                                            .octopus_database
                                            .insert_chat_token_audit(
                                                &mut transaction,
                                                chat_message.chat_id,
                                                chat_message.id,
                                                user.company_id,
                                                user.id,
                                                i64::from(completion_usage.prompt_tokens),
                                                &used_llm,
                                                &suggested_model,
                                                i64::from(completion_usage.completion_tokens),
                                            )
                                            .await?;
                                    }

                                    context
                                        .octopus_database
                                        .transaction_commit(transaction)
                                        .await?;

                                    if let Some(chat) = chat {
                                        if chat.r#type == ChatType::Task {
                                            let cloned_context = context.clone();
                                            tokio::spawn(async move {
                                                let task = tasks::check_task_result(
                                                    cloned_context,
                                                    chat.id,
                                                )
                                                .await;

                                                if let Err(e) = task {
                                                    error!("Error: {:?}", e);
                                                }
                                            });
                                        }
                                    }

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
