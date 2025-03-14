use crate::{
    Result,
    ai::{anthropic::ANTHROPIC, ollama::OLLAMA, open_ai::OPENAI},
    context::Context,
    entity::{
        AiServiceHealthCheckStatus, AiServiceSetupStatus, AiServiceStatus, Chat, ChatMessage,
        ChatMessageStatus, User,
    },
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{Postgres, Transaction};
use std::sync::Arc;
use uuid::Uuid;

pub mod anthropic;
pub mod code_tools;
pub mod function_call;
pub mod generator;
pub mod internal_function_call;
pub mod ollama;
pub mod open_ai;
pub mod service;
pub mod tasks;

pub const BASE_AI_FUNCTION_URL: &str = "http://127.0.0.1";
pub const PRIMARY_MODEL: &str = "PRIMARY_MODEL";
pub const SECONDARY_MODEL: &str = "SECONDARY_MODEL";
pub const TERTIARY_MODEL: &str = "TERTIARY_MODEL";

#[allow(clippy::module_name_repetitions)]
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
pub struct FunctionLlmRouterPost {
    pub text: String,
}

#[derive(Debug, Serialize)]
pub struct FunctionSensitiveInformationPost {
    pub value1: String,
}

pub async fn ai_request(
    context: Arc<Context>,
    chat_message: ChatMessage,
    user: User,
) -> Result<ChatMessage> {
    let chat_message = if chat_message.suggested_llm.clone().is_none() {
        let ai_function = context
            .octopus_database
            .try_get_ai_function_for_direct_call("llm_router")
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
                    let function_llm_router_post = FunctionLlmRouterPost {
                        text: chat_message.message.clone(),
                    };
                    let function_args = serde_json::to_value(function_llm_router_post)?;

                    let function_llm_router_response = function_call::llm_router_function_call(
                        &ai_function,
                        &ai_service,
                        &function_args,
                    )
                    .await;

                    match function_llm_router_response {
                        Ok(Some(function_llm_router_response)) => {
                            let value = function_llm_router_response.response.parse::<i32>();

                            if let Ok(value) = value {
                                let suggested = get_suggested_llm_and_suggested_model(
                                    context.clone(),
                                    user.company_id,
                                    user.id,
                                    value,
                                )
                                .await?;

                                if let Some(suggested) = suggested {
                                    let mut transaction =
                                        context.octopus_database.transaction_begin().await?;

                                    let chat_message = context
                                        .octopus_database
                                        .update_chat_message_suggested_llm_model(
                                            &mut transaction,
                                            chat_message.id,
                                            &suggested.llm,
                                            &suggested.model,
                                        )
                                        .await?;

                                    context
                                        .octopus_database
                                        .transaction_commit(transaction)
                                        .await?;

                                    chat_message
                                } else {
                                    chat_message
                                }
                            } else {
                                chat_message
                            }
                        }
                        _ => chat_message,
                    }
                } else {
                    chat_message
                }
            } else {
                chat_message
            }
        } else {
            chat_message
        }
    } else {
        chat_message
    };

    let main_llm = context
        .get_config()
        .await?
        .get_parameter_main_llm()
        .unwrap_or(OPENAI.to_string());
    let suggested_llm = chat_message.suggested_llm.clone().unwrap_or(main_llm);

    let chat_message = if suggested_llm == *ANTHROPIC {
        Box::pin(anthropic::anthropic_request(context, chat_message, user)).await?
    } else if suggested_llm == *OLLAMA {
        ollama::ollama_request(context, chat_message, user).await?
    } else {
        Box::pin(open_ai::open_ai_request(context, chat_message, user)).await?
    };

    Ok(chat_message)
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
                    let function_args = serde_json::to_value(function_sensitive_information_post)?;

                    let function_sensitive_information_response =
                        function_call::sensitive_information_function_call(
                            &ai_function,
                            &ai_service,
                            &function_args,
                        )
                        .await;

                    if let Ok(Some(function_sensitive_information_response)) =
                        function_sensitive_information_response
                    {
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

#[derive(Debug, Deserialize, Serialize)]
pub struct Suggested {
    pub llm: String,
    pub model: String,
}

pub async fn get_suggested_llm_and_suggested_model(
    context: Arc<Context>,
    company_id: Uuid,
    user_id: Uuid,
    complexity: i32,
) -> Result<Option<Suggested>> {
    let mut llm_router_config = context
        .octopus_database
        .try_get_llm_router_config_by_company_id_and_user_id_and_complexity(
            company_id,
            Some(user_id),
            complexity,
        )
        .await?;

    if llm_router_config.is_none() {
        llm_router_config = context
            .octopus_database
            .try_get_llm_router_config_by_company_id_and_complexity(company_id, complexity)
            .await?;
    }

    if let Some(llm_router_config) = llm_router_config {
        let mut suggested_llm = llm_router_config.suggested_llm.clone();
        let suggested_model = match llm_router_config.suggested_model.as_str() {
            PRIMARY_MODEL => match llm_router_config.suggested_llm.as_str() {
                ollama::OLLAMA => context
                    .get_config()
                    .await?
                    .get_parameter_main_llm_ollama_primary_model()
                    .unwrap_or(ollama::PRIMARY_MODEL.to_string()),
                open_ai::OPENAI => context
                    .get_config()
                    .await?
                    .get_parameter_main_llm_openai_primary_model()
                    .unwrap_or(open_ai::PRIMARY_MODEL.to_string()),
                &_ => {
                    suggested_llm = open_ai::OPENAI.to_string();

                    context
                        .get_config()
                        .await?
                        .get_parameter_main_llm_openai_primary_model()
                        .unwrap_or(open_ai::PRIMARY_MODEL.to_string())
                }
            },
            SECONDARY_MODEL => match llm_router_config.suggested_llm.as_str() {
                ollama::OLLAMA => ollama::SECONDARY_MODEL.to_string(),
                open_ai::OPENAI => context
                    .get_config()
                    .await?
                    .get_parameter_main_llm_openai_secondary_model()
                    .unwrap_or(open_ai::SECONDARY_MODEL.to_string()),
                &_ => {
                    suggested_llm = open_ai::OPENAI.to_string();

                    context
                        .get_config()
                        .await?
                        .get_parameter_main_llm_openai_secondary_model()
                        .unwrap_or(open_ai::SECONDARY_MODEL.to_string())
                }
            },
            TERTIARY_MODEL => match llm_router_config.suggested_llm.as_str() {
                ollama::OLLAMA => ollama::TERTIARY_MODEL.to_string(),
                open_ai::OPENAI => context
                    .get_config()
                    .await?
                    .get_parameter_main_llm_openai_secondary_model()
                    .unwrap_or(open_ai::SECONDARY_MODEL.to_string()),
                &_ => {
                    suggested_llm = open_ai::OPENAI.to_string();

                    context
                        .get_config()
                        .await?
                        .get_parameter_main_llm_openai_secondary_model()
                        .unwrap_or(open_ai::SECONDARY_MODEL.to_string())
                }
            },
            &_ => {
                suggested_llm = open_ai::OPENAI.to_string();

                context
                    .get_config()
                    .await?
                    .get_parameter_main_llm_openai_secondary_model()
                    .unwrap_or(open_ai::SECONDARY_MODEL.to_string())
            }
        };

        let suggested = Suggested {
            llm: suggested_llm,
            model: suggested_model,
        };

        return Ok(Some(suggested));
    }

    Ok(None)
}

pub async fn update_chat_name(
    context: Arc<Context>,
    transaction: &mut Transaction<'_, Postgres>,
    chat_message: &ChatMessage,
) -> Result<Option<Chat>> {
    let chat = context
        .octopus_database
        .try_get_chat_by_id(chat_message.chat_id)
        .await?;

    if let Some(ref chat) = chat {
        if chat.name.is_none() {
            let chat = context
                .octopus_database
                .update_chat(
                    transaction,
                    chat.id,
                    &chat_message.message,
                    chat.r#type.clone(),
                )
                .await?;

            return Ok(Some(chat));
        }
    }

    Ok(chat)
}
