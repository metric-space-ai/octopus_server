use crate::{
    ai::{anthropic::ANTHROPIC, ollama::OLLAMA, open_ai::OPENAI},
    context::Context,
    entity::{
        AiServiceHealthCheckStatus, AiServiceSetupStatus, AiServiceStatus, ChatMessage,
        ChatMessageStatus, User,
    },
    Result,
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
pub struct FunctionSensitiveInformationPost {
    pub value1: String,
}

pub async fn ai_request(
    context: Arc<Context>,
    chat_message: ChatMessage,
    user: User,
) -> Result<ChatMessage> {
    let main_llm = context
        .get_config()
        .await?
        .get_parameter_main_llm()
        .unwrap_or(OPENAI.to_string());
    let suggested_llm = chat_message.suggested_llm.clone().unwrap_or(main_llm);
    tracing::info!("suggested_llm = {:?}", suggested_llm);
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
                .update_chat(transaction, chat.id, &chat_message.message, chat.r#type)
                .await?;
        }
    }

    Ok(())
}
