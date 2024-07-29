use crate::{context::Context, entity::ChatTokenAudit, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};
use utoipa::ToSchema;

pub type ReportUserValue = HashMap<String, ReportLlmValue>;
type ReportLlmValue = HashMap<String, ReportModelValue>;
type ReportModelValue = HashMap<String, TokenAudit>;

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
pub struct ChatTokenAuditReport {
    pub ends_at: DateTime<Utc>,
    pub report: ReportUserValue,
    pub starts_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
pub struct TokenAudit {
    pub input_tokens: i64,
    pub output_tokens: i64,
}

pub async fn generate(
    chat_token_audits: Vec<ChatTokenAudit>,
    context: Arc<Context>,
    ends_at: DateTime<Utc>,
    starts_at: DateTime<Utc>,
) -> Result<ChatTokenAuditReport> {
    let mut user_ids = vec![];
    let mut report_user_value = ReportUserValue::new();

    for chat_token_audit in &chat_token_audits {
        if !user_ids.contains(&chat_token_audit.user_id) {
            user_ids.push(chat_token_audit.user_id);
        }
    }

    let users = context.octopus_database.get_users_by_ids(&user_ids).await?;

    for chat_token_audit in chat_token_audits {
        let user = users.iter().find(|x| x.id == chat_token_audit.user_id);

        if let Some(user) = user {
            if report_user_value.contains_key(&user.email) {
                let user_value = report_user_value.get_mut(&user.email);

                if let Some(user_value) = user_value {
                    #[allow(clippy::map_entry)]
                    if user_value.contains_key(&chat_token_audit.llm) {
                        let llm_value = user_value.get_mut(&chat_token_audit.llm);

                        if let Some(llm_value) = llm_value {
                            #[allow(clippy::map_entry)]
                            if llm_value.contains_key(&chat_token_audit.model) {
                                let model_value = llm_value.get_mut(&chat_token_audit.model);

                                if let Some(model_value) = model_value {
                                    model_value.input_tokens += chat_token_audit.input_tokens;
                                    model_value.output_tokens += chat_token_audit.output_tokens;
                                }
                            } else {
                                let value = TokenAudit {
                                    input_tokens: chat_token_audit.input_tokens,
                                    output_tokens: chat_token_audit.output_tokens,
                                };

                                llm_value.insert(chat_token_audit.model, value);
                            }
                        }
                    } else {
                        let value = TokenAudit {
                            input_tokens: chat_token_audit.input_tokens,
                            output_tokens: chat_token_audit.output_tokens,
                        };

                        let mut model_value = ReportModelValue::new();
                        model_value.insert(chat_token_audit.model, value);
                        user_value.insert(chat_token_audit.llm, model_value);
                    }
                }
            } else {
                let value = TokenAudit {
                    input_tokens: chat_token_audit.input_tokens,
                    output_tokens: chat_token_audit.output_tokens,
                };

                let mut model_value = ReportModelValue::new();
                model_value.insert(chat_token_audit.model, value);
                let mut llm_value = ReportLlmValue::new();
                llm_value.insert(chat_token_audit.llm, model_value);
                report_user_value.insert(user.email.clone(), llm_value);
            }
        }
    }

    let report = ChatTokenAuditReport {
        ends_at,
        report: report_user_value,
        starts_at,
    };

    Ok(report)
}
