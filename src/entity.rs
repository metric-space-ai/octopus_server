use crate::error::AppError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, Type};
use std::str::FromStr;
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema, Type)]
#[sqlx(
    type_name = "ai_functions_request_content_types",
    rename_all = "snake_case"
)]
pub enum AiFunctionRequestContentType {
    ApplicationJson,
}

impl FromStr for AiFunctionRequestContentType {
    type Err = AppError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "application_json" => Ok(AiFunctionRequestContentType::ApplicationJson),
            _ => Ok(AiFunctionRequestContentType::ApplicationJson),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema, Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(
    type_name = "ai_functions_response_content_types",
    rename_all = "snake_case"
)]
pub enum AiFunctionResponseContentType {
    ApplicationJson,
    ImageJpeg,
    ImagePng,
    TextPlain,
}

impl FromStr for AiFunctionResponseContentType {
    type Err = AppError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "application_json" => Ok(AiFunctionResponseContentType::ApplicationJson),
            "image_jpeg" => Ok(AiFunctionResponseContentType::ImageJpeg),
            "image_png" => Ok(AiFunctionResponseContentType::ImagePng),
            "text_plain" => Ok(AiFunctionResponseContentType::TextPlain),
            _ => Ok(AiFunctionResponseContentType::ApplicationJson),
        }
    }
}

#[derive(Clone, Debug, Deserialize, FromRow, Serialize, ToSchema)]
pub struct AiFunction {
    pub id: Uuid,
    pub ai_service_id: Uuid,
    pub description: String,
    pub formatted_name: String,
    pub is_enabled: bool,
    pub name: String,
    pub parameters: serde_json::Value,
    pub request_content_type: AiFunctionRequestContentType,
    pub response_content_type: AiFunctionResponseContentType,
    pub created_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema, Type)]
#[sqlx(
    type_name = "ai_services_health_check_statuses",
    rename_all = "snake_case"
)]
pub enum AiServiceHealthCheckStatus {
    NotWorking,
    Ok,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema, Type)]
#[sqlx(type_name = "ai_services_setup_statuses", rename_all = "snake_case")]
pub enum AiServiceSetupStatus {
    NotPerformed,
    Performed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema, Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(
    type_name = "ai_services_required_python_versions",
    rename_all = "snake_case"
)]
pub enum AiServiceRequiredPythonVersion {
    Cp310,
    Cp311,
    Cp312,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema, Type)]
#[sqlx(type_name = "ai_services_statuses", rename_all = "snake_case")]
pub enum AiServiceStatus {
    Configuration,
    Error,
    Initial,
    InstallationFinished,
    InstallationStarted,
    MaliciousCodeDetected,
    ParsingFinished,
    ParsingStarted,
    Running,
    Setup,
    Stopped,
}

#[derive(Clone, Debug, Deserialize, FromRow, Serialize, ToSchema)]
pub struct AiService {
    pub id: Uuid,
    pub device_map: Option<serde_json::Value>,
    pub health_check_execution_time: i32,
    pub health_check_status: AiServiceHealthCheckStatus,
    pub is_enabled: bool,
    pub original_file_name: String,
    pub original_function_body: String,
    pub port: i32,
    pub processed_function_body: Option<String>,
    pub progress: i32,
    pub required_python_version: AiServiceRequiredPythonVersion,
    pub setup_execution_time: i32,
    pub setup_status: AiServiceSetupStatus,
    pub status: AiServiceStatus,
    pub created_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
    pub health_check_at: Option<DateTime<Utc>>,
    pub setup_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, FromRow, Serialize, ToSchema)]
pub struct Chat {
    pub id: Uuid,
    pub user_id: Uuid,
    pub workspace_id: Uuid,
    pub name: Option<String>,
    pub created_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, FromRow, Serialize, ToSchema)]
pub struct ChatActivity {
    pub id: Uuid,
    pub chat_id: Uuid,
    pub session_id: Uuid,
    pub user_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, FromRow, Serialize, ToSchema)]
pub struct ChatAudit {
    pub id: Uuid,
    pub chat_id: Uuid,
    pub chat_message_id: Uuid,
    pub user_id: Uuid,
    pub trail: serde_json::Value,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, Type)]
#[sqlx(type_name = "chat_message_statuses", rename_all = "snake_case")]
pub enum ChatMessageStatus {
    Answered,
    Asked,
}

#[derive(Clone, Debug, Deserialize, FromRow, Serialize, ToSchema)]
pub struct ChatMessage {
    pub id: Uuid,
    pub ai_function_id: Option<Uuid>,
    pub chat_id: Uuid,
    pub simple_app_id: Option<Uuid>,
    pub user_id: Uuid,
    pub ai_function_call: Option<serde_json::Value>,
    pub ai_function_error: Option<String>,
    pub bad_reply_comment: Option<String>,
    pub bad_reply_is_harmful: bool,
    pub bad_reply_is_not_helpful: bool,
    pub bad_reply_is_not_true: bool,
    pub bypass_sensitive_information_filter: bool,
    pub estimated_response_at: DateTime<Utc>,
    pub is_anonymized: bool,
    pub is_sensitive: bool,
    pub message: String,
    pub progress: i32,
    pub response: Option<String>,
    pub simple_app_data: Option<serde_json::Value>,
    pub status: ChatMessageStatus,
    pub created_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, FromRow, Serialize, ToSchema)]
pub struct ChatMessageExtended {
    pub id: Uuid,
    pub ai_function_id: Option<Uuid>,
    pub chat_id: Uuid,
    pub simple_app_id: Option<Uuid>,
    pub user_id: Uuid,
    pub ai_function_call: Option<serde_json::Value>,
    pub ai_function_error: Option<String>,
    pub bad_reply_comment: Option<String>,
    pub bad_reply_is_harmful: bool,
    pub bad_reply_is_not_helpful: bool,
    pub bad_reply_is_not_true: bool,
    pub bypass_sensitive_information_filter: bool,
    pub chat_message_files: Vec<ChatMessageFile>,
    pub chat_message_pictures: Vec<ChatMessagePicture>,
    pub estimated_response_at: DateTime<Utc>,
    pub is_anonymized: bool,
    pub is_sensitive: bool,
    pub message: String,
    pub profile: Option<Profile>,
    pub progress: i32,
    pub response: Option<String>,
    pub simple_app_data: Option<serde_json::Value>,
    pub status: ChatMessageStatus,
    pub created_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, FromRow, Serialize, ToSchema)]
pub struct ChatMessageFile {
    pub id: Uuid,
    pub chat_message_id: Uuid,
    pub file_name: String,
    pub media_type: String,
    pub created_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Deserialize, FromRow, Serialize, ToSchema)]
pub struct ChatMessagePicture {
    pub id: Uuid,
    pub chat_message_id: Uuid,
    pub file_name: String,
    pub created_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, FromRow, Serialize, ToSchema)]
pub struct ChatPicture {
    pub id: Uuid,
    pub chat_id: Uuid,
    pub file_name: String,
    pub created_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, FromRow, Serialize, ToSchema)]
pub struct Company {
    pub id: Uuid,
    pub address: Option<String>,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, FromRow, Serialize)]
pub struct EstimatedSeconds {
    pub ceiling: Option<i64>,
}

#[derive(Clone, Debug, Deserialize, FromRow, Serialize, ToSchema)]
pub struct ExamplePrompt {
    pub id: Uuid,
    pub example_prompt_category_id: Uuid,
    pub background_file_name: Option<String>,
    pub is_visible: bool,
    pub priority: i32,
    pub prompt: String,
    pub title: String,
    pub created_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, FromRow, Serialize, ToSchema)]
pub struct ExamplePromptCategory {
    pub id: Uuid,
    pub description: String,
    pub is_visible: bool,
    pub title: String,
    pub created_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, FromRow, Serialize, ToSchema)]
pub struct InspectionDisabling {
    pub id: Uuid,
    pub user_id: Uuid,
    pub content_safety_disabled_until: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, FromRow, Serialize, ToSchema)]
pub struct PasswordResetToken {
    pub id: Uuid,
    pub user_id: Uuid,
    pub email: String,
    pub created_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
    pub expires_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, FromRow, Serialize)]
pub struct Port {
    pub max: Option<i32>,
}

#[derive(Clone, Debug, Deserialize, FromRow, Serialize, ToSchema)]
pub struct Profile {
    pub id: Uuid,
    pub user_id: Uuid,
    pub job_title: Option<String>,
    pub language: String,
    pub name: Option<String>,
    pub photo_file_name: Option<String>,
    pub text_size: i32,
    pub created_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, FromRow, Serialize, ToSchema)]
pub struct Session {
    pub id: Uuid,
    pub user_id: Uuid,
    pub data: String,
    pub expired_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, FromRow, Serialize, ToSchema)]
pub struct SimpleApp {
    pub id: Uuid,
    pub code: String,
    pub description: String,
    pub formatted_name: String,
    pub is_enabled: bool,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
}

pub const ROLE_ADMIN: &str = "ROLE_ADMIN";
pub const ROLE_COMPANY_ADMIN_USER: &str = "ROLE_COMPANY_ADMIN_USER";
pub const ROLE_PRIVATE_USER: &str = "ROLE_PRIVATE_USER";
pub const ROLE_PUBLIC_USER: &str = "ROLE_PUBLIC_USER";

#[derive(Clone, Debug, Deserialize, FromRow, Serialize, ToSchema)]
pub struct User {
    pub id: Uuid,
    pub company_id: Uuid,
    pub email: String,
    pub is_enabled: bool,
    pub roles: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema, Type)]
#[sqlx(type_name = "workspaces_types", rename_all = "snake_case")]
pub enum WorkspacesType {
    Private,
    Public,
}

#[derive(Clone, Debug, Deserialize, FromRow, Serialize, ToSchema)]
pub struct Workspace {
    pub id: Uuid,
    pub company_id: Uuid,
    pub user_id: Uuid,
    pub name: String,
    pub r#type: WorkspacesType,
    pub created_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
}
