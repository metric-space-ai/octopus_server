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

    fn from_str(_s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(AiFunctionRequestContentType::ApplicationJson)
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
    ApplicationPdf,
    AudioAac,
    AudioMpeg,
    ImageJpeg,
    ImagePng,
    TextHtml,
    TextPlain,
    VideoMp4,
}

impl FromStr for AiFunctionResponseContentType {
    type Err = AppError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "application_pdf" => Ok(AiFunctionResponseContentType::ApplicationPdf),
            "audio_aac" => Ok(AiFunctionResponseContentType::AudioAac),
            "audio_mpeg" => Ok(AiFunctionResponseContentType::AudioMpeg),
            "image_jpeg" => Ok(AiFunctionResponseContentType::ImageJpeg),
            "image_png" => Ok(AiFunctionResponseContentType::ImagePng),
            "text_html" => Ok(AiFunctionResponseContentType::TextHtml),
            "text_plain" => Ok(AiFunctionResponseContentType::TextPlain),
            "video_mp4" => Ok(AiFunctionResponseContentType::VideoMp4),
            _ => Ok(AiFunctionResponseContentType::ApplicationJson),
        }
    }
}

#[derive(Clone, Debug, Deserialize, FromRow, Serialize, ToSchema)]
pub struct AiFunction {
    pub id: Uuid,
    pub ai_service_id: Uuid,
    pub description: String,
    pub display_name: Option<String>,
    pub formatted_name: String,
    pub generated_description: Option<String>,
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
#[sqlx(type_name = "ai_services_setup_statuses", rename_all = "snake_case")]
pub enum AiServiceSetupStatus {
    NotPerformed,
    Performed,
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema, Type)]
#[sqlx(type_name = "ai_services_types", rename_all = "snake_case")]
pub enum AiServiceType {
    Normal,
    System,
}

#[derive(Clone, Debug, Deserialize, FromRow, Serialize, ToSchema)]
pub struct AiService {
    pub id: Uuid,
    pub allowed_user_ids: Option<Vec<Uuid>>,
    pub color: Option<String>,
    pub device_map: Option<serde_json::Value>,
    pub health_check_execution_time: i32,
    pub health_check_status: AiServiceHealthCheckStatus,
    pub is_enabled: bool,
    pub original_file_name: String,
    pub original_function_body: String,
    pub parser_feedback: Option<String>,
    pub port: i32,
    pub priority: i32,
    pub processed_function_body: Option<String>,
    pub progress: i32,
    pub required_python_version: AiServiceRequiredPythonVersion,
    pub setup_execution_time: i32,
    pub setup_status: AiServiceSetupStatus,
    pub status: AiServiceStatus,
    pub r#type: AiServiceType,
    pub created_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
    pub health_check_at: Option<DateTime<Utc>>,
    pub setup_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, FromRow, Serialize, ToSchema)]
pub struct CachedFile {
    pub id: Uuid,
    pub cache_key: String,
    pub file_name: String,
    pub media_type: String,
    pub original_file_name: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema, Type)]
#[sqlx(type_name = "chat_message_statuses", rename_all = "snake_case")]
pub enum ChatMessageStatus {
    Answered,
    Asked,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, FromRow, Serialize, ToSchema)]
pub struct ChatMessage {
    pub id: Uuid,
    pub ai_function_id: Option<Uuid>,
    pub ai_service_id: Option<Uuid>,
    pub chat_id: Uuid,
    pub simple_app_id: Option<Uuid>,
    pub suggested_ai_function_id: Option<Uuid>,
    pub user_id: Uuid,
    pub wasp_app_id: Option<Uuid>,
    pub ai_function_call: Option<serde_json::Value>,
    pub ai_function_error: Option<String>,
    pub bad_reply_comment: Option<String>,
    pub bad_reply_is_harmful: bool,
    pub bad_reply_is_not_helpful: bool,
    pub bad_reply_is_not_true: bool,
    pub bypass_sensitive_information_filter: bool,
    pub color: Option<String>,
    pub estimated_response_at: DateTime<Utc>,
    pub is_anonymized: bool,
    pub is_marked_as_not_sensitive: bool,
    pub is_not_checked_by_system: bool,
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

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, FromRow, Serialize, ToSchema)]
pub struct ChatMessageExtended {
    pub id: Uuid,
    pub ai_function_id: Option<Uuid>,
    pub ai_service_id: Option<Uuid>,
    pub chat_id: Uuid,
    pub simple_app_id: Option<Uuid>,
    pub suggested_ai_function_id: Option<Uuid>,
    pub user_id: Uuid,
    pub wasp_app_id: Option<Uuid>,
    pub ai_function_call: Option<serde_json::Value>,
    pub ai_function_error: Option<String>,
    pub bad_reply_comment: Option<String>,
    pub bad_reply_is_harmful: bool,
    pub bad_reply_is_not_helpful: bool,
    pub bad_reply_is_not_true: bool,
    pub bypass_sensitive_information_filter: bool,
    pub chat_message_files: Vec<ChatMessageFile>,
    pub chat_message_pictures: Vec<ChatMessagePicture>,
    pub color: Option<String>,
    pub estimated_response_at: DateTime<Utc>,
    pub is_anonymized: bool,
    pub is_marked_as_not_sensitive: bool,
    pub is_not_checked_by_system: bool,
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
    pub original_file_name: Option<String>,
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
pub struct NextcloudFile {
    pub id: Uuid,
    pub file_name: String,
    pub media_type: String,
    pub original_file_name: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema, Type)]
#[sqlx(type_name = "ollama_models_statuses", rename_all = "snake_case")]
pub enum OllamaModelStatus {
    Initial,
    Pulled,
}

#[derive(Clone, Debug, Deserialize, FromRow, Serialize, ToSchema)]
pub struct OllamaModel {
    pub id: Uuid,
    pub name: String,
    pub o_name: Option<String>,
    pub o_details_family: Option<String>,
    pub o_details_families: Option<Vec<String>>,
    pub o_details_format: Option<String>,
    pub o_details_parameter_size: Option<String>,
    pub o_details_parent_model: Option<String>,
    pub o_details_quantization_level: Option<String>,
    pub o_digest: Option<String>,
    pub o_model: Option<String>,
    pub o_modified_at: Option<String>,
    pub o_size: Option<String>,
    pub status: OllamaModelStatus,
    pub created_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
}

pub const PARAMETER_NAME_AI_MODEL: &str = "AI_MODEL";
pub const PARAMETER_NAME_AI_SYSTEM_PROMPT: &str = "AI_SYSTEM_PROMPT";
pub const PARAMETER_NAME_AZURE_OPENAI_API_KEY: &str = "AZURE_OPENAI_API_KEY";
pub const PARAMETER_NAME_AZURE_OPENAI_DEPLOYMENT_ID: &str = "AZURE_OPENAI_DEPLOYMENT_ID";
pub const PARAMETER_NAME_AZURE_OPENAI_ENABLED: &str = "AZURE_OPENAI_ENABLED";
pub const PARAMETER_NAME_HUGGING_FACE_TOKEN_ACCESS: &str = "HUGGING_FACE_TOKEN_ACCESS";
pub const PARAMETER_NAME_NEXTCLOUD_PASSWORD: &str = "NEXTCLOUD_PASSWORD";
pub const PARAMETER_NAME_NEXTCLOUD_USERNAME: &str = "NEXTCLOUD_USERNAME";
pub const PARAMETER_NAME_OCTOPUS_API_URL: &str = "OCTOPUS_API_URL";
pub const PARAMETER_NAME_OCTOPUS_WS_URL: &str = "OCTOPUS_WS_URL";
pub const PARAMETER_NAME_OPENAI_API_KEY: &str = "OPENAI_API_KEY";
pub const PARAMETER_NAME_REGISTRATION_ALLOWED: &str = "REGISTRATION_ALLOWED";
pub const PARAMETER_NAME_SENDGRID_API_KEY: &str = "SENDGRID_API_KEY";

#[derive(Clone, Debug, Deserialize, FromRow, Serialize, ToSchema)]
pub struct Parameter {
    pub id: Uuid,
    pub name: String,
    pub value: String,
    pub created_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
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
    pub is_invited: bool,
    pub roles: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, FromRow, Serialize, ToSchema)]
pub struct UserExtended {
    pub id: Uuid,
    pub company_id: Uuid,
    pub email: String,
    pub is_enabled: bool,
    pub is_invited: bool,
    pub profile: Option<Profile>,
    pub roles: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema, Type)]
#[sqlx(type_name = "wasp_apps_instance_types", rename_all = "snake_case")]
pub enum WaspAppInstanceType {
    Private,
    Shared,
}

#[derive(Clone, Debug, Deserialize, FromRow, Serialize, ToSchema)]
pub struct WaspApp {
    pub id: Uuid,
    pub wasp_generator_id: Option<Uuid>,
    pub allowed_user_ids: Option<Vec<Uuid>>,
    #[serde(skip_serializing)]
    pub code: Vec<u8>,
    pub description: String,
    pub formatted_name: String,
    pub instance_type: WaspAppInstanceType,
    pub is_enabled: bool,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema, Type)]
#[sqlx(type_name = "wasp_generator_statuses", rename_all = "snake_case")]
pub enum WaspGeneratorStatus {
    Changed,
    Generated,
    Generating,
    Initial,
}

#[derive(Clone, Debug, Deserialize, FromRow, Serialize, ToSchema)]
pub struct WaspGenerator {
    pub id: Uuid,
    pub user_id: Uuid,
    pub wasp_app_id: Option<Uuid>,
    pub api_access_secret: Option<String>,
    pub api_access_url: Option<String>,
    #[serde(skip_serializing)]
    pub code: Option<Vec<u8>>,
    pub description: String,
    pub log: Option<String>,
    pub name: String,
    pub status: WaspGeneratorStatus,
    pub version: i32,
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
