use crate::error::AppError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, Type};
use std::{fmt, str::FromStr};
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
    #[schema(no_recursion)]
    pub request_content_type: AiFunctionRequestContentType,
    #[schema(no_recursion)]
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

impl fmt::Display for AiServiceRequiredPythonVersion {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let printable = match *self {
            AiServiceRequiredPythonVersion::Cp310 => "3.10".to_string(),
            AiServiceRequiredPythonVersion::Cp311 => "3.11".to_string(),
            AiServiceRequiredPythonVersion::Cp312 => "3.12".to_string(),
        };
        write!(f, "{printable}")
    }
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
    Restarting,
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
    pub ai_service_generator_id: Option<Uuid>,
    pub allowed_user_ids: Option<Vec<Uuid>>,
    pub color: Option<String>,
    pub device_map: Option<serde_json::Value>,
    pub health_check_execution_time: i32,
    #[schema(no_recursion)]
    pub health_check_status: AiServiceHealthCheckStatus,
    pub is_enabled: bool,
    pub original_file_name: String,
    pub original_function_body: String,
    pub parser_feedback: Option<String>,
    pub port: i32,
    pub priority: i32,
    pub processed_function_body: Option<String>,
    pub progress: i32,
    #[schema(no_recursion)]
    pub required_python_version: AiServiceRequiredPythonVersion,
    pub setup_execution_time: i32,
    #[schema(no_recursion)]
    pub setup_status: AiServiceSetupStatus,
    #[schema(no_recursion)]
    pub status: AiServiceStatus,
    #[schema(no_recursion)]
    pub r#type: AiServiceType,
    pub created_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
    pub health_check_at: Option<DateTime<Utc>>,
    pub setup_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema, Type)]
#[sqlx(type_name = "ai_service_generator_statuses", rename_all = "snake_case")]
pub enum AiServiceGeneratorStatus {
    Changed,
    Deployed,
    Generated,
    Generating,
    Initial,
    InternetResearchEnded,
    InternetResearchStarted,
}

#[derive(Clone, Debug, Deserialize, FromRow, Serialize, ToSchema)]
pub struct AiServiceGenerator {
    pub id: Uuid,
    pub user_id: Uuid,
    pub ai_service_id: Option<Uuid>,
    pub description: String,
    pub internet_research_results: Option<String>,
    pub log: Option<String>,
    pub name: String,
    pub original_function_body: Option<String>,
    pub sample_code: Option<String>,
    #[schema(no_recursion)]
    pub status: AiServiceGeneratorStatus,
    pub version: i32,
    pub created_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema, Type)]
#[sqlx(type_name = "chat_types", rename_all = "snake_case")]
pub enum ChatType {
    Chat,
    Task,
}

impl FromStr for ChatType {
    type Err = AppError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "Task" => Ok(ChatType::Task),
            _ => Ok(ChatType::Chat),
        }
    }
}

#[derive(Clone, Debug, Deserialize, FromRow, Serialize, ToSchema)]
pub struct Chat {
    pub id: Uuid,
    pub user_id: Uuid,
    pub workspace_id: Uuid,
    pub name: Option<String>,
    pub r#type: ChatType,
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
    pub scheduled_prompt_id: Option<Uuid>,
    pub simple_app_id: Option<Uuid>,
    pub suggested_ai_function_id: Option<Uuid>,
    pub suggested_simple_app_id: Option<Uuid>,
    pub suggested_wasp_app_id: Option<Uuid>,
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
    pub is_task_description: bool,
    pub message: String,
    pub progress: i32,
    pub response: Option<String>,
    pub simple_app_data: Option<serde_json::Value>,
    pub status: ChatMessageStatus,
    pub suggested_llm: Option<String>,
    pub suggested_model: Option<String>,
    pub suggested_secondary_model: bool,
    pub used_llm: Option<String>,
    pub used_model: Option<String>,
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
    pub scheduled_prompt_id: Option<Uuid>,
    pub simple_app_id: Option<Uuid>,
    pub suggested_ai_function_id: Option<Uuid>,
    pub suggested_simple_app_id: Option<Uuid>,
    pub suggested_wasp_app_id: Option<Uuid>,
    pub user_id: Uuid,
    pub wasp_app_id: Option<Uuid>,
    pub ai_function_call: Option<serde_json::Value>,
    pub ai_function_error: Option<String>,
    pub bad_reply_comment: Option<String>,
    pub bad_reply_is_harmful: bool,
    pub bad_reply_is_not_helpful: bool,
    pub bad_reply_is_not_true: bool,
    pub bypass_sensitive_information_filter: bool,
    #[schema(no_recursion)]
    pub chat_message_files: Vec<ChatMessageFile>,
    #[schema(no_recursion)]
    pub chat_message_pictures: Vec<ChatMessagePicture>,
    pub color: Option<String>,
    pub estimated_response_at: DateTime<Utc>,
    pub is_anonymized: bool,
    pub is_marked_as_not_sensitive: bool,
    pub is_not_checked_by_system: bool,
    pub is_sensitive: bool,
    pub is_task_description: bool,
    pub message: String,
    pub profile: Option<Profile>,
    pub progress: i32,
    pub response: Option<String>,
    pub simple_app_data: Option<serde_json::Value>,
    pub status: ChatMessageStatus,
    pub suggested_llm: Option<String>,
    pub suggested_model: Option<String>,
    pub suggested_secondary_model: bool,
    pub used_llm: Option<String>,
    pub used_model: Option<String>,
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
pub struct ChatTokenAudit {
    pub id: Uuid,
    pub chat_id: Uuid,
    pub chat_message_id: Uuid,
    pub company_id: Uuid,
    pub user_id: Uuid,
    pub input_tokens: i64,
    pub llm: String,
    pub model: String,
    pub output_tokens: i64,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, FromRow, Serialize, ToSchema)]
pub struct Company {
    pub id: Uuid,
    pub address: Option<String>,
    pub allowed_domains: Option<Vec<String>>,
    pub custom_style: Option<String>,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, FromRow, Serialize, ToSchema)]
pub struct LlmRouterConfig {
    pub id: Uuid,
    pub company_id: Uuid,
    pub user_id: Option<Uuid>,
    pub complexity: i32,
    pub suggested_llm: String,
    pub suggested_model: String,
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema, Type)]
#[sqlx(type_name = "files_access_types", rename_all = "snake_case")]
pub enum FileAccessType {
    Company,
    Owner,
}

impl FromStr for FileAccessType {
    type Err = AppError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "Company" => Ok(FileAccessType::Company),
            _ => Ok(FileAccessType::Owner),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema, Type)]
#[sqlx(type_name = "files_types", rename_all = "snake_case")]
pub enum FileType {
    Document,
    KnowledgeBook,
    Normal,
    TaskBook,
}

impl FromStr for FileType {
    type Err = AppError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "Document" => Ok(FileType::Document),
            "KnowledgeBook" => Ok(FileType::KnowledgeBook),
            "TaskBook" => Ok(FileType::TaskBook),
            _ => Ok(FileType::Normal),
        }
    }
}

#[derive(Clone, Debug, Deserialize, FromRow, Serialize, ToSchema)]
pub struct File {
    pub id: Uuid,
    pub company_id: Uuid,
    pub user_id: Uuid,
    #[schema(no_recursion)]
    pub access_type: FileAccessType,
    pub file_name: String,
    pub media_type: String,
    pub original_file_name: String,
    #[schema(no_recursion)]
    pub r#type: FileType,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, FromRow, Serialize, ToSchema)]
pub struct FileWithUrl {
    pub id: Uuid,
    pub company_id: Uuid,
    pub user_id: Uuid,
    #[schema(no_recursion)]
    pub access_type: FileAccessType,
    pub file_name: String,
    pub media_type: String,
    pub original_file_name: String,
    #[schema(no_recursion)]
    pub r#type: FileType,
    pub url: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl FileWithUrl {
    pub fn from_file(file: File, url_prefix: &str) -> FileWithUrl {
        let url = format!("{url_prefix}/{}", file.file_name);

        Self {
            id: file.id,
            company_id: file.company_id,
            user_id: file.user_id,
            access_type: file.access_type,
            file_name: file.file_name,
            media_type: file.media_type,
            original_file_name: file.original_file_name,
            r#type: file.r#type,
            url,
            created_at: file.created_at,
            updated_at: file.updated_at,
        }
    }
}

#[derive(Clone, Debug, Deserialize, FromRow, Serialize, ToSchema)]
pub struct InspectionDisabling {
    pub id: Uuid,
    pub user_id: Uuid,
    pub content_safety_disabled_until: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema, Type)]
#[sqlx(type_name = "kvs_access_types", rename_all = "snake_case")]
pub enum KVAccessType {
    Company,
    Owner,
}

impl FromStr for KVAccessType {
    type Err = AppError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "Company" => Ok(KVAccessType::Company),
            _ => Ok(KVAccessType::Owner),
        }
    }
}

#[derive(Clone, Debug, Deserialize, FromRow, Serialize, ToSchema)]
pub struct KV {
    pub id: Uuid,
    pub company_id: Uuid,
    pub user_id: Uuid,
    #[schema(no_recursion)]
    pub access_type: KVAccessType,
    pub kv_key: String,
    pub kv_value: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
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
    #[schema(no_recursion)]
    pub status: OllamaModelStatus,
    pub created_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
}

pub const PARAMETER_NAME_HUGGING_FACE_TOKEN_ACCESS: &str = "HUGGING_FACE_TOKEN_ACCESS";
pub const PARAMETER_NAME_MAIN_LLM: &str = "MAIN_LLM";
pub const PARAMETER_NAME_MAIN_LLM_ANTHROPIC_API_KEY: &str = "MAIN_LLM_ANTHROPIC_API_KEY";
pub const PARAMETER_NAME_MAIN_LLM_ANTHROPIC_PRIMARY_MODEL: &str =
    "MAIN_LLM_ANTHROPIC_PRIMARY_MODEL";
pub const PARAMETER_NAME_MAIN_LLM_AZURE_OPENAI_API_KEY: &str = "MAIN_LLM_AZURE_OPENAI_API_KEY";
pub const PARAMETER_NAME_MAIN_LLM_AZURE_OPENAI_DEPLOYMENT_ID: &str =
    "MAIN_LLM_AZURE_OPENAI_DEPLOYMENT_ID";
pub const PARAMETER_NAME_MAIN_LLM_AZURE_OPENAI_ENABLED: &str = "MAIN_LLM_AZURE_OPENAI_ENABLED";
pub const PARAMETER_NAME_MAIN_LLM_AZURE_OPENAI_URL: &str = "MAIN_LLM_AZURE_OPENAI_URL";
pub const PARAMETER_NAME_MAIN_LLM_OLLAMA_PRIMARY_MODEL: &str = "MAIN_LLM_OLLAMA_PRIMARY_MODEL";
pub const PARAMETER_NAME_MAIN_LLM_OPENAI_API_KEY: &str = "MAIN_LLM_OPENAI_API_KEY";
pub const PARAMETER_NAME_MAIN_LLM_OPENAI_PRIMARY_MODEL: &str = "MAIN_LLM_OPENAI_PRIMARY_MODEL";
pub const PARAMETER_NAME_MAIN_LLM_OPENAI_SECONDARY_MODEL: &str = "MAIN_LLM_OPENAI_SECONDARY_MODEL";
pub const PARAMETER_NAME_MAIN_LLM_OPENAI_TEMPERATURE: &str = "MAIN_LLM_OPENAI_TEMPERATURE";
pub const PARAMETER_NAME_MAIN_LLM_SYSTEM_PROMPT: &str = "MAIN_LLM_SYSTEM_PROMPT";
pub const PARAMETER_NAME_NEXTCLOUD_PASSWORD: &str = "NEXTCLOUD_PASSWORD";
pub const PARAMETER_NAME_NEXTCLOUD_URL: &str = "NEXTCLOUD_URL";
pub const PARAMETER_NAME_NEXTCLOUD_USERNAME: &str = "NEXTCLOUD_USERNAME";
pub const PARAMETER_NAME_OCTOPUS_API_URL: &str = "OCTOPUS_API_URL";
pub const PARAMETER_NAME_OCTOPUS_WS_URL: &str = "OCTOPUS_WS_URL";
pub const PARAMETER_NAME_REGISTRATION_ALLOWED: &str = "REGISTRATION_ALLOWED";
pub const PARAMETER_NAME_SCRAPINGBEE_API_KEY: &str = "SCRAPINGBEE_API_KEY";
pub const PARAMETER_NAME_SENDGRID_API_KEY: &str = "SENDGRID_API_KEY";
pub const PARAMETER_NAME_SUPERPROXY_ISP_PASSWORD: &str = "SUPERPROXY_ISP_PASSWORD";
pub const PARAMETER_NAME_SUPERPROXY_ISP_USER: &str = "SUPERPROXY_ISP_USER";
pub const PARAMETER_NAME_SUPERPROXY_SERP_PASSWORD: &str = "SUPERPROXY_SERP_PASSWORD";
pub const PARAMETER_NAME_SUPERPROXY_SERP_USER: &str = "SUPERPROXY_SERP_USER";
pub const PARAMETER_NAME_SUPERPROXY_ZONE_PASSWORD: &str = "SUPERPROXY_ZONE_PASSWORD";
pub const PARAMETER_NAME_SUPERPROXY_ZONE_USER: &str = "SUPERPROXY_ZONE_USER";

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
pub struct ScheduledPrompt {
    pub id: Uuid,
    pub chat_id: Uuid,
    pub user_id: Uuid,
    pub desired_schedule: String,
    pub job_id: Option<Uuid>,
    pub prompt: String,
    pub schedule: Option<String>,
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema, Type)]
#[sqlx(type_name = "task_statuses", rename_all = "snake_case")]
pub enum TaskStatus {
    Completed,
    NotCompleted,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema, Type)]
#[sqlx(type_name = "task_types", rename_all = "snake_case")]
pub enum TaskType {
    Normal,
    Test,
}

#[derive(Clone, Debug, Deserialize, FromRow, Serialize, ToSchema)]
pub struct Task {
    pub id: Uuid,
    pub assigned_user_chat_id: Option<Uuid>,
    pub assigned_user_id: Option<Uuid>,
    pub chat_id: Uuid,
    pub existing_task_id: Option<Uuid>,
    pub user_id: Uuid,
    pub workspace_id: Uuid,
    pub description: Option<String>,
    pub status: TaskStatus,
    pub test_result: Option<String>,
    pub title: Option<String>,
    pub r#type: TaskType,
    pub use_task_book_generation: bool,
    pub created_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, FromRow, Serialize, ToSchema)]
pub struct TaskTest {
    pub id: Uuid,
    pub task_id: Uuid,
    pub user_id: Uuid,
    pub answer: Option<String>,
    pub answer_is_correct: bool,
    pub question: String,
    pub created_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
}

pub const ROLE_ADMIN: &str = "ROLE_ADMIN";
pub const ROLE_COMPANY_ADMIN_USER: &str = "ROLE_COMPANY_ADMIN_USER";
pub const ROLE_PRIVATE_USER: &str = "ROLE_PRIVATE_USER";
pub const ROLE_PUBLIC_USER: &str = "ROLE_PUBLIC_USER";
pub const ROLE_SUPERVISOR: &str = "ROLE_SUPERVISOR";

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
    #[schema(no_recursion)]
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
    User,
}

impl FromStr for WaspAppInstanceType {
    type Err = AppError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "Private" => Ok(WaspAppInstanceType::Private),
            "User" => Ok(WaspAppInstanceType::User),
            _ => Ok(WaspAppInstanceType::Shared),
        }
    }
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
    #[schema(no_recursion)]
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
    PrivateScheduled,
    Public,
}

#[derive(Clone, Debug, Deserialize, FromRow, Serialize, ToSchema)]
pub struct Workspace {
    pub id: Uuid,
    pub company_id: Uuid,
    pub user_id: Uuid,
    pub name: String,
    #[schema(no_recursion)]
    pub r#type: WorkspacesType,
    pub created_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
}
