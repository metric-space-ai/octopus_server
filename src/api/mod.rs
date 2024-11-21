use crate::{
    ai::{
        code_tools::WaspAppMeta,
        function_call::{
            AiFunctionErrorResponse, AiFunctionFileResponse, AiFunctionResponse,
            AiFunctionTextResponse,
        },
    },
    api::{
        ai_functions::{AiFunctionDirectCallPost, AiFunctionPut},
        ai_service_generators::{
            AiServiceGeneratorGeneratePost, AiServiceGeneratorPost, AiServiceGeneratorPut,
        },
        ai_services::{
            AiServiceAllowedUsersPut, AiServiceColorPut, AiServiceConfigurationPut,
            AiServiceOperation, AiServiceOperationPost, AiServiceOperationResponse,
            AiServicePriorityPut,
        },
        auth::{
            change_password, change_password::ChangePasswordPut, login, login::LoginPost, logout,
            register, register::RegisterPost,
        },
        chat_messages::{ChatMessageFlagPut, ChatMessagePost, ChatMessagePut},
        chats::{ChatPost, ChatPut},
        companies::CompanyPut,
        example_prompt_categories::{ExamplePromptCategoryPost, ExamplePromptCategoryPut},
        example_prompts::{ExamplePromptPost, ExamplePromptPut},
        inspection_disablings::InspectionDisablingPost,
        kvs::{KVPost, KVPut},
        ollama_models::{OllamaModelPost, OllamaModelPut},
        parameters::{ParameterPost, ParameterPut},
        password_resets::{PasswordResetPost, PasswordResetPut},
        profiles::ProfilePut,
        scheduled_prompts::{ScheduledPromptPost, ScheduledPromptPut},
        setup::{SetupInfoResponse, SetupPost},
        task_tests::{TaskTestAnswerPut, TaskTestPost, TaskTestPut},
        tasks::{TaskPost, TaskPut},
        users::{UserInvitationPost, UserPost, UserPut},
        version::VersionInfoResponse,
        wasp_apps::{AutoLoginUser, WaspAppAllowedUsersPut},
        wasp_generators::{WaspGeneratorDeployPost, WaspGeneratorPost, WaspGeneratorPut},
        workspaces::{WorkspacePost, WorkspacePut},
    },
    context::Context,
    entity::{
        AiFunction, AiFunctionRequestContentType, AiFunctionResponseContentType, AiService,
        AiServiceGenerator, AiServiceGeneratorStatus, AiServiceHealthCheckStatus,
        AiServiceRequiredPythonVersion, AiServiceSetupStatus, AiServiceStatus, AiServiceType,
        CachedFile, Chat, ChatActivity, ChatAudit, ChatMessage, ChatMessageExtended,
        ChatMessageFile, ChatMessagePicture, ChatMessageStatus, ChatPicture, ChatTokenAudit,
        Company, ExamplePrompt, ExamplePromptCategory, FileAccessType, FileType, FileWithUrl,
        InspectionDisabling, KVAccessType, NextcloudFile, OllamaModel, OllamaModelStatus,
        Parameter, PasswordResetToken, Profile, ScheduledPrompt, SimpleApp, Task, TaskStatus,
        TaskTest, TaskType, User, UserExtended, WaspApp, WaspAppInstanceType, WaspGenerator,
        WaspGeneratorStatus, Workspace, WorkspacesType, KV,
    },
    error::ResponseError,
    process_manager::{Process, ProcessState, ProcessType},
    server_resources::{Gpu, ServerResources},
    session::{SessionResponse, SessionResponseData},
    Result,
};
use axum::{
    error_handling::HandleErrorLayer,
    extract::DefaultBodyLimit,
    http::{header, Method, StatusCode},
    routing::{delete, get, post, put},
    Router,
};
use std::{sync::Arc, time::Duration};
use tower::{BoxError, ServiceBuilder};
use tower_http::{
    cors::{Any, CorsLayer},
    limit::RequestBodyLimitLayer,
    services::ServeDir,
    trace::TraceLayer,
};
use utoipa::{
    openapi::security::{ApiKey, ApiKeyValue, SecurityScheme},
    Modify, OpenApi,
};
use utoipa_swagger_ui::SwaggerUi;

mod ai_functions;
pub mod ai_service_generators;
mod ai_services;
mod auth;
mod cached_files;
mod chat_activities;
mod chat_audits;
mod chat_message_files;
mod chat_message_pictures;
mod chat_messages;
mod chat_pictures;
mod chat_token_audits;
mod chats;
mod companies;
mod example_prompt_categories;
mod example_prompts;
mod files;
mod inspection_disablings;
mod kvs;
mod llm_proxy;
mod llms;
mod nextcloud_files;
mod nextcloud_raw_files;
mod ollama_models;
mod parameters;
mod password_resets;
mod process_manager;
mod profile_pictures;
mod profiles;
mod scheduled_prompts;
mod scraper;
mod server_resources;
mod setup;
mod simple_apps;
mod task_tests;
mod tasks;
mod users;
mod version;
mod wasp_apps;
mod wasp_generators;
mod workspaces;

#[allow(clippy::too_many_lines)]
pub fn router(context: Arc<Context>) -> Result<Router> {
    #[derive(OpenApi)]
    #[openapi(
        components(
            schemas(
                AiFunction,
                AiFunctionDirectCallPost,
                AiFunctionErrorResponse,
                AiFunctionFileResponse,
                AiFunctionPut,
                AiFunctionRequestContentType,
                AiFunctionResponse,
                AiFunctionResponseContentType,
                AiFunctionTextResponse,
                AiService,
                AiServiceAllowedUsersPut,
                AiServiceColorPut,
                AiServiceConfigurationPut,
                AiServiceGenerator,
                AiServiceGeneratorGeneratePost,
                AiServiceGeneratorPost,
                AiServiceGeneratorPut,
                AiServiceGeneratorStatus,
                AiServiceHealthCheckStatus,
                AiServiceOperation,
                AiServiceOperationPost,
                AiServiceOperationResponse,
                AiServicePriorityPut,
                AiServiceRequiredPythonVersion,
                AiServiceSetupStatus,
                AiServiceStatus,
                AiServiceType,
                AutoLoginUser,
                CachedFile,
                ChangePasswordPut,
                Chat,
                ChatActivity,
                ChatAudit,
                ChatMessage,
                ChatMessageExtended,
                ChatMessageFile,
                ChatMessageFlagPut,
                ChatMessagePicture,
                ChatMessagePost,
                ChatMessagePut,
                ChatMessageStatus,
                ChatPicture,
                ChatPost,
                ChatPut,
                ChatTokenAudit,
                Company,
                CompanyPut,
                ExamplePrompt,
                ExamplePromptCategory,
                ExamplePromptCategoryPost,
                ExamplePromptCategoryPut,
                ExamplePromptPost,
                ExamplePromptPut,
                FileAccessType,
                FileType,
                FileWithUrl,
                Gpu,
                InspectionDisabling,
                InspectionDisablingPost,
                KV,
                KVAccessType,
                KVPost,
                KVPut,
                LoginPost,
                NextcloudFile,
                OllamaModel,
                OllamaModelPost,
                OllamaModelPut,
                OllamaModelStatus,
                Parameter,
                ParameterPost,
                ParameterPut,
                PasswordResetPost,
                PasswordResetPut,
                PasswordResetToken,
                Process,
                ProcessState,
                ProcessType,
                Profile,
                ProfilePut,
                RegisterPost,
                ResponseError,
                ScheduledPrompt,
                ScheduledPromptPost,
                ScheduledPromptPut,
                ServerResources,
                SessionResponse,
                SessionResponseData,
                SetupInfoResponse,
                SetupPost,
                SimpleApp,
                Task,
                TaskPost,
                TaskPut,
                TaskStatus,
                TaskTest,
                TaskTestAnswerPut,
                TaskTestPost,
                TaskTestPut,
                TaskType,
                User,
                UserExtended,
                UserInvitationPost,
                UserPost,
                UserPut,
                VersionInfoResponse,
                WaspApp,
                WaspAppAllowedUsersPut,
                WaspAppInstanceType,
                WaspAppMeta,
                WaspGenerator,
                WaspGeneratorDeployPost,
                WaspGeneratorPost,
                WaspGeneratorPut,
                WaspGeneratorStatus,
                Workspace,
                WorkspacePost,
                WorkspacePut,
                WorkspacesType,
            )
        ),
        modifiers(&SecurityAddon),
        paths(
            ai_functions::delete,
            ai_functions::direct_call,
            ai_functions::list,
            ai_functions::list_all,
            ai_functions::read,
            ai_functions::update,
            ai_service_generators::create,
            ai_service_generators::delete,
            ai_service_generators::deploy,
            ai_service_generators::download_original_function_body,
            ai_service_generators::generate,
            ai_service_generators::list,
            ai_service_generators::read,
            ai_service_generators::update,
            ai_services::allowed_users,
            ai_services::color,
            ai_services::configuration,
            ai_services::create,
            ai_services::delete,
            ai_services::diff,
            ai_services::download_original_function_body,
            ai_services::download_processed_function_body,
            ai_services::installation,
            ai_services::list,
            ai_services::logs,
            ai_services::operation,
            ai_services::priority,
            ai_services::read,
            ai_services::update,
            cached_files::create,
            cached_files::delete,
            cached_files::list,
            cached_files::read,
            cached_files::update,
            change_password::change_password,
            chat_activities::create,
            chat_activities::list,
            chat_audits::list,
            chat_audits::read,
            chat_messages::anonymize,
            chat_messages::create,
            chat_messages::delete,
            chat_messages::flag,
            chat_messages::history,
            chat_messages::latest,
            chat_messages::list,
            chat_messages::not_sensitive,
            chat_messages::read,
            chat_messages::regenerate,
            chat_messages::update,
            chat_message_files::delete,
            chat_message_files::list,
            chat_message_files::read,
            chat_message_files::read_render_html,
            chat_message_pictures::create,
            chat_message_pictures::delete,
            chat_message_pictures::read,
            chat_message_pictures::update,
            chat_pictures::create,
            chat_pictures::delete,
            chat_pictures::read,
            chat_pictures::update,
            chat_token_audits::list,
            chat_token_audits::read,
            chat_token_audits::report,
            chats::create,
            chats::delete,
            chats::latest,
            chats::list,
            chats::read,
            chats::update,
            companies::read,
            companies::update,
            example_prompt_categories::create,
            example_prompt_categories::delete,
            example_prompt_categories::list,
            example_prompt_categories::read,
            example_prompt_categories::update,
            example_prompts::create,
            example_prompts::delete,
            example_prompts::list,
            example_prompts::list_by_category,
            example_prompts::read,
            example_prompts::update,
            files::create,
            files::delete,
            files::list,
            files::read,
            files::update,
            inspection_disablings::create,
            inspection_disablings::delete,
            inspection_disablings::read,
            kvs::create,
            kvs::delete,
            kvs::list,
            kvs::read,
            kvs::update,
            llm_proxy::proxy,
            llms::list,
            login::login,
            logout::logout,
            nextcloud_files::create,
            nextcloud_files::delete,
            nextcloud_files::list,
            nextcloud_files::read,
            nextcloud_files::update,
            nextcloud_raw_files::create,
            nextcloud_raw_files::list,
            ollama_models::create,
            ollama_models::delete,
            ollama_models::models,
            ollama_models::list,
            ollama_models::read,
            ollama_models::update,
            parameters::create,
            parameters::delete,
            parameters::list,
            parameters::names,
            parameters::read,
            parameters::update,
            password_resets::change_password,
            password_resets::request,
            password_resets::validate,
            process_manager::list,
            profiles::read,
            profiles::update,
            profile_pictures::delete,
            profile_pictures::update,
            register::register,
            scheduled_prompts::create,
            scheduled_prompts::delete,
            scheduled_prompts::list,
            scheduled_prompts::read,
            scheduled_prompts::update,
            scraper::scraper,
            scraper::scraper_search_service,
            scraper::scraper_service,
            server_resources::info,
            setup::info,
            setup::setup,
            simple_apps::code,
            simple_apps::create,
            simple_apps::delete,
            simple_apps::list,
            simple_apps::read,
            simple_apps::update,
            task_tests::answer,
            task_tests::create,
            task_tests::delete,
            task_tests::list,
            task_tests::read,
            task_tests::update,
            tasks::create,
            tasks::delete,
            tasks::latest,
            tasks::latest_assigned,
            tasks::list,
            tasks::list_assigned,
            tasks::read,
            tasks::update,
            users::create,
            users::delete,
            users::invitation,
            users::list,
            users::read,
            users::roles,
            users::update,
            version::info,
            wasp_apps::allowed_users,
            wasp_apps::auto_login,
            wasp_apps::create,
            wasp_apps::delete,
            wasp_apps::extract_meta,
            wasp_apps::list,
            wasp_apps::logs,
            wasp_apps::proxy_backend,
            wasp_apps::proxy_backend_web_socket,
            wasp_apps::proxy_frontend,
            wasp_apps::read,
            wasp_apps::update,
            wasp_generators::create,
            wasp_generators::delete,
            wasp_generators::deploy,
            wasp_generators::generate,
            wasp_generators::list,
            wasp_generators::logs,
            wasp_generators::proxy_backend,
            wasp_generators::proxy_backend_web_socket,
            wasp_generators::proxy_frontend,
            wasp_generators::read,
            wasp_generators::update,
            workspaces::create,
            workspaces::delete,
            workspaces::list,
            workspaces::read,
            workspaces::update,
        ),
        tags(
            (name = "ai_functions", description = "AI functions API."),
            (name = "ai_service_generators", description = "AI service generators API."),
            (name = "ai_services", description = "AI services API."),
            (name = "cached_files", description = "Cached files API."),
            (name = "change_password", description = "Change password API."),
            (name = "chats", description = "Chats API."),
            (name = "chat_activities", description = "Chat activities API."),
            (name = "chat_audits", description = "Chat audits API."),
            (name = "chat_messages", description = "Chat messages API."),
            (name = "chat_message_files", description = "Chat message files API."),
            (name = "chat_message_pictures", description = "Chat message pictures API."),
            (name = "chat_pictures", description = "Chat pictures API."),
            (name = "chat_token_audits", description = "Chat token audits API."),
            (name = "companies", description = "Companies API."),
            (name = "example_prompt_categories", description = "Example prompt categories API."),
            (name = "example_prompts", description = "Example prompts API."),
            (name = "files", description = "Files API."),
            (name = "inspection_disablings", description = "Inspection disablings API."),
            (name = "kvs", description = "KVs API."),
            (name = "llm_proxy", description = "LLM proxy API."),
            (name = "llms", description = "LLMs API."),
            (name = "login", description = "Login API."),
            (name = "logout", description = "Logout API."),
            (name = "nextcloud_files", description = "Nextcloud files API."),
            (name = "nextcloud_raw_files", description = "Nextcloud raw files API."),
            (name = "ollama_models", description = "Ollama models API."),
            (name = "parameters", description = "Parameters API."),
            (name = "password_resets", description = "Password resets API."),
            (name = "process_manager", description = "Process manager API."),
            (name = "profiles", description = "Profiles API."),
            (name = "profile_pictures", description = "Profile pictures API."),
            (name = "register", description = "Register API."),
            (name = "scheduled_prompts", description = "Scheduled prompts API."),
            (name = "scraper", description = "Scraper API."),
            (name = "server_resources", description = "Server resources API."),
            (name = "setup", description = "Setup API."),
            (name = "simple_apps", description = "Simple apps API."),
            (name = "task_tests", description = "Task tests API."),
            (name = "tasks", description = "Tasks API."),
            (name = "users", description = "Users API."),
            (name = "version", description = "Version API."),
            (name = "wasp_apps", description = "Wasp apps API."),
            (name = "wasp_generators", description = "Wasp generators API."),
            (name = "workspaces", description = "Workspaces API."),
        )
    )]
    struct ApiDoc;

    struct SecurityAddon;

    impl Modify for SecurityAddon {
        fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
            if let Some(components) = openapi.components.as_mut() {
                components.add_security_scheme(
                    "api_key",
                    SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::new("X-Auth-Token"))),
                );
            }
        }
    }

    let router = Router::new()
        .nest_service("/public", ServeDir::new("public"))
        .merge(SwaggerUi::new("/swagger-ui").url("/api-doc/openapi.json", ApiDoc::openapi()))
        .route("/api/v1/auth", delete(logout::logout).post(login::login))
        .route("/api/v1/auth/register", post(register::register))
        .route(
            "/api/v1/auth/:user_id",
            put(change_password::change_password),
        )
        .route("/api/v1/ai-functions", get(ai_functions::list_all))
        .route(
            "/api/v1/ai-functions/direct-call",
            post(ai_functions::direct_call),
        )
        .route(
            "/api/v1/ai-functions/:ai_service_id",
            get(ai_functions::list),
        )
        .route(
            "/api/v1/ai-functions/:ai_service_id/:ai_function_id",
            delete(ai_functions::delete)
                .get(ai_functions::read)
                .put(ai_functions::update),
        )
        .route(
            "/api/v1/ai-service-generators",
            get(ai_service_generators::list).post(ai_service_generators::create),
        )
        .route(
            "/api/v1/ai-service-generators/:id",
            delete(ai_service_generators::delete)
                .get(ai_service_generators::read)
                .put(ai_service_generators::update),
        )
        .route(
            "/api/v1/ai-service-generators/:id/deploy",
            post(ai_service_generators::deploy),
        )
        .route(
            "/api/v1/ai-service-generators/:id/download-original-function-body",
            get(ai_service_generators::download_original_function_body),
        )
        .route(
            "/api/v1/ai-service-generators/:id/generate",
            post(ai_service_generators::generate),
        )
        .route(
            "/api/v1/ai-services",
            get(ai_services::list).post(ai_services::create),
        )
        .route(
            "/api/v1/ai-services/:id/allowed-users",
            put(ai_services::allowed_users),
        )
        .route("/api/v1/ai-services/:id/color", put(ai_services::color))
        .route(
            "/api/v1/ai-services/:id/configuration",
            put(ai_services::configuration),
        )
        .route("/api/v1/ai-services/:id/diff", get(ai_services::diff))
        .route(
            "/api/v1/ai-services/:id/download-original-function-body",
            get(ai_services::download_original_function_body),
        )
        .route(
            "/api/v1/ai-services/:id/download-processed-function-body",
            get(ai_services::download_processed_function_body),
        )
        .route(
            "/api/v1/ai-services/:id/installation",
            put(ai_services::installation),
        )
        .route("/api/v1/ai-services/:id/logs", get(ai_services::logs))
        .route(
            "/api/v1/ai-services/:id/priority",
            put(ai_services::priority),
        )
        .route(
            "/api/v1/ai-services/:id",
            delete(ai_services::delete)
                .get(ai_services::read)
                .post(ai_services::operation)
                .put(ai_services::update),
        )
        .route(
            "/api/v1/cached-files",
            get(cached_files::list).post(cached_files::create),
        )
        .route(
            "/api/v1/cached-files/:cache_key",
            delete(cached_files::delete)
                .get(cached_files::read)
                .put(cached_files::update),
        )
        .route(
            "/api/v1/chat-activities/:chat_id",
            get(chat_activities::list).post(chat_activities::create),
        )
        .route("/api/v1/chat-audits", get(chat_audits::list))
        .route("/api/v1/chat-audits/:chat_audit_id", get(chat_audits::read))
        .route(
            "/api/v1/chat-messages/:chat_id",
            get(chat_messages::list).post(chat_messages::create),
        )
        .route(
            "/api/v1/chat-messages/:chat_id/latest",
            get(chat_messages::latest),
        )
        .route(
            "/api/v1/chat-messages/:chat_id/:chat_message_id",
            delete(chat_messages::delete)
                .get(chat_messages::read)
                .post(chat_messages::regenerate)
                .put(chat_messages::update),
        )
        .route(
            "/api/v1/chat-messages/:chat_id/:chat_message_id/anonymize",
            put(chat_messages::anonymize),
        )
        .route(
            "/api/v1/chat-messages/:chat_id/:chat_message_id/flag",
            put(chat_messages::flag),
        )
        .route(
            "/api/v1/chat-messages/:chat_id/:chat_message_id/not-sensitive",
            put(chat_messages::not_sensitive),
        )
        .route(
            "/api/v1/chat-messages/:chat_message_id/history",
            get(chat_messages::history),
        )
        .route(
            "/api/v1/chat-message-files/:chat_message_id",
            get(chat_message_files::list),
        )
        .route(
            "/api/v1/chat-message-files/:chat_message_id/:chat_message_file_id",
            delete(chat_message_files::delete).get(chat_message_files::read),
        )
        .route(
            "/api/v1/chat-message-files/:chat_message_id/:chat_message_file_id/render-html",
            get(chat_message_files::read_render_html),
        )
        .route(
            "/api/v1/chat-message-pictures/:chat_message_id",
            post(chat_message_pictures::create),
        )
        .route(
            "/api/v1/chat-message-pictures/:chat_message_id/:chat_message_picture_id",
            delete(chat_message_pictures::delete)
                .get(chat_message_pictures::read)
                .put(chat_message_pictures::update),
        )
        .route(
            "/api/v1/chat-pictures/:chat_id",
            post(chat_pictures::create),
        )
        .route(
            "/api/v1/chat-pictures/:chat_id/:chat_picture_id",
            delete(chat_pictures::delete)
                .get(chat_pictures::read)
                .put(chat_pictures::update),
        )
        .route("/api/v1/chat-token-audits", get(chat_token_audits::list))
        .route(
            "/api/v1/chat-token-audits/:chat_token_audit_id",
            get(chat_token_audits::read),
        )
        .route(
            "/api/v1/chat-token-audits/:company_id/report",
            get(chat_token_audits::report),
        )
        .route(
            "/api/v1/chats/:workspace_id",
            get(chats::list).post(chats::create),
        )
        .route("/api/v1/chats/:workspace_id/latest", get(chats::latest))
        .route(
            "/api/v1/chats/:workspace_id/:chat_id",
            delete(chats::delete).get(chats::read).put(chats::update),
        )
        .route(
            "/api/v1/companies/:id",
            get(companies::read).put(companies::update),
        )
        .route(
            "/api/v1/example-prompts",
            get(example_prompts::list).post(example_prompts::create),
        )
        .route(
            "/api/v1/example-prompts/by-category/:example_prompt_category_id",
            get(example_prompts::list_by_category),
        )
        .route(
            "/api/v1/example-prompts/:id",
            delete(example_prompts::delete)
                .get(example_prompts::read)
                .put(example_prompts::update),
        )
        .route(
            "/api/v1/example-prompt-categories",
            get(example_prompt_categories::list).post(example_prompt_categories::create),
        )
        .route(
            "/api/v1/example-prompt-categories/:id",
            delete(example_prompt_categories::delete)
                .get(example_prompt_categories::read)
                .put(example_prompt_categories::update),
        )
        .route("/api/v1/files", get(files::list).post(files::create))
        .route(
            "/api/v1/files/:id",
            delete(files::delete).get(files::read).put(files::update),
        )
        .route(
            "/api/v1/inspection-disablings/:user_id",
            delete(inspection_disablings::delete)
                .get(inspection_disablings::read)
                .post(inspection_disablings::create),
        )
        .route("/api/v1/kvs", get(kvs::list).post(kvs::create))
        .route(
            "/api/v1/kvs/:id",
            delete(kvs::delete).get(kvs::read).put(kvs::update),
        )
        .route(
            "/api/v1/llm-proxy/*pass",
            delete(llm_proxy::proxy)
                .get(llm_proxy::proxy)
                .post(llm_proxy::proxy)
                .put(llm_proxy::proxy),
        )
        .route("/api/v1/llms", get(llms::list))
        .route(
            "/api/v1/nextcloud-files",
            get(nextcloud_files::list).post(nextcloud_files::create),
        )
        .route(
            "/api/v1/nextcloud-files/:id",
            delete(nextcloud_files::delete)
                .get(nextcloud_files::read)
                .put(nextcloud_files::update),
        )
        .route(
            "/api/v1/nextcloud-raw-files",
            get(nextcloud_raw_files::list).post(nextcloud_raw_files::create),
        )
        .route(
            "/api/v1/ollama-models",
            get(ollama_models::list).post(ollama_models::create),
        )
        .route("/api/v1/ollama-models/models", get(ollama_models::models))
        .route(
            "/api/v1/ollama-models/:id",
            delete(ollama_models::delete)
                .get(ollama_models::read)
                .put(ollama_models::update),
        )
        .route(
            "/api/v1/parameters",
            get(parameters::list).post(parameters::create),
        )
        .route("/api/v1/parameters/names", get(parameters::names))
        .route(
            "/api/v1/parameters/:id",
            delete(parameters::delete)
                .get(parameters::read)
                .put(parameters::update),
        )
        .route("/api/v1/password-resets", post(password_resets::request))
        .route(
            "/api/v1/password-resets/:token",
            get(password_resets::validate).put(password_resets::change_password),
        )
        .route("/api/v1/process-manager", get(process_manager::list))
        .route(
            "/api/v1/profile-pictures/:user_id",
            delete(profile_pictures::delete).put(profile_pictures::update),
        )
        .route(
            "/api/v1/profiles/:user_id",
            get(profiles::read).put(profiles::update),
        )
        .route(
            "/api/v1/scheduled-prompts",
            get(scheduled_prompts::list).post(scheduled_prompts::create),
        )
        .route(
            "/api/v1/scheduled-prompts/:id",
            delete(scheduled_prompts::delete)
                .get(scheduled_prompts::read)
                .put(scheduled_prompts::update),
        )
        .route("/api/v1/scraper", get(scraper::scraper))
        .route(
            "/api/v1/scraper-search-service",
            get(scraper::scraper_search_service),
        )
        .route("/api/v1/scraper-service", get(scraper::scraper_service))
        .route("/api/v1/server-resources", get(server_resources::info))
        .route("/api/v1/setup", get(setup::info).post(setup::setup))
        .route(
            "/api/v1/simple-apps",
            get(simple_apps::list).post(simple_apps::create),
        )
        .route("/api/v1/simple-apps/:id/code", get(simple_apps::code))
        .route(
            "/api/v1/simple-apps/:id",
            delete(simple_apps::delete)
                .get(simple_apps::read)
                .put(simple_apps::update),
        )
        .route(
            "/api/v1/tasks/:workspace_id",
            get(tasks::list).post(tasks::create),
        )
        .route(
            "/api/v1/tasks/:workspace_id/assigned",
            get(tasks::list_assigned),
        )
        .route("/api/v1/tasks/:workspace_id/latest", get(tasks::latest))
        .route(
            "/api/v1/tasks/:workspace_id/latest/assigned",
            get(tasks::latest_assigned),
        )
        .route(
            "/api/v1/tasks/:workspace_id/:task_id",
            delete(tasks::delete).get(tasks::read).put(tasks::update),
        )
        .route(
            "/api/v1/task-tests/:task_id",
            get(task_tests::list).post(task_tests::create),
        )
        .route(
            "/api/v1/task-tests/:task_id/:task_test_id",
            delete(task_tests::delete)
                .get(task_tests::read)
                .put(task_tests::update),
        )
        .route(
            "/api/v1/task-tests/:task_id/:task_test_id/answer",
            put(task_tests::answer),
        )
        .route("/api/v1/users", get(users::list).post(users::create))
        .route("/api/v1/users/invitation", post(users::invitation))
        .route("/api/v1/users/roles", get(users::roles))
        .route(
            "/api/v1/users/:user_id",
            delete(users::delete).get(users::read).put(users::update),
        )
        .route("/api/v1/version", get(version::info))
        .route(
            "/api/v1/wasp-apps",
            get(wasp_apps::list).post(wasp_apps::create),
        )
        .route("/api/v1/wasp-apps/auto-login", get(wasp_apps::auto_login))
        .route(
            "/api/v1/wasp-apps/extract-meta",
            post(wasp_apps::extract_meta),
        )
        .route(
            "/api/v1/wasp-apps/:id/allowed-users",
            put(wasp_apps::allowed_users),
        )
        .route(
            "/api/v1/wasp-apps/:id/:chat_message_id/logs",
            get(wasp_apps::logs),
        )
        .route(
            "/api/v1/wasp-apps/:id/:chat_message_id/proxy-backend",
            delete(wasp_apps::proxy_backend)
                .get(wasp_apps::proxy_backend)
                .post(wasp_apps::proxy_backend)
                .put(wasp_apps::proxy_backend),
        )
        .route(
            "/api/v1/wasp-apps/:id/:chat_message_id/proxy-backend/*pass",
            delete(wasp_apps::proxy_backend)
                .get(wasp_apps::proxy_backend)
                .post(wasp_apps::proxy_backend)
                .put(wasp_apps::proxy_backend),
        )
        .route(
            "/api/v1/wasp-apps/:id/:chat_message_id/proxy-frontend",
            delete(wasp_apps::proxy_frontend)
                .get(wasp_apps::proxy_frontend)
                .post(wasp_apps::proxy_frontend)
                .put(wasp_apps::proxy_frontend),
        )
        .route(
            "/api/v1/wasp-apps/:id/:chat_message_id/proxy-frontend/",
            delete(wasp_apps::proxy_frontend)
                .get(wasp_apps::proxy_frontend)
                .post(wasp_apps::proxy_frontend)
                .put(wasp_apps::proxy_frontend),
        )
        .route(
            "/api/v1/wasp-apps/:id/:chat_message_id/proxy-frontend/*pass",
            delete(wasp_apps::proxy_frontend)
                .get(wasp_apps::proxy_frontend)
                .post(wasp_apps::proxy_frontend)
                .put(wasp_apps::proxy_frontend),
        )
        .route(
            "/api/v1/wasp-apps/:id",
            delete(wasp_apps::delete)
                .get(wasp_apps::read)
                .put(wasp_apps::update),
        )
        .route(
            "/api/v1/wasp-generators",
            get(wasp_generators::list).post(wasp_generators::create),
        )
        .route(
            "/api/v1/wasp-generators/:id/logs",
            get(wasp_generators::logs),
        )
        .route(
            "/api/v1/wasp-generators/:id/proxy-backend",
            delete(wasp_generators::proxy_backend)
                .get(wasp_generators::proxy_backend)
                .post(wasp_generators::proxy_backend)
                .put(wasp_generators::proxy_backend),
        )
        .route(
            "/api/v1/wasp-generators/:id/proxy-backend/*pass",
            delete(wasp_generators::proxy_backend)
                .get(wasp_generators::proxy_backend)
                .post(wasp_generators::proxy_backend)
                .put(wasp_generators::proxy_backend),
        )
        .route(
            "/api/v1/wasp-generators/:id/proxy-frontend",
            delete(wasp_generators::proxy_frontend)
                .get(wasp_generators::proxy_frontend)
                .post(wasp_generators::proxy_frontend)
                .put(wasp_generators::proxy_frontend),
        )
        .route(
            "/api/v1/wasp-generators/:id/proxy-frontend/",
            delete(wasp_generators::proxy_frontend)
                .get(wasp_generators::proxy_frontend)
                .post(wasp_generators::proxy_frontend)
                .put(wasp_generators::proxy_frontend),
        )
        .route(
            "/api/v1/wasp-generators/:id/proxy-frontend/*pass",
            delete(wasp_generators::proxy_frontend)
                .get(wasp_generators::proxy_frontend)
                .post(wasp_generators::proxy_frontend)
                .put(wasp_generators::proxy_frontend),
        )
        .route(
            "/api/v1/wasp-generators/:id",
            delete(wasp_generators::delete)
                .get(wasp_generators::read)
                .put(wasp_generators::update),
        )
        .route(
            "/api/v1/wasp-generators/:id/deploy",
            post(wasp_generators::deploy),
        )
        .route(
            "/api/v1/wasp-generators/:id/generate",
            post(wasp_generators::generate),
        )
        .route(
            "/api/v1/workspaces",
            get(workspaces::list).post(workspaces::create),
        )
        .route(
            "/api/v1/workspaces/:id",
            delete(workspaces::delete)
                .get(workspaces::read)
                .put(workspaces::update),
        )
        .layer(DefaultBodyLimit::disable())
        .layer(RequestBodyLimitLayer::new(512 * 1024 * 1024))
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(vec![
                    Method::DELETE,
                    Method::GET,
                    Method::OPTIONS,
                    Method::POST,
                    Method::PUT,
                ])
                .allow_headers(vec![
                    header::CONTENT_TYPE,
                    header::HeaderName::from_lowercase(b"x-auth-token")?,
                ]),
        )
        .layer(
            ServiceBuilder::new()
                .layer(HandleErrorLayer::new(|error: BoxError| async move {
                    if error.is::<tower::timeout::error::Elapsed>() {
                        Ok(StatusCode::REQUEST_TIMEOUT)
                    } else {
                        Err((
                            StatusCode::INTERNAL_SERVER_ERROR,
                            format!("Unhandled internal error: {error}"),
                        ))
                    }
                }))
                .timeout(Duration::from_secs(1800))
                .layer(TraceLayer::new_for_http())
                .into_inner(),
        )
        .with_state(context);

    Ok(router)
}

pub fn ws_router(context: Arc<Context>) -> Result<Router> {
    #[derive(OpenApi)]
    #[openapi(
        modifiers(&SecurityAddon),
        paths(
            wasp_apps::proxy_backend_web_socket,
        ),
        tags(
            (name = "wasp_apps", description = "Wasp apps API."),
        )
    )]
    struct ApiDoc;

    struct SecurityAddon;

    impl Modify for SecurityAddon {
        fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
            if let Some(components) = openapi.components.as_mut() {
                components.add_security_scheme(
                    "api_key",
                    SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::new("X-Auth-Token"))),
                );
            }
        }
    }

    let router = Router::new()
        .merge(SwaggerUi::new("/ws/swagger-ui").url("/ws/api-doc/openapi.json", ApiDoc::openapi()))
        .route(
            "/ws/api/v1/wasp-apps/:id/:chat_message_id/proxy-backend/",
            delete(wasp_apps::proxy_backend_web_socket)
                .get(wasp_apps::proxy_backend_web_socket)
                .post(wasp_apps::proxy_backend_web_socket)
                .put(wasp_apps::proxy_backend_web_socket),
        )
        .route(
            "/ws/api/v1/wasp-generators/:id/proxy-backend/",
            delete(wasp_generators::proxy_backend_web_socket)
                .get(wasp_generators::proxy_backend_web_socket)
                .post(wasp_generators::proxy_backend_web_socket)
                .put(wasp_generators::proxy_backend_web_socket),
        )
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(vec![
                    Method::DELETE,
                    Method::GET,
                    Method::OPTIONS,
                    Method::POST,
                    Method::PUT,
                ])
                .allow_headers(vec![
                    header::CONTENT_TYPE,
                    header::HeaderName::from_lowercase(b"x-auth-token")?,
                ]),
        )
        .layer(
            ServiceBuilder::new()
                .layer(HandleErrorLayer::new(|error: BoxError| async move {
                    if error.is::<tower::timeout::error::Elapsed>() {
                        Ok(StatusCode::REQUEST_TIMEOUT)
                    } else {
                        Err((
                            StatusCode::INTERNAL_SERVER_ERROR,
                            format!("Unhandled internal error: {error}"),
                        ))
                    }
                }))
                .timeout(Duration::from_secs(120))
                .layer(TraceLayer::new_for_http())
                .into_inner(),
        )
        .with_state(context);

    Ok(router)
}

#[cfg(test)]
pub mod tests {
    use crate::context::Context;
    use sqlx::{Postgres, Transaction};
    use std::sync::Arc;

    pub async fn transaction_commit(context: Arc<Context>, transaction: Transaction<'_, Postgres>) {
        context
            .octopus_database
            .transaction_commit(transaction)
            .await
            .unwrap();
    }
}
