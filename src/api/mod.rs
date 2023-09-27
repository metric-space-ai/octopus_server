use crate::{
    ai::{
        AiFunctionResponse, AiFunctionResponseFileAttachement, AiFunctionResponseResponse,
        AiFunctionResponseStatus,
    },
    api::{
        ai_functions::{AiFunctionDirectCallPost, AiFunctionPut},
        ai_services::{
            AiServiceOperation, AiServiceOperationPost, AiServiceOperationResponse, AiServicePut,
        },
        auth::{
            change_password, change_password::ChangePasswordPut, login, login::LoginPost, logout,
            register, register::RegisterPost,
        },
        chat_messages::{ChatMessageFlagPut, ChatMessagePost, ChatMessagePut},
        chats::ChatPut,
        example_prompt_categories::{ExamplePromptCategoryPost, ExamplePromptCategoryPut},
        example_prompts::{ExamplePromptPost, ExamplePromptPut},
        inspection_disablings::InspectionDisablingPost,
        password_resets::{PasswordResetPost, PasswordResetPut},
        profiles::ProfilePut,
        setup::{SetupInfoResponse, SetupPost},
        users::UserPut,
        workspaces::{WorkspacePost, WorkspacePut},
    },
    context::Context,
    entity::{
        AiFunction, AiFunctionRequestContentType, AiFunctionResponseContentType, AiService,
        AiServiceHealthCheckStatus, AiServiceSetupStatus, Chat, ChatActivity, ChatAudit,
        ChatMessage, ChatMessageExtended, ChatMessageFile, ChatMessagePicture, ChatMessageStatus,
        ChatPicture, ExamplePrompt, ExamplePromptCategory, InspectionDisabling, PasswordResetToken,
        Profile, User, Workspace, WorkspacesType,
    },
    error::ResponseError,
    server_resources::{Gpu, ServerResources},
    session::{SessionResponse, SessionResponseData},
};
use axum::{
    error_handling::HandleErrorLayer,
    http::{header, Method, StatusCode},
    routing::{delete, get, post, put},
    Router,
};
use std::{sync::Arc, time::Duration};
use tower::{BoxError, ServiceBuilder};
use tower_http::{
    cors::{Any, CorsLayer},
    services::ServeDir,
    trace::TraceLayer,
};
use utoipa::{
    openapi::security::{ApiKey, ApiKeyValue, SecurityScheme},
    Modify, OpenApi,
};
use utoipa_swagger_ui::SwaggerUi;

mod ai_functions;
mod ai_services;
mod auth;
mod chat_activities;
mod chat_audits;
mod chat_message_files;
mod chat_message_pictures;
mod chat_messages;
mod chat_pictures;
mod chats;
mod example_prompt_categories;
mod example_prompts;
mod inspection_disablings;
mod password_resets;
mod profile_pictures;
mod profiles;
mod server_resources;
mod setup;
mod users;
mod workspaces;

pub async fn router(context: Arc<Context>) -> Router {
    #[derive(OpenApi)]
    #[openapi(
        components(
            schemas(
                AiFunction,
                AiFunctionPut,
                AiFunctionRequestContentType,
                AiFunctionResponse,
                AiFunctionResponseContentType,
                AiFunctionResponseFileAttachement,
                AiFunctionResponseResponse,
                AiFunctionResponseStatus,
                AiFunctionDirectCallPost,
                AiService,
                AiServiceHealthCheckStatus,
                AiServiceOperation,
                AiServiceOperationPost,
                AiServiceOperationResponse,
                AiServicePut,
                AiServiceSetupStatus,
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
                ChatPut,
                ExamplePrompt,
                ExamplePromptCategory,
                ExamplePromptCategoryPost,
                ExamplePromptCategoryPut,
                ExamplePromptPost,
                ExamplePromptPut,
                Gpu,
                InspectionDisabling,
                InspectionDisablingPost,
                LoginPost,
                PasswordResetPost,
                PasswordResetPut,
                PasswordResetToken,
                Profile,
                ProfilePut,
                RegisterPost,
                ResponseError,
                ServerResources,
                SessionResponse,
                SessionResponseData,
                SetupInfoResponse,
                SetupPost,
                User,
                UserPut,
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
            ai_functions::read,
            ai_functions::update,
            ai_services::create,
            ai_services::delete,
            ai_services::list,
            ai_services::operation,
            ai_services::read,
            ai_services::update,
            change_password::change_password,
            chat_activities::create,
            chat_activities::list,
            chat_audits::list,
            chat_audits::read,
            chat_messages::anonymize,
            chat_messages::create,
            chat_messages::delete,
            chat_messages::flag,
            chat_messages::latest,
            chat_messages::list,
            chat_messages::read,
            chat_messages::regenerate,
            chat_messages::update,
            chat_message_files::delete,
            chat_message_files::list,
            chat_message_files::read,
            chat_message_pictures::create,
            chat_message_pictures::delete,
            chat_message_pictures::read,
            chat_message_pictures::update,
            chat_pictures::create,
            chat_pictures::delete,
            chat_pictures::read,
            chat_pictures::update,
            chats::create,
            chats::delete,
            chats::latest,
            chats::list,
            chats::read,
            chats::update,
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
            inspection_disablings::create,
            inspection_disablings::delete,
            inspection_disablings::read,
            login::login,
            logout::logout,
            password_resets::change_password,
            password_resets::request,
            password_resets::validate,
            profiles::read,
            profiles::update,
            profile_pictures::delete,
            profile_pictures::update,
            register::register,
            server_resources::info,
            setup::info,
            setup::setup,
            users::read,
            users::update,
            workspaces::create,
            workspaces::delete,
            workspaces::list,
            workspaces::read,
            workspaces::update,
        ),
        tags(
            (name = "ai_functions", description = "AI functions API."),
            (name = "ai_services", description = "AI services API."),
            (name = "change_password", description = "Change password API."),
            (name = "chats", description = "Chats API."),
            (name = "chat_activities", description = "Chat activities API."),
            (name = "chat_audits", description = "Chat audits API."),
            (name = "chat_messages", description = "Chat messages API."),
            (name = "chat_message_files", description = "Chat message files API."),
            (name = "chat_message_pictures", description = "Chat message pictures API."),
            (name = "chat_pictures", description = "Chat pictures API."),
            (name = "example_prompt_categories", description = "Example prompt categories API."),
            (name = "example_prompts", description = "Example prompts API."),
            (name = "inspection_disablings", description = "Inspection disablings API."),
            (name = "login", description = "Login API."),
            (name = "logout", description = "Logout API."),
            (name = "password_resets", description = "Password resets API."),
            (name = "profiles", description = "Profiles API."),
            (name = "profile_pictures", description = "Profile pictures API."),
            (name = "register", description = "Register API."),
            (name = "server_resources", description = "Server resources API."),
            (name = "setup", description = "Setup API."),
            (name = "users", description = "Users API."),
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

    Router::new()
        .nest_service("/public", ServeDir::new("public"))
        .merge(SwaggerUi::new("/swagger-ui").url("/api-doc/openapi.json", ApiDoc::openapi()))
        .route("/api/v1/auth", delete(logout::logout).post(login::login))
        .route("/api/v1/auth/register", post(register::register))
        .route(
            "/api/v1/auth/register/:company_id",
            post(register::register_with_company_id),
        )
        .route(
            "/api/v1/auth/:user_id",
            put(change_password::change_password),
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
            "/api/v1/chat-message-files/:chat_message_id",
            get(chat_message_files::list),
        )
        .route(
            "/api/v1/chat-message-files/:chat_message_id/:chat_message_file_id",
            delete(chat_message_files::delete).get(chat_message_files::read),
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
            "/api/v1/ai-services",
            get(ai_services::list).post(ai_services::create),
        )
        .route(
            "/api/v1/ai-services/:id/configuration",
            put(ai_services::configuration),
        )
        .route(
            "/api/v1/ai-services/:id/installation",
            put(ai_services::installation),
        )
        .route(
            "/api/v1/ai-services/:id",
            delete(ai_services::delete)
                .get(ai_services::read)
                .post(ai_services::operation)
                .put(ai_services::update),
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
        .route(
            "/api/v1/inspection-disablings/:user_id",
            delete(inspection_disablings::delete)
                .get(inspection_disablings::read)
                .post(inspection_disablings::create),
        )
        .route("/api/v1/password-resets", post(password_resets::request))
        .route(
            "/api/v1/password-resets/:token",
            get(password_resets::validate).put(password_resets::change_password),
        )
        .route(
            "/api/v1/profile-pictures/:user_id",
            delete(profile_pictures::delete).put(profile_pictures::update),
        )
        .route(
            "/api/v1/profiles/:user_id",
            get(profiles::read).put(profiles::update),
        )
        .route("/api/v1/server-resources", get(server_resources::info))
        .route("/api/v1/setup", get(setup::info).post(setup::setup))
        .route(
            "/api/v1/users/:user_id",
            get(users::read).put(users::update),
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
                    header::HeaderName::from_lowercase(b"x-auth-token").unwrap(),
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
        .with_state(context)
}
