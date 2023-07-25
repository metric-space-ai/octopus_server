use crate::{
    api::{
        auth::{
            change_password, change_password::ChangePasswordPut, login, login::LoginPost, logout,
            register, register::RegisterPost, register_company,
            register_company::RegisterCompanyPost,
        },
        chat_messages::{ChatMessagePost, ChatMessagePut},
        chats::ChatPut,
        example_prompts::{ExamplePromptPost, ExamplePromptPut},
        profiles::ProfilePut,
        workspaces::{WorkspacePost, WorkspacePut},
    },
    context::Context,
    entity::{
        Chat, ChatMessage, ChatMessageFile, ChatMessageStatus, ChatPicture, ExamplePrompt, Profile,
        User, Workspace, WorkspacesType,
    },
    error::ResponseError,
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

mod auth;
mod chat_message_files;
mod chat_messages;
mod chat_pictures;
mod chats;
mod example_prompts;
mod profile_pictures;
mod profiles;
mod workspaces;

pub async fn router(context: Arc<Context>) -> Router {
    #[derive(OpenApi)]
    #[openapi(
        components(
            schemas(
                ChangePasswordPut,
                Chat,
                ChatMessage,
                ChatMessageFile,
                ChatMessagePost,
                ChatMessagePut,
                ChatMessageStatus,
                ChatPicture,
                ChatPut,
                ExamplePrompt,
                ExamplePromptPost,
                ExamplePromptPut,
                LoginPost,
                Profile,
                ProfilePut,
                RegisterCompanyPost,
                RegisterPost,
                ResponseError,
                SessionResponse,
                SessionResponseData,
                User,
                Workspace,
                WorkspacePost,
                WorkspacePut,
                WorkspacesType,
            )
        ),
        modifiers(&SecurityAddon),
        paths(
            change_password::change_password,
            chat_messages::create,
            chat_messages::delete,
            chat_messages::list,
            chat_messages::read,
            chat_messages::regenerate,
            chat_messages::update,
            chat_message_files::delete,
            chat_message_files::list,
            chat_message_files::read,
            chat_pictures::create,
            chat_pictures::delete,
            chat_pictures::read,
            chat_pictures::update,
            chats::create,
            chats::delete,
            chats::list,
            chats::read,
            chats::update,
            example_prompts::create,
            example_prompts::delete,
            example_prompts::list,
            example_prompts::read,
            example_prompts::update,
            login::login,
            logout::logout,
            profiles::read,
            profiles::update,
            profile_pictures::delete,
            profile_pictures::update,
            register::register,
            register_company::register_company,
            workspaces::create,
            workspaces::delete,
            workspaces::list,
            workspaces::read,
            workspaces::update,
        ),
        tags(
            (name = "chats", description = "Chats API."),
            (name = "chat_messages", description = "Chat messages API."),
            (name = "chat_message_files", description = "Chat message files API."),
            (name = "chat_pictures", description = "Chat pictures API."),
            (name = "example_prompts", description = "Example prompts API."),
            (name = "workspaces", description = "Workspaces API."),
            (name = "profiles", description = "Profiles API."),
            (name = "profile_pictures", description = "Profile pictures API."),
            (name = "change_password", description = "Change password API."),
            (name = "login", description = "Login API."),
            (name = "logout", description = "Logout API."),
            (name = "register", description = "Register API."),
            (name = "register_company", description = "Register company API."),
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
            "/api/v1/auth/register-company",
            post(register_company::register_company),
        )
        .route(
            "/api/v1/auth/:user_id",
            put(change_password::change_password),
        )
        .route(
            "/api/v1/chat-messages/:chat_id",
            get(chat_messages::list).post(chat_messages::create),
        )
        .route(
            "/api/v1/chat-messages/:chat_id/:chat_message_id",
            delete(chat_messages::delete)
                .get(chat_messages::read)
                .post(chat_messages::regenerate)
                .put(chat_messages::update),
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
        .route(
            "/api/v1/chats/:workspace_id/:chat_id",
            delete(chats::delete).get(chats::read).put(chats::update),
        )
        .route(
            "/api/v1/example-prompts",
            get(example_prompts::list).post(example_prompts::create),
        )
        .route(
            "/api/v1/example-prompts/:id",
            delete(example_prompts::delete)
                .get(example_prompts::read)
                .put(example_prompts::update),
        )
        .route(
            "/api/v1/profile-pictures/:user_id",
            delete(profile_pictures::delete).put(profile_pictures::update),
        )
        .route(
            "/api/v1/profiles/:user_id",
            get(profiles::read).put(profiles::update),
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
                .timeout(Duration::from_secs(10))
                .layer(TraceLayer::new_for_http())
                .into_inner(),
        )
        .with_state(context)
}
