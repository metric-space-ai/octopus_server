use crate::{
    api::{
        auth::{login, login::LoginPost, logout, register, register::RegisterPost},
        chats::ChatPut,
        example_prompts::{ExamplePromptPost, ExamplePromptPut},
    },
    context::Context,
    entity::{Chat, ExamplePrompt, User},
    error::ResponseError,
    session::{SessionResponse, SessionResponseData},
};
use axum::{
    error_handling::HandleErrorLayer,
    http::StatusCode,
    routing::{delete, get, post},
    Router,
};
use std::{sync::Arc, time::Duration};
use tower::{BoxError, ServiceBuilder};
use tower_http::trace::TraceLayer;
use utoipa::{
    openapi::security::{ApiKey, ApiKeyValue, SecurityScheme},
    Modify, OpenApi,
};
use utoipa_swagger_ui::SwaggerUi;

mod auth;
mod chat;
mod chats;
mod example_prompts;

pub async fn router(context: Arc<Context>) -> Router {
    #[derive(OpenApi)]
    #[openapi(
        components(
            schemas(
                Chat,
                ChatPut,
                ExamplePrompt,
                ExamplePromptPost,
                ExamplePromptPut,
                LoginPost,
                RegisterPost,
                ResponseError,
                SessionResponse,
                SessionResponseData,
                User,
            )
        ),
        modifiers(&SecurityAddon),
        paths(
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
            register::register,
        ),
        tags(
            (name = "chats", description = "Chats API."),
            (name = "example_prompts", description = "Example prompts API."),
            (name = "login", description = "Login API."),
            (name = "logout", description = "Logout API."),
            (name = "register", description = "Register API."),
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
                )
            }
        }
    }

    Router::new()
        .merge(SwaggerUi::new("/swagger-ui").url("/api-doc/openapi.json", ApiDoc::openapi()))
        .route("/api/v1/auth", delete(logout::logout).post(login::login))
        .route("/api/v1/auth/register", post(register::register))
        .route("/api/v1/chat", post(chat::create))
        .route("/api/v1/chats", get(chats::list).post(chats::create))
        .route(
            "/api/v1/chats/:id",
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
