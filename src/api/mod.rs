use crate::{
    api::auth::{login, login::LoginPost, logout, register, register::RegisterPost},
    context::Context,
    entity::User,
    error::ResponseError,
    session::SessionResponse,
};
use axum::{
    error_handling::HandleErrorLayer,
    http::StatusCode,
    routing::{delete, post},
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

pub async fn router(context: Arc<Context>) -> Router {
    #[derive(OpenApi)]
    #[openapi(
        components(
            schemas(
                LoginPost,
                RegisterPost,
                ResponseError,
                SessionResponse,
                User,
            )
        ),
        modifiers(&SecurityAddon),
        paths(
            register::register,
        ),
        tags(
            (name = "login", description = "Login API."),
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
