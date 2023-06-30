use crate::{
    api::auth::{signup, signup::SignupPost},
    context::Context,
    entity::User,
    error::ResponseError,
};
use axum::{error_handling::HandleErrorLayer, http::StatusCode, routing::post, Router};
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
                ResponseError,
                SignupPost,
                User,
            )
        ),
        modifiers(&SecurityAddon),
        paths(
            signup::signup,
        ),
        tags(
            (name = "signup", description = "Signup API."),
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
        .route("/api/v1/auth/signup", post(signup::signup))
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
