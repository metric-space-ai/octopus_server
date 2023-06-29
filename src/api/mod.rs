use crate::config::Config;
use axum::{
    error_handling::HandleErrorLayer,
    http::StatusCode,
    routing::post,
    Router,
};
use std::{sync::Arc, time::Duration};
use tower::{BoxError, ServiceBuilder};
use tower_http::trace::TraceLayer;

mod chat;

pub async fn router(config: Arc<Config>) -> Router {
    Router::new()
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
        .with_state(config)
}
