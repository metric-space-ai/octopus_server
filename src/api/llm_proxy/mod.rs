use crate::{
    context::Context,
    error::AppError,
    ollama::proxy,
    session::{require_authenticated, ExtractedSession},
};
use axum::{
    body::Body,
    extract::{Path, Request, State},
    response::IntoResponse,
};
use serde::Deserialize;
use std::sync::Arc;
use utoipa::IntoParams;

#[derive(Deserialize, IntoParams)]
pub struct LlmProxyParams {
    pass: Option<String>,
}

#[axum_macros::debug_handler]
#[utoipa::path(
    get,
    path = "/api/v1/llm-proxy/*pass",
    responses(
        (status = 200, description = "LLM proxy.", body = String),
        (status = 401, description = "Unauthorized request.", body = ResponseError),
        (status = 403, description = "Forbidden.", body = ResponseError),
    ),
    params(
        ("pass" = String, Path, description = "Parameters that are passed to proxified service"),
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn proxy(
    State(context): State<Arc<Context>>,
    extracted_session: ExtractedSession,
    Path(LlmProxyParams { pass }): Path<LlmProxyParams>,
    request: Request<Body>,
) -> Result<impl IntoResponse, AppError> {
    let session = require_authenticated(extracted_session).await?;

    context
        .octopus_database
        .try_get_user_by_id(session.user_id)
        .await?
        .ok_or(AppError::Forbidden)?;

    let response = proxy::request(context.clone(), pass, request).await?;

    Ok(response)
}
