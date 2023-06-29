use crate::{config::Config, error::AppError};
use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use validator::Validate;

#[axum_macros::debug_handler]
pub async fn create(
    State(config): State<Arc<Config>>,
    Json(input): Json<CreateChatMessage>,
) -> Result<impl IntoResponse, AppError> {
    input.validate()?;

    Ok((StatusCode::CREATED, Json(input)).into_response())
}

#[derive(Debug, Deserialize, Serialize, Validate)]
pub struct CreateChatMessage {
    message: String,
}
