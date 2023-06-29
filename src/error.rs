use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use serde_json::json;
use validator::ValidationErrors;

#[derive(Debug)]
pub enum AppError {
    Validation(ValidationErrors),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AppError::Validation(_error) => (StatusCode::BAD_REQUEST, "Invalid key."),
        };

        let body = Json(json!(ResponseError {
            error: error_message.to_string(),
        }));

        (status, body).into_response()
    }
}

impl From<ValidationErrors> for AppError {
    fn from(inner: ValidationErrors) -> Self {
        AppError::Validation(inner)
    }
}

#[derive(Debug, Serialize)]
pub struct ResponseError {
    pub error: String,
}
