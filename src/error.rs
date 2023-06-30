use async_openai::error::OpenAIError;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use serde_json::json;
use std::error::Error;
use validator::ValidationErrors;

#[derive(Debug)]
pub enum AppError {
    Concurrency(tokio::task::JoinError),
    Generic(Box<dyn Error + Send + Sync>),
    PasswordHash(argon2::password_hash::Error),
    OpenAI(OpenAIError),
    UserAlreadyExists,
    Validation(ValidationErrors),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AppError::Concurrency(_error) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Concurrency problem")
            }
            AppError::Generic(_error) => (StatusCode::INTERNAL_SERVER_ERROR, "Generic error."),
            AppError::PasswordHash(_error) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Password hash problem")
            }
            AppError::OpenAI(_error) => (StatusCode::BAD_REQUEST, "OpenAI problem."),
            AppError::UserAlreadyExists => (
                StatusCode::BAD_REQUEST,
                "User with such email already exists.",
            ),
            AppError::Validation(_error) => (StatusCode::BAD_REQUEST, "Validation problem."),
        };

        let body = Json(json!(ResponseError {
            error: error_message.to_string(),
        }));

        (status, body).into_response()
    }
}

impl From<argon2::password_hash::Error> for AppError {
    fn from(inner: argon2::password_hash::Error) -> Self {
        AppError::PasswordHash(inner)
    }
}

impl From<Box<dyn Error + Send + Sync>> for AppError {
    fn from(inner: Box<dyn Error + Send + Sync>) -> Self {
        AppError::Generic(inner)
    }
}

impl From<OpenAIError> for AppError {
    fn from(inner: OpenAIError) -> Self {
        AppError::OpenAI(inner)
    }
}

impl From<tokio::task::JoinError> for AppError {
    fn from(inner: tokio::task::JoinError) -> Self {
        AppError::Concurrency(inner)
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
