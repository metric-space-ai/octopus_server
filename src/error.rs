use async_openai::error::OpenAIError;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use http::header::ToStrError;
use serde::Serialize;
use serde_json::json;
use std::error::Error;
use utoipa::ToSchema;
use validator::ValidationErrors;

#[derive(Debug)]
pub enum AppError {
    Concurrency(tokio::task::JoinError),
    Generic(Box<dyn Error + Send + Sync>),
    Header(ToStrError),
    Json(serde_json::Error),
    NotRegistered,
    PasswordHash(argon2::password_hash::Error),
    OpenAI(OpenAIError),
    Unauthorized,
    UserAlreadyExists,
    Uuid(uuid::Error),
    Validation(ValidationErrors),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AppError::Concurrency(_error) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Concurrency problem")
            }
            AppError::Generic(_error) => (StatusCode::INTERNAL_SERVER_ERROR, "Generic error."),
            AppError::Header(_error) => (StatusCode::CONFLICT, "Invalid header"),
            AppError::Json(_error) => (StatusCode::BAD_REQUEST, "Invalid JSON"),
            AppError::NotRegistered => (StatusCode::NOT_FOUND, "Email address not registered"),
            AppError::PasswordHash(_error) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Password hash problem")
            }
            AppError::OpenAI(_error) => (StatusCode::BAD_REQUEST, "OpenAI problem."),
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, "Unauthorized"),
            AppError::UserAlreadyExists => (
                StatusCode::BAD_REQUEST,
                "User with such email already exists.",
            ),
            AppError::Uuid(_error) => (StatusCode::BAD_REQUEST, "Invalid API key."),
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

impl From<serde_json::Error> for AppError {
    fn from(inner: serde_json::Error) -> Self {
        AppError::Json(inner)
    }
}

impl From<tokio::task::JoinError> for AppError {
    fn from(inner: tokio::task::JoinError) -> Self {
        AppError::Concurrency(inner)
    }
}

impl From<ToStrError> for AppError {
    fn from(inner: ToStrError) -> Self {
        AppError::Header(inner)
    }
}

impl From<uuid::Error> for AppError {
    fn from(inner: uuid::Error) -> Self {
        AppError::Uuid(inner)
    }
}

impl From<ValidationErrors> for AppError {
    fn from(inner: ValidationErrors) -> Self {
        AppError::Validation(inner)
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ResponseError {
    pub error: String,
}
