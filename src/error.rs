use async_openai::error::OpenAIError;
use axum::{
    extract::multipart::MultipartError,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use http::header::ToStrError;
use serde::Serialize;
use serde_json::json;
use std::error::Error;
use strum_macros::Display;
use utoipa::ToSchema;
use validator::ValidationErrors;

#[derive(Debug, Display)]
pub enum AppError {
    BadResponse,
    BadRequest,
    Casting,
    CompanyNotFound,
    Concurrency(tokio::task::JoinError),
    Conflict,
    File,
    Forbidden,
    Generic(Box<dyn Error + Send + Sync>),
    Gone,
    Header(ToStrError),
    InternalError,
    Io(std::io::Error),
    Json(serde_json::Error),
    Multipart(MultipartError),
    NotFound,
    NotRegistered,
    OpenAI(OpenAIError),
    PasswordDoesNotMatch,
    PasswordHash(argon2::password_hash::Error),
    Request(reqwest::Error),
    Unauthorized,
    UserAlreadyExists,
    Uuid(uuid::Error),
    Validation(ValidationErrors),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AppError::BadResponse => (StatusCode::INTERNAL_SERVER_ERROR, "Response problem."),
            AppError::BadRequest => (StatusCode::BAD_REQUEST, "Bad request."),
            AppError::Casting => (StatusCode::INTERNAL_SERVER_ERROR, "Casting problem."),
            AppError::CompanyNotFound => {
                (StatusCode::BAD_REQUEST, "Main company is not registered.")
            }
            AppError::Concurrency(_error) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Concurrency problem.")
            }
            AppError::Conflict => (StatusCode::CONFLICT, "Conflicting request."),
            AppError::File => (StatusCode::BAD_REQUEST, "File error."),
            AppError::Forbidden => (StatusCode::FORBIDDEN, "Forbidden."),
            AppError::Generic(_error) => (StatusCode::INTERNAL_SERVER_ERROR, "Generic error."),
            AppError::Gone => (StatusCode::GONE, "Resource gone."),
            AppError::Header(_error) => (StatusCode::CONFLICT, "Invalid header."),
            AppError::InternalError => (StatusCode::INTERNAL_SERVER_ERROR, "Internal error."),
            AppError::Io(_error) => (StatusCode::INTERNAL_SERVER_ERROR, "Filesystem error."),
            AppError::Json(_error) => (StatusCode::BAD_REQUEST, "Invalid JSON."),
            AppError::Multipart(_error) => (StatusCode::BAD_REQUEST, "Multipart form error."),
            AppError::NotFound => (StatusCode::NOT_FOUND, "Not found."),
            AppError::NotRegistered => (StatusCode::NOT_FOUND, "Email address not registered."),
            AppError::OpenAI(_error) => (StatusCode::BAD_REQUEST, "OpenAI problem."),
            AppError::PasswordDoesNotMatch => (StatusCode::BAD_REQUEST, "Password does not match."),
            AppError::PasswordHash(_error) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Password hash problem.")
            }
            AppError::Request(_error) => (StatusCode::INTERNAL_SERVER_ERROR, "Request error."),
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, "Unauthorized."),
            AppError::UserAlreadyExists => {
                (StatusCode::CONFLICT, "User with such email already exists.")
            }
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

impl From<std::io::Error> for AppError {
    fn from(inner: std::io::Error) -> Self {
        AppError::Io(inner)
    }
}

impl From<MultipartError> for AppError {
    fn from(inner: MultipartError) -> Self {
        AppError::Multipart(inner)
    }
}

impl From<OpenAIError> for AppError {
    fn from(inner: OpenAIError) -> Self {
        AppError::OpenAI(inner)
    }
}

impl From<reqwest::Error> for AppError {
    fn from(inner: reqwest::Error) -> Self {
        AppError::Request(inner)
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

impl serde::ser::StdError for AppError {}

#[derive(Debug, Serialize, ToSchema)]
pub struct ResponseError {
    pub error: String,
}
