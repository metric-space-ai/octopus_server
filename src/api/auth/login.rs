use crate::{api::auth, context::Context, error::AppError};
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use chrono::{Duration, Utc};
use serde::Deserialize;
use std::sync::Arc;
use utoipa::ToSchema;
use validator::Validate;

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct LoginPost {
    #[validate(email)]
    pub email: String,
    #[validate(length(min = 8))]
    pub password: String,
}

#[axum_macros::debug_handler]
#[utoipa::path(
    post,
    path = "/api/v1/auth",
    request_body = LoginPost,
    responses(
        (status = 201, description = "Authenticate user", body = Session),
        (status = 401, description = "Unauthorized", body = ResponseError),
        (status = 404, description = "User not found", body = ResponseError)
    )
)]
pub async fn login(
    State(context): State<Arc<Context>>,
    Json(input): Json<LoginPost>,
) -> Result<impl IntoResponse, AppError> {
    input.validate()?;

    let hash = context
        .octopus_database
        .try_get_hash_for_email(&input.email)
        .await?;
    let hash = match hash {
        Some(hash) => hash,
        None => return Err(AppError::NotRegistered),
    };

    let is_valid = auth::verify_password(context.clone(), hash, input.password).await?;
    if !is_valid {
        return Err(AppError::Unauthorized);
    }

    let user = context
        .octopus_database
        .try_get_user_by_email(&input.email)
        .await?
        .ok_or(AppError::NotRegistered)?;

    if !user.is_enabled {
        return Err(AppError::Unauthorized);
    }

    let data = serde_json::to_string(&user.roles)?;
    let expired_at = Utc::now() + Duration::days(365);

    let session = context
        .octopus_database
        .insert_session(user.id, &data, expired_at)
        .await?;

    Ok((StatusCode::CREATED, Json(session)).into_response())
}
