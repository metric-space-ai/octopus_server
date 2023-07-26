use crate::{
    context::Context,
    entity::ROLE_COMPANY_ADMIN_USER,
    error::AppError,
    session::{require_authenticated_session, ExtractedSession},
    PUBLIC_DIR,
};
use axum::{
    extract::{Multipart, Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use std::{
    fs::{remove_file, File},
    io::Write,
    sync::Arc,
};
use uuid::Uuid;

#[axum_macros::debug_handler]
#[utoipa::path(
    delete,
    path = "/api/v1/profile-pictures/:user_id",
    responses(
        (status = 204, description = "User profile picture deleted."),
        (status = 401, description = "Unauthorized request.", body = ResponseError),
        (status = 404, description = "User profile not found.", body = ResponseError),
    ),
    params(
        ("user_id" = String, Path, description = "User id")
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn delete(
    State(context): State<Arc<Context>>,
    extracted_session: ExtractedSession,
    Path(user_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let session = require_authenticated_session(extracted_session).await?;

    let session_user = context
        .octopus_database
        .try_get_user_by_id(session.user_id)
        .await?
        .ok_or(AppError::Unauthorized)?;

    let user = context
        .octopus_database
        .try_get_user_by_id(user_id)
        .await?
        .ok_or(AppError::NotFound)?;

    let profile = context
        .octopus_database
        .try_get_profile_by_user_id(user_id)
        .await?
        .ok_or(AppError::NotFound)?;

    if session_user.id != user_id
        && (!session_user
            .roles
            .contains(&ROLE_COMPANY_ADMIN_USER.to_string())
            || session_user.company_id != user.company_id)
    {
        return Err(AppError::Unauthorized);
    }

    let old_path = profile
        .photo_file_name
        .map(|photo_file_name| format!("{PUBLIC_DIR}/{}", photo_file_name));

    let profile = context
        .octopus_database
        .update_profile_photo_file_name(profile.id, None)
        .await?;

    if let Some(old_path) = old_path {
        remove_file(old_path)?;
    }

    Ok((StatusCode::OK, Json(profile)).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    put,
    path = "/api/v1/profile-pictures/:user_id",
    responses(
        (status = 200, description = "User profile picture updated.", body = Profile),
        (status = 401, description = "Unauthorized request.", body = ResponseError),
        (status = 404, description = "User profile not found.", body = ResponseError),
    ),
    params(
        ("user_id" = String, Path, description = "User id")
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn update(
    State(context): State<Arc<Context>>,
    extracted_session: ExtractedSession,
    Path(user_id): Path<Uuid>,
    mut multipart: Multipart,
) -> Result<impl IntoResponse, AppError> {
    let session = require_authenticated_session(extracted_session).await?;

    let session_user = context
        .octopus_database
        .try_get_user_by_id(session.user_id)
        .await?
        .ok_or(AppError::Unauthorized)?;

    let user = context
        .octopus_database
        .try_get_user_by_id(user_id)
        .await?
        .ok_or(AppError::NotFound)?;

    let profile = context
        .octopus_database
        .try_get_profile_by_user_id(user.id)
        .await?
        .ok_or(AppError::NotFound)?;

    if session_user.id != user_id
        && (!session_user
            .roles
            .contains(&ROLE_COMPANY_ADMIN_USER.to_string())
            || session_user.company_id != user.company_id)
    {
        return Err(AppError::Unauthorized);
    }

    let old_path = profile
        .photo_file_name
        .map(|photo_file_name| format!("{PUBLIC_DIR}/{}", photo_file_name));

    while let Some(field) = multipart.next_field().await? {
        let extension = (*field
            .file_name()
            .ok_or(AppError::File)?
            .to_string()
            .split('.')
            .collect::<Vec<&str>>()
            .last()
            .ok_or(AppError::File)?)
        .to_string();
        let content_image = (*field
            .content_type()
            .ok_or(AppError::File)?
            .to_string()
            .split('/')
            .collect::<Vec<&str>>()
            .first()
            .ok_or(AppError::File)?)
        .to_string();

        if content_image == "image" {
            let data = field.bytes().await?;

            let file_name = format!("{}.{}", Uuid::new_v4(), extension);
            let path = format!("{PUBLIC_DIR}/{file_name}");

            let mut file = File::create(path)?;
            file.write_all(&data)?;

            let profile = context
                .octopus_database
                .update_profile_photo_file_name(profile.id, Some(file_name))
                .await?;

            if let Some(old_path) = old_path {
                remove_file(old_path)?;
            }

            return Ok((StatusCode::OK, Json(profile)).into_response());
        }
    }

    Err(AppError::BadRequest)
}
