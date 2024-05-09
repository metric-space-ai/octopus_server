use crate::{
    context::Context,
    entity::ROLE_COMPANY_ADMIN_USER,
    error::AppError,
    session::{ensure_secured, require_authenticated, ExtractedSession},
    NEXTCLOUD_FILES_DIR,
};
use axum::{
    extract::{Multipart, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use std::{
    fs::{read_dir, File},
    io::Write,
    sync::Arc,
};

#[axum_macros::debug_handler]
#[utoipa::path(
    post,
    path = "/api/v1/nextcloud-raw-files",
    responses(
        (status = 201, description = "Nextcloud file created.", body = String),
        (status = 400, description = "Bad request.", body = ResponseError),
        (status = 403, description = "Forbidden.", body = ResponseError),
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn create(
    State(context): State<Arc<Context>>,
    extracted_session: ExtractedSession,
    mut multipart: Multipart,
) -> Result<impl IntoResponse, AppError> {
    ensure_secured(context.clone(), extracted_session, ROLE_COMPANY_ADMIN_USER).await?;

    let mut data = None;
    let mut original_file_name = None;

    while let Some(field) = multipart.next_field().await? {
        original_file_name = Some((field.file_name().ok_or(AppError::File)?).to_string());
        data = Some(field.bytes().await?.clone().to_vec());
    }

    if let (Some(data), Some(original_file_name)) = (data, original_file_name) {
        let nextcloud_subdir = context.get_config().await?.nextcloud_subdir;
        let path = format!("{NEXTCLOUD_FILES_DIR}/{nextcloud_subdir}{original_file_name}");

        let mut file = File::create(path)?;
        file.write_all(&data)?;

        return Ok((StatusCode::CREATED, Json(original_file_name)).into_response());
    }

    Err(AppError::BadRequest)
}

#[axum_macros::debug_handler]
#[utoipa::path(
    get,
    path = "/api/v1/nextcloud-raw-files",
    responses(
        (status = 200, description = "List of Nextcloud files.", body = [String]),
        (status = 401, description = "Unauthorized request.", body = ResponseError),
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn list(
    State(context): State<Arc<Context>>,
    extracted_session: ExtractedSession,
) -> Result<impl IntoResponse, AppError> {
    require_authenticated(extracted_session).await?;

    let mut nextcloud_files = vec![];
    let nextcloud_subdir = context.get_config().await?.nextcloud_subdir;
    let path = format!("{NEXTCLOUD_FILES_DIR}/{nextcloud_subdir}");
    let read_dir = read_dir(path)?;

    for dir_entry in read_dir.flatten() {
        let file_name = dir_entry.file_name().into_string();
        if let Ok(file_name) = file_name {
            nextcloud_files.push(file_name);
        }
    }

    nextcloud_files.sort();

    Ok((StatusCode::OK, Json(nextcloud_files)).into_response())
}
