use crate::{
    context::Context,
    entity::{WorkspacesType, ROLE_COMPANY_ADMIN_USER, ROLE_PRIVATE_USER},
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
use serde::Deserialize;
use std::{
    fs::{remove_file, File},
    io::Write,
    sync::Arc,
};
use utoipa::IntoParams;
use uuid::Uuid;

#[derive(Deserialize, IntoParams)]
pub struct Params {
    chat_message_id: Uuid,
    chat_message_picture_id: Uuid,
}

#[axum_macros::debug_handler]
#[utoipa::path(
    post,
    path = "/api/v1/chat-message-pictures/:chat_message_id",
    responses(
        (status = 201, description = "Chat message picture created.", body = ChatMessagePicture),
        (status = 403, description = "Forbidden.", body = ResponseError),
        (status = 404, description = "Chat not found.", body = ResponseError),
        (status = 409, description = "Conflicting request.", body = ResponseError),
    ),
    params(
        ("chat_message_id" = String, Path, description = "Chat message id"),
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn create(
    State(context): State<Arc<Context>>,
    extracted_session: ExtractedSession,
    Path(chat_message_id): Path<Uuid>,
    mut multipart: Multipart,
) -> Result<impl IntoResponse, AppError> {
    let session = require_authenticated_session(extracted_session).await?;

    let session_user = context
        .octopus_database
        .try_get_user_by_id(session.user_id)
        .await?
        .ok_or(AppError::Forbidden)?;

    let chat_message = context
        .octopus_database
        .try_get_chat_message_by_id(chat_message_id)
        .await?
        .ok_or(AppError::NotFound)?;

    let chat = context
        .octopus_database
        .try_get_chat_by_id(chat_message.chat_id)
        .await?
        .ok_or(AppError::NotFound)?;

    let user = context
        .octopus_database
        .try_get_user_by_id(chat.user_id)
        .await?
        .ok_or(AppError::NotFound)?;

    let workspace = context
        .octopus_database
        .try_get_workspace_by_id(chat.workspace_id)
        .await?
        .ok_or(AppError::NotFound)?;

    match workspace.r#type {
        WorkspacesType::Private => {
            if session_user.id != chat_message.user_id
                && !session_user.roles.contains(&ROLE_PRIVATE_USER.to_string())
            {
                return Err(AppError::Forbidden);
            }
        }
        WorkspacesType::Public => {
            if session_user.id != chat_message.user_id && session_user.company_id != user.company_id
            {
                return Err(AppError::Forbidden);
            }
        }
    }

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

            let chat_message_picture = context
                .octopus_database
                .insert_chat_message_picture(chat_message.id, &file_name)
                .await?;

            return Ok((StatusCode::CREATED, Json(chat_message_picture)).into_response());
        }
    }

    Err(AppError::BadRequest)
}

#[axum_macros::debug_handler]
#[utoipa::path(
    delete,
    path = "/api/v1/chat-message-pictures/:chat_message_id/:chat_message_picture_id",
    responses(
        (status = 204, description = "Chat message picture deleted."),
        (status = 403, description = "Forbidden.", body = ResponseError),
        (status = 404, description = "Chat message picture not found.", body = ResponseError),
    ),
    params(
        ("chat_message_id" = String, Path, description = "Chat message id"),
        ("chat_message_picture_id" = String, Path, description = "Chat message picture id")
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn delete(
    State(context): State<Arc<Context>>,
    extracted_session: ExtractedSession,
    Path(Params {
        chat_message_id,
        chat_message_picture_id,
    }): Path<Params>,
) -> Result<impl IntoResponse, AppError> {
    let session = require_authenticated_session(extracted_session).await?;

    let session_user = context
        .octopus_database
        .try_get_user_by_id(session.user_id)
        .await?
        .ok_or(AppError::Forbidden)?;

    let chat_message_picture = context
        .octopus_database
        .try_get_chat_message_picture_by_id(chat_message_picture_id)
        .await?
        .ok_or(AppError::NotFound)?;

    if chat_message_id != chat_message_picture.chat_message_id {
        return Err(AppError::Forbidden);
    }

    let chat_message = context
        .octopus_database
        .try_get_chat_message_by_id(chat_message_picture.chat_message_id)
        .await?
        .ok_or(AppError::NotFound)?;

    let user = context
        .octopus_database
        .try_get_user_by_id(chat_message.user_id)
        .await?
        .ok_or(AppError::NotFound)?;

    if session_user.id != chat_message.user_id
        && (!session_user
            .roles
            .contains(&ROLE_COMPANY_ADMIN_USER.to_string())
            || session_user.company_id != user.company_id)
    {
        return Err(AppError::Forbidden);
    }

    context
        .octopus_database
        .try_delete_chat_message_picture_by_id(chat_message_picture.id)
        .await?
        .ok_or(AppError::NotFound)?;

    let path = format!("{PUBLIC_DIR}/{}", chat_message_picture.file_name);
    remove_file(path)?;

    Ok((StatusCode::NO_CONTENT, ()).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    get,
    path = "/api/v1/chat-message-pictures/:chat_message_id/:chat_message_picture_id",
    responses(
        (status = 200, description = "Chat message picture read.", body = ChatMessagePicture),
        (status = 403, description = "Forbidden.", body = ResponseError),
        (status = 404, description = "Chat message picture not found.", body = ResponseError),
    ),
    params(
        ("chat_message_id" = String, Path, description = "Chat message id"),
        ("chat_message_picture_id" = String, Path, description = "Chat message picture id")
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn read(
    State(context): State<Arc<Context>>,
    extracted_session: ExtractedSession,
    Path(Params {
        chat_message_id,
        chat_message_picture_id,
    }): Path<Params>,
) -> Result<impl IntoResponse, AppError> {
    let session = require_authenticated_session(extracted_session).await?;

    let session_user = context
        .octopus_database
        .try_get_user_by_id(session.user_id)
        .await?
        .ok_or(AppError::Forbidden)?;

    let chat_message_picture = context
        .octopus_database
        .try_get_chat_message_picture_by_id(chat_message_picture_id)
        .await?
        .ok_or(AppError::NotFound)?;

    if chat_message_id != chat_message_picture.chat_message_id {
        return Err(AppError::Forbidden);
    }

    let chat_message = context
        .octopus_database
        .try_get_chat_message_by_id(chat_message_picture.chat_message_id)
        .await?
        .ok_or(AppError::NotFound)?;

    let user = context
        .octopus_database
        .try_get_user_by_id(chat_message.user_id)
        .await?
        .ok_or(AppError::NotFound)?;

    if session_user.id != chat_message.user_id && session_user.company_id != user.company_id {
        return Err(AppError::Forbidden);
    }

    Ok((StatusCode::OK, Json(chat_message_picture)).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    put,
    path = "/api/v1/chat-message-pictures/:chat_message_id/:chat_message_picture_id",
    responses(
        (status = 200, description = "Chat message picture updated.", body = ChatMessagePicture),
        (status = 403, description = "Forbidden.", body = ResponseError),
        (status = 404, description = "Chat message picture not found.", body = ResponseError),
    ),
    params(
        ("chat_message_id" = String, Path, description = "Chat message id"),
        ("chat_message_picture_id" = String, Path, description = "Chat message picture id")
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn update(
    State(context): State<Arc<Context>>,
    extracted_session: ExtractedSession,
    Path(Params {
        chat_message_id,
        chat_message_picture_id,
    }): Path<Params>,
    mut multipart: Multipart,
) -> Result<impl IntoResponse, AppError> {
    let session = require_authenticated_session(extracted_session).await?;

    let session_user = context
        .octopus_database
        .try_get_user_by_id(session.user_id)
        .await?
        .ok_or(AppError::Forbidden)?;

    let chat_message_picture = context
        .octopus_database
        .try_get_chat_message_picture_by_id(chat_message_picture_id)
        .await?
        .ok_or(AppError::NotFound)?;

    if chat_message_id != chat_message_picture.chat_message_id {
        return Err(AppError::Forbidden);
    }

    let chat_message = context
        .octopus_database
        .try_get_chat_message_by_id(chat_message_picture.chat_message_id)
        .await?
        .ok_or(AppError::NotFound)?;

    let user = context
        .octopus_database
        .try_get_user_by_id(chat_message.user_id)
        .await?
        .ok_or(AppError::NotFound)?;

    if session_user.id != chat_message.user_id
        && (!session_user
            .roles
            .contains(&ROLE_COMPANY_ADMIN_USER.to_string())
            || session_user.company_id != user.company_id)
    {
        return Err(AppError::Forbidden);
    }

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

            let old_file = format!("{PUBLIC_DIR}/{}", chat_message_picture.file_name);

            let file_name = format!("{}.{}", Uuid::new_v4(), extension);
            let path = format!("{PUBLIC_DIR}/{file_name}");

            let mut file = File::create(path)?;
            file.write_all(&data)?;

            let chat_message_picture = context
                .octopus_database
                .update_chat_message_picture(chat_message_picture.id, &file_name)
                .await?;

            remove_file(old_file)?;

            return Ok((StatusCode::CREATED, Json(chat_message_picture)).into_response());
        }
    }

    Err(AppError::BadRequest)
}
