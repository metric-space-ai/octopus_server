use crate::{
    ai::code_tools::open_ai_wasp_generator_advanced_meta_extraction,
    context::Context,
    entity::{WaspGeneratorInstanceType, ROLE_COMPANY_ADMIN_USER},
    error::AppError,
    process_manager,
    session::{ensure_secured, require_authenticated, ExtractedSession},
    wasp_generator,
};
use axum::{
    body::Body,
    extract::{Multipart, Path, Request, State, WebSocketUpgrade},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use std::{fs::read_to_string, io::Write, sync::Arc};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;
use validator::Validate;

#[axum_macros::debug_handler]
#[utoipa::path(
    post,
    path = "/api/v1/wasp-generators",
    responses(
        (status = 201, description = "Wasp generator created.", body = WaspGenerator),
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

    let mut code = None;
    let mut description = None;
    let mut instance_type = WaspGeneratorInstanceType::Shared;
    let mut is_enabled = true;
    let mut name = None;

    while let Some(field) = multipart.next_field().await? {
        let field_name = (field.name().ok_or(AppError::Parsing)?).to_string();

        if field_name == "description" {
            description = Some((field.text().await?).to_string());
        } else if field_name == "name" {
            name = Some((field.text().await?).to_string());
        } else if field_name == "instance_type" {
            let value = (field.text().await?).to_string();
            if value == "Private" {
                instance_type = WaspGeneratorInstanceType::Private;
            }
        } else if field_name == "is_enabled" {
            is_enabled = (field.text().await?).parse::<bool>().unwrap_or(true);
        } else {
            let content_type = (field.content_type().ok_or(AppError::File)?).to_string();

            if content_type == "application/zip"
                || content_type == "application/x-zip"
                || content_type == "application/x-zip-compressed"
            {
                code = Some(field.bytes().await?.clone().to_vec());
            }
        }
    }

    if let (Some(code), Some(description), Some(name)) = (code, description, name) {
        let formatted_name = name.clone().replace(' ', "_").to_lowercase();

        let mut transaction = context.octopus_database.transaction_begin().await?;

        let wasp_generator = context
            .octopus_database
            .insert_wasp_generator(
                &mut transaction,
                &code,
                &description,
                &formatted_name,
                instance_type,
                is_enabled,
                &name,
            )
            .await?;

        context
            .octopus_database
            .transaction_commit(transaction)
            .await?;

        return Ok((StatusCode::CREATED, Json(wasp_generator)).into_response());
    }

    Err(AppError::BadRequest)
}

#[axum_macros::debug_handler]
#[utoipa::path(
    delete,
    path = "/api/v1/wasp-generators/:id",
    responses(
        (status = 204, description = "Wasp generator deleted."),
        (status = 403, description = "Forbidden.", body = ResponseError),
        (status = 404, description = "Wasp generator not found.", body = ResponseError),
    ),
    params(
        ("id" = String, Path, description = "Wasp generator id")
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn delete(
    State(context): State<Arc<Context>>,
    extracted_session: ExtractedSession,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    ensure_secured(context.clone(), extracted_session, ROLE_COMPANY_ADMIN_USER).await?;

    let mut transaction = context.octopus_database.transaction_begin().await?;

    context
        .octopus_database
        .try_delete_wasp_generator_by_id(&mut transaction, id)
        .await?
        .ok_or(AppError::NotFound)?;

    context
        .octopus_database
        .transaction_commit(transaction)
        .await?;

    Ok((StatusCode::NO_CONTENT, ()).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    get,
    path = "/api/v1/wasp-generators",
    responses(
        (status = 200, description = "List of Wasp generators.", body = [WaspGenerator]),
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

    let wasp_generators = context.octopus_database.get_wasp_generators().await?;

    Ok((StatusCode::OK, Json(wasp_generators)).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    get,
    path = "/api/v1/wasp-generators/:id",
    responses(
        (status = 200, description = "Wasp generator read.", body = WaspGenerator),
        (status = 401, description = "Unauthorized request.", body = ResponseError),
        (status = 404, description = "Wasp generator not found.", body = ResponseError),
    ),
    params(
        ("id" = String, Path, description = "Wasp generator id")
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn read(
    State(context): State<Arc<Context>>,
    extracted_session: ExtractedSession,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    require_authenticated(extracted_session).await?;

    let wasp_generator = context
        .octopus_database
        .try_get_wasp_generator_by_id(id)
        .await?
        .ok_or(AppError::NotFound)?;

    if !wasp_generator.is_enabled {
        return Err(AppError::NotFound);
    }

    Ok((StatusCode::OK, Json(wasp_generator)).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    put,
    path = "/api/v1/wasp-generators/:id",
    responses(
        (status = 200, description = "Wasp generator updated.", body = WaspGenerator),
        (status = 400, description = "Bad request.", body = ResponseError),
        (status = 403, description = "Forbidden.", body = ResponseError),
        (status = 404, description = "Wasp generator not found.", body = ResponseError),
    ),
    params(
        ("id" = String, Path, description = "Wasp generator id")
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn update(
    State(context): State<Arc<Context>>,
    extracted_session: ExtractedSession,
    Path(id): Path<Uuid>,
    mut multipart: Multipart,
) -> Result<impl IntoResponse, AppError> {
    ensure_secured(context.clone(), extracted_session, ROLE_COMPANY_ADMIN_USER).await?;

    context
        .octopus_database
        .try_get_wasp_generator_id_by_id(id)
        .await?
        .ok_or(AppError::NotFound)?;

    let mut code = None;
    let mut description = None;
    let mut instance_type = WaspGeneratorInstanceType::Shared;
    let mut is_enabled = true;
    let mut name = None;

    while let Some(field) = multipart.next_field().await? {
        let field_name = (field.name().ok_or(AppError::Parsing)?).to_string();

        if field_name == "description" {
            description = Some((field.text().await?).to_string());
        } else if field_name == "name" {
            name = Some((field.text().await?).to_string());
        } else if field_name == "instance_type" {
            let value = (field.text().await?).to_string();
            if value == "Private" {
                instance_type = WaspGeneratorInstanceType::Private;
            }
        } else if field_name == "is_enabled" {
            is_enabled = (field.text().await?).parse::<bool>().unwrap_or(true);
        } else {
            let content_type = (field.content_type().ok_or(AppError::File)?).to_string();

            if content_type == "application/zip"
                || content_type == "application/x-zip"
                || content_type == "application/x-zip-compressed"
            {
                code = Some(field.bytes().await?.clone().to_vec());
            }
        }
    }

    if let (Some(code), Some(description), Some(name)) =
        (code.clone(), description.clone(), name.clone())
    {
        let formatted_name = name.clone().replace(' ', "_").to_lowercase();

        let mut transaction = context.octopus_database.transaction_begin().await?;

        let wasp_generator = context
            .octopus_database
            .update_wasp_generator(
                &mut transaction,
                id,
                &code,
                &description,
                &formatted_name,
                instance_type,
                is_enabled,
                &name,
            )
            .await?;

        context
            .octopus_database
            .transaction_commit(transaction)
            .await?;

        Ok((StatusCode::OK, Json(wasp_generator)).into_response())
    } else if let (None, Some(description), Some(name)) = (code, description, name) {
        let formatted_name = name.clone().replace(' ', "_").to_lowercase();

        let mut transaction = context.octopus_database.transaction_begin().await?;

        let wasp_generator = context
            .octopus_database
            .update_wasp_generator_info(
                &mut transaction,
                id,
                &description,
                &formatted_name,
                instance_type,
                is_enabled,
                &name,
            )
            .await?;

        context
            .octopus_database
            .transaction_commit(transaction)
            .await?;

        Ok((StatusCode::OK, Json(wasp_generator)).into_response())
    } else {
        Err(AppError::BadRequest)
    }
}
