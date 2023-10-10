use crate::{
    ai,
    context::Context,
    entity::ROLE_COMPANY_ADMIN_USER,
    error::AppError,
    session::{ensure_secured, require_authenticated_session, ExtractedSession},
};
use axum::{
    extract::{Multipart, Path, State},
    http::StatusCode,
    response::{Html, IntoResponse},
    Json,
};
use std::sync::Arc;
use uuid::Uuid;

#[axum_macros::debug_handler]
#[utoipa::path(
    get,
    path = "/api/v1/simple-apps/:id/code",
    responses(
        (status = 200, description = "Simple app code.", body = SimpleApp),
        (status = 401, description = "Unauthorized request.", body = ResponseError),
        (status = 404, description = "Simple app not found.", body = ResponseError),
    ),
    params(
        ("id" = String, Path, description = "Simple app id")
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn code(
    State(context): State<Arc<Context>>,
    extracted_session: ExtractedSession,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    require_authenticated_session(extracted_session).await?;

    let simple_app = context
        .octopus_database
        .try_get_simple_app_by_id(id)
        .await?
        .ok_or(AppError::NotFound)?;

    if !simple_app.is_enabled {
        return Err(AppError::NotFound);
    }

    Ok((StatusCode::OK, Html(simple_app.code)).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    post,
    path = "/api/v1/simple-apps",
    responses(
        (status = 201, description = "Simple app created.", body = SimpleApp),
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

    while let Some(field) = multipart.next_field().await? {
        let content_type = (field.content_type().ok_or(AppError::File)?).to_string();

        if content_type == "text/html" {
            let data = field.bytes().await?.clone().to_vec();
            let code = String::from_utf8(data)?;

            let malicious_code_detected = ai::open_ai_code_check(&code).await?;

            if malicious_code_detected {
                return Err(AppError::BadRequest);
            }

            let simple_app_meta = ai::open_ai_simple_app_meta_extraction(&code).await?;

            let formatted_name = simple_app_meta
                .title
                .clone()
                .replace(' ', "_")
                .to_lowercase();

            let simple_app = context
                .octopus_database
                .insert_simple_app(
                    &code,
                    &simple_app_meta.description,
                    &formatted_name,
                    true,
                    &simple_app_meta.title,
                )
                .await?;

            return Ok((StatusCode::CREATED, Json(simple_app)).into_response());
        }
    }

    Err(AppError::BadRequest)
}

#[axum_macros::debug_handler]
#[utoipa::path(
    delete,
    path = "/api/v1/simple-apps/:id",
    responses(
        (status = 204, description = "Simple app deleted."),
        (status = 403, description = "Forbidden.", body = ResponseError),
        (status = 404, description = "Simple app not found.", body = ResponseError),
    ),
    params(
        ("id" = String, Path, description = "Simple app id")
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

    context
        .octopus_database
        .try_delete_simple_app_by_id(id)
        .await?
        .ok_or(AppError::NotFound)?;

    Ok((StatusCode::NO_CONTENT, ()).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    get,
    path = "/api/v1/simple-apps",
    responses(
        (status = 200, description = "List of Simple apps.", body = [SimpleApp]),
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
    require_authenticated_session(extracted_session).await?;

    let simple_apps = context.octopus_database.get_simple_apps().await?;

    Ok((StatusCode::OK, Json(simple_apps)).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    get,
    path = "/api/v1/simple-apps/:id",
    responses(
        (status = 200, description = "Simple app read.", body = SimpleApp),
        (status = 401, description = "Unauthorized request.", body = ResponseError),
        (status = 404, description = "Simple app not found.", body = ResponseError),
    ),
    params(
        ("id" = String, Path, description = "Simple app id")
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
    require_authenticated_session(extracted_session).await?;

    let simple_app = context
        .octopus_database
        .try_get_simple_app_by_id(id)
        .await?
        .ok_or(AppError::NotFound)?;

    if !simple_app.is_enabled {
        return Err(AppError::NotFound);
    }

    Ok((StatusCode::OK, Json(simple_app)).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    put,
    path = "/api/v1/simple-apps/:id",
    responses(
        (status = 200, description = "Simple app updated.", body = SimpleApp),
        (status = 400, description = "Bad request.", body = ResponseError),
        (status = 403, description = "Forbidden.", body = ResponseError),
        (status = 404, description = "Simple app not found.", body = ResponseError),
    ),
    params(
        ("id" = String, Path, description = "Simple app id")
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
        .try_get_simple_app_id_by_id(id)
        .await?
        .ok_or(AppError::NotFound)?;

    while let Some(field) = multipart.next_field().await? {
        let content_type = (field.content_type().ok_or(AppError::File)?).to_string();

        if content_type == "text/html" {
            let data = field.bytes().await?.clone().to_vec();
            let code = String::from_utf8(data)?;

            let malicious_code_detected = ai::open_ai_code_check(&code).await?;

            if malicious_code_detected {
                return Err(AppError::BadRequest);
            }

            let simple_app_meta = ai::open_ai_simple_app_meta_extraction(&code).await?;

            let formatted_name = simple_app_meta
                .title
                .clone()
                .replace(' ', "_")
                .to_lowercase();

            let simple_app = context
                .octopus_database
                .update_simple_app(
                    id,
                    &code,
                    &simple_app_meta.description,
                    &formatted_name,
                    true,
                    &simple_app_meta.title,
                )
                .await?;

            return Ok((StatusCode::OK, Json(simple_app)).into_response());
        }
    }

    Err(AppError::BadRequest)
}
