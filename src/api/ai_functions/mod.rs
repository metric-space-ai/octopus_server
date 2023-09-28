use crate::{
    ai::function_call::function_call,
    context::Context,
    entity::{AiServiceHealthCheckStatus, AiServiceSetupStatus, ROLE_COMPANY_ADMIN_USER},
    error::AppError,
    session::{ensure_secured, require_authenticated_session, ExtractedSession},
};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use std::sync::Arc;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;
use validator::Validate;

#[derive(Debug, Deserialize, ToSchema, Validate)]
pub struct AiFunctionDirectCallPost {
    pub name: String,
    pub parameters: serde_json::Value,
}

#[derive(Debug, Deserialize, ToSchema, Validate)]
pub struct AiFunctionPut {
    pub is_enabled: bool,
}

#[derive(Deserialize, IntoParams)]
pub struct Params {
    ai_service_id: Uuid,
    ai_function_id: Uuid,
}

#[axum_macros::debug_handler]
#[utoipa::path(
    delete,
    path = "/api/v1/ai-functions/:ai_service_id/:ai_function_id",
    responses(
        (status = 204, description = "AI Function deleted."),
        (status = 403, description = "Forbidden.", body = ResponseError),
        (status = 404, description = "AI Function not found.", body = ResponseError),
    ),
    params(
        ("ai_service_id" = String, Path, description = "AI Service id"),
        ("ai_function_id" = String, Path, description = "AI Function id"),
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn delete(
    State(context): State<Arc<Context>>,
    extracted_session: ExtractedSession,
    Path(Params {
        ai_service_id,
        ai_function_id,
    }): Path<Params>,
) -> Result<impl IntoResponse, AppError> {
    ensure_secured(context.clone(), extracted_session, ROLE_COMPANY_ADMIN_USER).await?;

    let ai_function = context
        .octopus_database
        .try_get_ai_function_by_id(ai_function_id)
        .await?
        .ok_or(AppError::NotFound)?;

    if ai_service_id != ai_function.ai_service_id {
        return Err(AppError::Forbidden);
    }

    context
        .octopus_database
        .try_delete_ai_function_by_id(ai_function_id)
        .await?
        .ok_or(AppError::NotFound)?;

    Ok((StatusCode::NO_CONTENT, ()).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    post,
    path = "/api/v1/ai-functions/direct-call",
    request_body = AiFunctionDirectCallPost,
    responses(
        (status = 201, description = "AI Function direct call executed.", body = AiFunctionResponse),
        (status = 403, description = "Forbidden.", body = ResponseError),
        (status = 404, description = "AI Function not found.", body = ResponseError),
        (status = 410, description = "Resource gone.", body = ResponseError),
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn direct_call(
    State(context): State<Arc<Context>>,
    extracted_session: ExtractedSession,
    Json(input): Json<AiFunctionDirectCallPost>,
) -> Result<impl IntoResponse, AppError> {
    require_authenticated_session(extracted_session).await?;
    input.validate()?;

    let ai_function = context
        .octopus_database
        .try_get_ai_function_by_name(&input.name)
        .await?
        .ok_or(AppError::NotFound)?;

    let ai_service = context
        .octopus_database
        .try_get_ai_service_by_id(ai_function.ai_service_id)
        .await?
        .ok_or(AppError::NotFound)?;

    if !ai_function.is_enabled
        || !ai_service.is_enabled
        || ai_service.health_check_status != AiServiceHealthCheckStatus::Ok
        || ai_service.setup_status != AiServiceSetupStatus::Performed
    {
        return Err(AppError::Gone);
    }

    let ai_function_response = function_call(&ai_function, &ai_service, &input.parameters).await?;

    if let Some(ai_function_response) = ai_function_response {
        return Ok((StatusCode::CREATED, Json(ai_function_response)).into_response());
    }

    Err(AppError::Gone)
}

#[axum_macros::debug_handler]
#[utoipa::path(
    get,
    path = "/api/v1/ai-functions/:ai_service_id",
    responses(
        (status = 200, description = "List of AI Functions.", body = [AiFunction]),
        (status = 401, description = "Unauthorized request.", body = ResponseError),
        (status = 404, description = "AI Function not found.", body = ResponseError),
    ),
    params(
        ("ai_service_id" = String, Path, description = "AI Service id")
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn list(
    State(context): State<Arc<Context>>,
    extracted_session: ExtractedSession,
    Path(ai_service_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    require_authenticated_session(extracted_session).await?;

    let ai_functions = context
        .octopus_database
        .get_ai_functions_by_ai_service_id(ai_service_id)
        .await?;

    Ok((StatusCode::OK, Json(ai_functions)).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    get,
    path = "/api/v1/ai-functions/:ai_service_id/:ai_function_id",
    responses(
        (status = 200, description = "AI Function read.", body = AiFunction),
        (status = 401, description = "Unauthorized request.", body = ResponseError),
        (status = 404, description = "AI Function not found.", body = ResponseError),
    ),
    params(
        ("ai_service_id" = String, Path, description = "AI Service id"),
        ("ai_function_id" = String, Path, description = "AI Function id"),
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn read(
    State(context): State<Arc<Context>>,
    extracted_session: ExtractedSession,
    Path(Params {
        ai_service_id,
        ai_function_id,
    }): Path<Params>,
) -> Result<impl IntoResponse, AppError> {
    require_authenticated_session(extracted_session).await?;

    let ai_function = context
        .octopus_database
        .try_get_ai_function_by_id(ai_function_id)
        .await?
        .ok_or(AppError::NotFound)?;

    if ai_service_id != ai_function.ai_service_id {
        return Err(AppError::Forbidden);
    }

    Ok((StatusCode::OK, Json(ai_function)).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    put,
    path = "/api/v1/ai-functions/:ai_service_id/:ai_function_id",
    request_body = AiFunctionPut,
    responses(
        (status = 200, description = "AI Function updated.", body = AiFunction),
        (status = 403, description = "Forbidden.", body = ResponseError),
        (status = 404, description = "AI Function not found.", body = ResponseError),
    ),
    params(
        ("ai_service_id" = String, Path, description = "AI Service id"),
        ("ai_function_id" = String, Path, description = "AI Function id"),
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn update(
    State(context): State<Arc<Context>>,
    extracted_session: ExtractedSession,
    Path(Params {
        ai_service_id,
        ai_function_id,
    }): Path<Params>,
    Json(input): Json<AiFunctionPut>,
) -> Result<impl IntoResponse, AppError> {
    ensure_secured(context.clone(), extracted_session, ROLE_COMPANY_ADMIN_USER).await?;
    input.validate()?;

    let ai_function = context
        .octopus_database
        .try_get_ai_function_by_id(ai_function_id)
        .await?
        .ok_or(AppError::NotFound)?;

    if ai_service_id != ai_function.ai_service_id {
        return Err(AppError::Forbidden);
    }

    let ai_function = context
        .octopus_database
        .update_ai_function_is_enabled(ai_function.id, input.is_enabled)
        .await?;

    Ok((StatusCode::OK, Json(ai_function)).into_response())
}
