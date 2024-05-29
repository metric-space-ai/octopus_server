use crate::{
    ai::generator,
    api::ai_services::PyFile,
    context::Context,
    entity::{AiServiceGeneratorStatus, ROLE_COMPANY_ADMIN_USER},
    error::AppError,
    parser,
    session::{require_authenticated, ExtractedSession},
};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use std::sync::Arc;
use tracing::debug;
use utoipa::ToSchema;
use uuid::Uuid;
use validator::Validate;

#[derive(Debug, Deserialize, ToSchema, Validate)]
pub struct AiServiceGeneratorGeneratePost {
    pub skip_regenerate_internet_research_results: Option<bool>,
}

#[derive(Debug, Deserialize, ToSchema, Validate)]
pub struct AiServiceGeneratorPost {
    pub description: String,
    pub name: String,
    pub sample_code: Option<String>,
    pub version: Option<i32>,
}

#[derive(Debug, Deserialize, ToSchema, Validate)]
pub struct AiServiceGeneratorPut {
    pub description: String,
    pub name: String,
    pub sample_code: Option<String>,
    pub version: Option<i32>,
}

#[axum_macros::debug_handler]
#[utoipa::path(
    post,
    path = "/api/v1/ai-service-generators",
    request_body = AiServiceGeneratorPost,
    responses(
        (status = 201, description = "AI Service generator created.", body = AiServiceGenerator),
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
    Json(input): Json<AiServiceGeneratorPost>,
) -> Result<impl IntoResponse, AppError> {
    let session = require_authenticated(extracted_session).await?;

    let session_user = context
        .octopus_database
        .try_get_user_by_id(session.user_id)
        .await?
        .ok_or(AppError::Forbidden)?;

    input.validate()?;

    let mut transaction = context.octopus_database.transaction_begin().await?;

    let ai_service_generator = context
        .octopus_database
        .insert_ai_service_generator(
            &mut transaction,
            session_user.id,
            &input.description,
            &input.name,
            input.sample_code,
            input.version.unwrap_or(1),
        )
        .await?;

    context
        .octopus_database
        .transaction_commit(transaction)
        .await?;

    Ok((StatusCode::CREATED, Json(ai_service_generator)).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    delete,
    path = "/api/v1/ai-service-generators/:id",
    responses(
        (status = 204, description = "AI Service generator deleted."),
        (status = 403, description = "Forbidden.", body = ResponseError),
        (status = 404, description = "AI Service generator not found.", body = ResponseError),
    ),
    params(
        ("id" = String, Path, description = "AI Service generator id")
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
    let session = require_authenticated(extracted_session).await?;

    let session_user = context
        .octopus_database
        .try_get_user_by_id(session.user_id)
        .await?
        .ok_or(AppError::Forbidden)?;

    let ai_service_generator = context
        .octopus_database
        .try_get_ai_service_generator_by_id(id)
        .await?
        .ok_or(AppError::NotFound)?;

    let user = context
        .octopus_database
        .try_get_user_by_id(ai_service_generator.user_id)
        .await?
        .ok_or(AppError::NotFound)?;

    if session_user.id != ai_service_generator.user_id
        && (!session_user
            .roles
            .contains(&ROLE_COMPANY_ADMIN_USER.to_string())
            || session_user.company_id != user.company_id)
    {
        return Err(AppError::Forbidden);
    }

    let mut transaction = context.octopus_database.transaction_begin().await?;

    context
        .octopus_database
        .try_delete_ai_service_generator_by_id(&mut transaction, ai_service_generator.id)
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
    post,
    path = "/api/v1/ai-service-generators/:id/deploy",
    responses(
        (status = 200, description = "AI Service generator deploy request.", body = AiServiceGenerator),
        (status = 400, description = "Bad request.", body = ResponseError),
        (status = 403, description = "Forbidden.", body = ResponseError),
        (status = 404, description = "AI Service generator not found.", body = ResponseError),
    ),
    params(
        ("id" = String, Path, description = "AI Service generator id")
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn deploy(
    State(context): State<Arc<Context>>,
    extracted_session: ExtractedSession,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let session = require_authenticated(extracted_session).await?;

    let session_user = context
        .octopus_database
        .try_get_user_by_id(session.user_id)
        .await?
        .ok_or(AppError::Forbidden)?;

    let ai_service_generator = context
        .octopus_database
        .try_get_ai_service_generator_by_id(id)
        .await?
        .ok_or(AppError::NotFound)?;

    if ai_service_generator.status != AiServiceGeneratorStatus::Generated {
        return Err(AppError::Conflict);
    }

    let user = context
        .octopus_database
        .try_get_user_by_id(ai_service_generator.user_id)
        .await?
        .ok_or(AppError::NotFound)?;

    if session_user.id != ai_service_generator.user_id
        && (!session_user
            .roles
            .contains(&ROLE_COMPANY_ADMIN_USER.to_string())
            || session_user.company_id != user.company_id)
    {
        return Err(AppError::Forbidden);
    }

    if let Some(ref original_function_body) = ai_service_generator.original_function_body {
        let mut transaction = context.octopus_database.transaction_begin().await?;

        let ai_service = match ai_service_generator.ai_service_id {
            None => {
                let port = context
                    .octopus_database
                    .get_ai_services_max_port(&mut transaction)
                    .await?;

                let port = port.max.unwrap_or(9999) + 1;

                context
                    .octopus_database
                    .insert_ai_service(
                        &mut transaction,
                        &format!("{}.py", ai_service_generator.id),
                        original_function_body,
                        port,
                    )
                    .await?
            }
            Some(ai_service_id) => {
                context
                    .octopus_database
                    .update_ai_service(
                        &mut transaction,
                        ai_service_id,
                        true,
                        &format!("{}.py", ai_service_generator.id),
                        original_function_body,
                    )
                    .await?
            }
        };

        context
            .octopus_database
            .update_ai_service_ai_service_generator_id(
                &mut transaction,
                ai_service.id,
                ai_service_generator.id,
            )
            .await?;

        context
            .octopus_database
            .update_ai_service_generator_ai_service_id(
                &mut transaction,
                ai_service_generator.id,
                ai_service.id,
            )
            .await?;

        context
            .octopus_database
            .transaction_commit(transaction)
            .await?;

        parser::ai_service_malicious_code_check(ai_service, true, context).await?;
    }

    Ok((StatusCode::CREATED, Json(ai_service_generator)).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    get,
    path = "/api/v1/ai-service-generators/:id/download-original-function-body",
    responses(
        (status = 200, description = "AI Service generator original function body.", body = String),
        (status = 403, description = "Forbidden.", body = ResponseError),
        (status = 404, description = "AI Service generator not found.", body = ResponseError),
    ),
    params(
        ("id" = String, Path, description = "AI Service generator id")
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn download_original_function_body(
    State(context): State<Arc<Context>>,
    extracted_session: ExtractedSession,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    require_authenticated(extracted_session).await?;

    let ai_service_generator = context
        .octopus_database
        .try_get_ai_service_generator_by_id(id)
        .await?
        .ok_or(AppError::NotFound)?;

    let original_function_body = ai_service_generator
        .original_function_body
        .unwrap_or("".to_string());

    Ok((StatusCode::OK, PyFile(original_function_body)).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    post,
    path = "/api/v1/ai-service-generators/:id/generate",
    request_body = AiServiceGeneratorGeneratePost,
    responses(
        (status = 200, description = "AI Service generator generate request.", body = AiServiceGenerator),
        (status = 400, description = "Bad request.", body = ResponseError),
        (status = 403, description = "Forbidden.", body = ResponseError),
        (status = 404, description = "AI Service generator not found.", body = ResponseError),
    ),
    params(
        ("id" = String, Path, description = "AI Service generator id")
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn generate(
    State(context): State<Arc<Context>>,
    extracted_session: ExtractedSession,
    Path(id): Path<Uuid>,
    Json(input): Json<AiServiceGeneratorGeneratePost>,
) -> Result<impl IntoResponse, AppError> {
    let session = require_authenticated(extracted_session).await?;

    let session_user = context
        .octopus_database
        .try_get_user_by_id(session.user_id)
        .await?
        .ok_or(AppError::Forbidden)?;

    input.validate()?;

    let skip_regenerate_internet_research_results = input
        .skip_regenerate_internet_research_results
        .unwrap_or(false);

    let ai_service_generator = context
        .octopus_database
        .try_get_ai_service_generator_by_id(id)
        .await?
        .ok_or(AppError::NotFound)?;

    let user = context
        .octopus_database
        .try_get_user_by_id(ai_service_generator.user_id)
        .await?
        .ok_or(AppError::NotFound)?;

    if session_user.id != ai_service_generator.user_id
        && (!session_user
            .roles
            .contains(&ROLE_COMPANY_ADMIN_USER.to_string())
            || session_user.company_id != user.company_id)
    {
        return Err(AppError::Forbidden);
    }

    let mut transaction = context.octopus_database.transaction_begin().await?;

    let ai_service_generator = context
        .octopus_database
        .update_ai_service_generator_status(
            &mut transaction,
            ai_service_generator.id,
            AiServiceGeneratorStatus::Generating,
        )
        .await?;

    context
        .octopus_database
        .transaction_commit(transaction)
        .await?;

    let cloned_context = context.clone();
    let cloned_ai_service_generator = ai_service_generator.clone();
    tokio::spawn(async move {
        let ai_service_generator = generator::generate(
            cloned_ai_service_generator,
            cloned_context,
            skip_regenerate_internet_research_results,
        )
        .await;

        if let Err(e) = ai_service_generator {
            debug!("Error: {:?}", e);
        }
    });

    Ok((StatusCode::CREATED, Json(ai_service_generator)).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    get,
    path = "/api/v1/ai-service-generators",
    responses(
        (status = 200, description = "List of AI Service generators.", body = [AiServiceGenerator]),
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

    let ai_service_generators = context.octopus_database.get_ai_service_generators().await?;

    Ok((StatusCode::OK, Json(ai_service_generators)).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    get,
    path = "/api/v1/ai-service-generators/:id",
    responses(
        (status = 200, description = "AI Service generator read.", body = AiServiceGenerator),
        (status = 401, description = "Unauthorized request.", body = ResponseError),
        (status = 404, description = "AI Service generator not found.", body = ResponseError),
    ),
    params(
        ("id" = String, Path, description = "AI Service generator id")
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
    let session = require_authenticated(extracted_session).await?;

    let session_user = context
        .octopus_database
        .try_get_user_by_id(session.user_id)
        .await?
        .ok_or(AppError::Forbidden)?;

    let ai_service_generator = context
        .octopus_database
        .try_get_ai_service_generator_by_id(id)
        .await?
        .ok_or(AppError::NotFound)?;

    let user = context
        .octopus_database
        .try_get_user_by_id(ai_service_generator.user_id)
        .await?
        .ok_or(AppError::NotFound)?;

    if session_user.id != ai_service_generator.user_id
        && (!session_user
            .roles
            .contains(&ROLE_COMPANY_ADMIN_USER.to_string())
            || session_user.company_id != user.company_id)
    {
        return Err(AppError::Forbidden);
    }

    Ok((StatusCode::OK, Json(ai_service_generator)).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    put,
    path = "/api/v1/ai-service-generators/:id",
    request_body = AiServiceGeneratorPut,
    responses(
        (status = 200, description = "AI Service generator updated.", body = AiServiceGenerator),
        (status = 400, description = "Bad request.", body = ResponseError),
        (status = 403, description = "Forbidden.", body = ResponseError),
        (status = 404, description = "AI Service generator not found.", body = ResponseError),
    ),
    params(
        ("id" = String, Path, description = "AI Service generator id")
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn update(
    State(context): State<Arc<Context>>,
    extracted_session: ExtractedSession,
    Path(id): Path<Uuid>,
    Json(input): Json<AiServiceGeneratorPut>,
) -> Result<impl IntoResponse, AppError> {
    let session = require_authenticated(extracted_session).await?;

    let session_user = context
        .octopus_database
        .try_get_user_by_id(session.user_id)
        .await?
        .ok_or(AppError::Forbidden)?;

    input.validate()?;

    let ai_service_generator = context
        .octopus_database
        .try_get_ai_service_generator_by_id(id)
        .await?
        .ok_or(AppError::NotFound)?;

    let user = context
        .octopus_database
        .try_get_user_by_id(ai_service_generator.user_id)
        .await?
        .ok_or(AppError::NotFound)?;

    if session_user.id != ai_service_generator.user_id
        && (!session_user
            .roles
            .contains(&ROLE_COMPANY_ADMIN_USER.to_string())
            || session_user.company_id != user.company_id)
    {
        return Err(AppError::Forbidden);
    }

    let mut transaction = context.octopus_database.transaction_begin().await?;

    let ai_service_generator = context
        .octopus_database
        .update_ai_service_generator(
            &mut transaction,
            ai_service_generator.id,
            &input.description,
            &input.name,
            input.sample_code,
            AiServiceGeneratorStatus::Changed,
            input.version.unwrap_or(1),
        )
        .await?;

    context
        .octopus_database
        .transaction_commit(transaction)
        .await?;

    Ok((StatusCode::OK, Json(ai_service_generator)).into_response())
}
