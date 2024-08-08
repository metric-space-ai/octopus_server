use crate::{
    ai,
    context::Context,
    entity::{AiServiceStatus, AiServiceType, ROLE_COMPANY_ADMIN_USER},
    error::AppError,
    get_pwd, parser, process_manager,
    session::{require_authenticated, ExtractedSession},
    SERVICES_DIR,
};
use axum::{
    body::Body,
    extract::{Multipart, Path, Query, State},
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use chrono::{DateTime, Duration, Utc};
use rev_buf_reader::RevBufReader;
use serde::{Deserialize, Serialize};
use std::{fs::File, io::BufRead, path, sync::Arc};
use utoipa::ToSchema;
use uuid::Uuid;
use validator::Validate;

#[derive(Debug, Deserialize, ToSchema, Validate)]
pub struct AiServiceAllowedUsersPut {
    pub allowed_user_ids: Vec<Uuid>,
}

#[derive(Debug, Deserialize, ToSchema, Validate)]
pub struct AiServiceColorPut {
    pub color: String,
}

#[derive(Debug, Deserialize, ToSchema, Validate)]
pub struct AiServiceConfigurationPut {
    pub color: Option<String>,
    pub device_map: serde_json::Value,
    pub r#type: Option<AiServiceType>,
}

#[derive(Clone, Debug, Deserialize, ToSchema)]
pub enum AiServiceOperation {
    Disable,
    Enable,
    HealthCheck,
    Setup,
}

#[derive(Clone, Debug, Deserialize, ToSchema, Validate)]
pub struct AiServiceOperationPost {
    pub operation: AiServiceOperation,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AiServiceOperationResponse {
    pub estimated_operation_end_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, ToSchema, Validate)]
pub struct AiServicePriorityPut {
    #[validate(range(min = 0, max = 31))]
    pub priority: i32,
}

#[axum_macros::debug_handler]
#[utoipa::path(
    put,
    path = "/api/v1/ai-services/:id/allowed-users",
    request_body = AiServiceAllowedUsersPut,
    responses(
        (status = 200, description = "AI Service configured.", body = AiService),
        (status = 401, description = "Unauthorized request.", body = ResponseError),
        (status = 403, description = "Forbidden.", body = ResponseError),
        (status = 404, description = "AI Service not found.", body = ResponseError),
    ),
    params(
        ("id" = String, Path, description = "AI Service id")
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn allowed_users(
    State(context): State<Arc<Context>>,
    extracted_session: ExtractedSession,
    Path(id): Path<Uuid>,
    Json(input): Json<AiServiceAllowedUsersPut>,
) -> Result<impl IntoResponse, AppError> {
    let session = require_authenticated(extracted_session).await?;

    let session_user = context
        .octopus_database
        .try_get_user_by_id(session.user_id)
        .await?
        .ok_or(AppError::Forbidden)?;

    if !session_user
        .roles
        .contains(&ROLE_COMPANY_ADMIN_USER.to_string())
    {
        return Err(AppError::Forbidden);
    }

    input.validate()?;

    let ai_service = context
        .octopus_database
        .try_get_ai_service_by_id(id)
        .await?
        .ok_or(AppError::NotFound)?;

    let allowed_user_ids = if input.allowed_user_ids.is_empty() {
        None
    } else {
        Some(input.allowed_user_ids)
    };

    let mut transaction = context.octopus_database.transaction_begin().await?;

    let ai_service = context
        .octopus_database
        .update_ai_service_allowed_user_ids(&mut transaction, ai_service.id, allowed_user_ids)
        .await?;

    context
        .octopus_database
        .transaction_commit(transaction)
        .await?;

    Ok((StatusCode::OK, Json(ai_service)).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    put,
    path = "/api/v1/ai-services/:id/color",
    request_body = AiServiceColorPut,
    responses(
        (status = 200, description = "AI Service configured.", body = AiService),
        (status = 401, description = "Unauthorized request.", body = ResponseError),
        (status = 403, description = "Forbidden.", body = ResponseError),
        (status = 404, description = "AI Service not found.", body = ResponseError),
    ),
    params(
        ("id" = String, Path, description = "AI Service id")
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn color(
    State(context): State<Arc<Context>>,
    extracted_session: ExtractedSession,
    Path(id): Path<Uuid>,
    Json(input): Json<AiServiceColorPut>,
) -> Result<impl IntoResponse, AppError> {
    let session = require_authenticated(extracted_session).await?;

    let session_user = context
        .octopus_database
        .try_get_user_by_id(session.user_id)
        .await?
        .ok_or(AppError::Forbidden)?;

    if !session_user
        .roles
        .contains(&ROLE_COMPANY_ADMIN_USER.to_string())
    {
        return Err(AppError::Forbidden);
    }

    input.validate()?;

    let ai_service = context
        .octopus_database
        .try_get_ai_service_by_id(id)
        .await?
        .ok_or(AppError::NotFound)?;

    let mut transaction = context.octopus_database.transaction_begin().await?;

    let ai_service = context
        .octopus_database
        .update_ai_service_color(&mut transaction, ai_service.id, &input.color)
        .await?;

    context
        .octopus_database
        .transaction_commit(transaction)
        .await?;

    Ok((StatusCode::OK, Json(ai_service)).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    put,
    path = "/api/v1/ai-services/:id/configuration",
    request_body = AiServiceConfigurationPut,
    responses(
        (status = 200, description = "AI Service configured.", body = AiService),
        (status = 401, description = "Unauthorized request.", body = ResponseError),
        (status = 403, description = "Forbidden.", body = ResponseError),
        (status = 404, description = "AI Service not found.", body = ResponseError),
        (status = 409, description = "Conflicting request.", body = ResponseError),
    ),
    params(
        ("id" = String, Path, description = "AI Service id")
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn configuration(
    State(context): State<Arc<Context>>,
    extracted_session: ExtractedSession,
    Path(id): Path<Uuid>,
    Json(input): Json<AiServiceConfigurationPut>,
) -> Result<impl IntoResponse, AppError> {
    let session = require_authenticated(extracted_session).await?;

    let session_user = context
        .octopus_database
        .try_get_user_by_id(session.user_id)
        .await?
        .ok_or(AppError::Forbidden)?;

    if !session_user
        .roles
        .contains(&ROLE_COMPANY_ADMIN_USER.to_string())
    {
        return Err(AppError::Forbidden);
    }

    input.validate()?;

    let ai_service = context
        .octopus_database
        .try_get_ai_service_by_id(id)
        .await?
        .ok_or(AppError::NotFound)?;

    if ai_service.status == AiServiceStatus::Initial
        || ai_service.status == AiServiceStatus::MaliciousCodeDetected
    {
        return Err(AppError::Conflict);
    }

    let mut transaction = context.octopus_database.transaction_begin().await?;

    let r#type = input.r#type.unwrap_or(AiServiceType::Normal);
    let color = input.color.unwrap_or("#b7b7b7".to_string());

    let ai_service = context
        .octopus_database
        .update_ai_service_device_map(
            &mut transaction,
            ai_service.id,
            input.device_map,
            AiServiceStatus::ParsingStarted,
            r#type,
            &color,
        )
        .await?;

    context
        .octopus_database
        .transaction_commit(transaction)
        .await?;

    let cloned_context = context.clone();
    let cloned_ai_service = ai_service.clone();
    tokio::spawn(async move {
        let ai_service = parser::ai_service_parsing(cloned_ai_service, cloned_context).await;

        if let Err(e) = ai_service {
            tracing::error!("Error: {:?}", e);
        }
    });

    Ok((StatusCode::OK, Json(ai_service)).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    post,
    path = "/api/v1/ai-services",
    responses(
        (status = 201, description = "AI Service created.", body = AiService),
        (status = 400, description = "Bad request.", body = ResponseError),
        (status = 401, description = "Unauthorized request.", body = ResponseError),
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
    let session = require_authenticated(extracted_session).await?;

    let session_user = context
        .octopus_database
        .try_get_user_by_id(session.user_id)
        .await?
        .ok_or(AppError::Forbidden)?;

    if !session_user
        .roles
        .contains(&ROLE_COMPANY_ADMIN_USER.to_string())
    {
        return Err(AppError::Forbidden);
    }

    let mut bypass_code_check = false;
    let mut data = None;
    let mut original_file_name = None;

    while let Some(field) = multipart.next_field().await? {
        let field_name = (field.name().ok_or(AppError::Parsing)?).to_string();

        if field_name == "bypass_code_check" {
            bypass_code_check = (field.text().await?).parse::<bool>().unwrap_or(false);
        } else {
            original_file_name = Some((field.file_name().ok_or(AppError::File)?).to_string());
            let content_type = (field.content_type().ok_or(AppError::File)?).to_string();

            if content_type == "application/octet-stream" || content_type == "text/plain" {
                data = Some(field.bytes().await?.clone().to_vec());
            }
        }
    }

    if let (Some(data), Some(original_file_name)) = (data, original_file_name) {
        let mut transaction = context.octopus_database.transaction_begin().await?;

        let port = context
            .octopus_database
            .get_ai_services_max_port(&mut transaction)
            .await?;

        let port = port.max.unwrap_or(9999) + 1;
        let original_function_body = String::from_utf8(data)?;

        let ai_service = context
            .octopus_database
            .insert_ai_service(
                &mut transaction,
                &original_file_name,
                &original_function_body,
                port,
            )
            .await?;

        context
            .octopus_database
            .transaction_commit(transaction)
            .await?;

        let ai_service =
            parser::ai_service_malicious_code_check(ai_service, bypass_code_check, context).await?;

        return Ok((StatusCode::CREATED, Json(ai_service)).into_response());
    }

    Err(AppError::BadRequest)
}

#[axum_macros::debug_handler]
#[utoipa::path(
    delete,
    path = "/api/v1/ai-services/:id",
    responses(
        (status = 204, description = "AI Service deleted."),
        (status = 401, description = "Unauthorized request.", body = ResponseError),
        (status = 403, description = "Forbidden.", body = ResponseError),
        (status = 404, description = "AI Service not found.", body = ResponseError),
    ),
    params(
        ("id" = String, Path, description = "AI Service id")
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

    if !session_user
        .roles
        .contains(&ROLE_COMPANY_ADMIN_USER.to_string())
    {
        return Err(AppError::Forbidden);
    }

    let ai_service = context
        .octopus_database
        .try_get_ai_service_by_id(id)
        .await?
        .ok_or(AppError::NotFound)?;

    let ai_service =
        process_manager::ai_service::stop_and_remove(ai_service, context.clone()).await?;

    let mut transaction = context.octopus_database.transaction_begin().await?;

    context
        .octopus_database
        .try_delete_ai_service_by_id(&mut transaction, ai_service.id)
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
    path = "/api/v1/ai-services/:id/diff",
    responses(
        (status = 200, description = "AI Service diff.", body = String),
        (status = 401, description = "Unauthorized request.", body = ResponseError),
        (status = 403, description = "Forbidden.", body = ResponseError),
        (status = 404, description = "AI Service not found.", body = ResponseError),
    ),
    params(
        ("id" = String, Path, description = "AI Service id")
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn diff(
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

    if !session_user
        .roles
        .contains(&ROLE_COMPANY_ADMIN_USER.to_string())
    {
        return Err(AppError::Forbidden);
    }

    let ai_service = context
        .octopus_database
        .try_get_ai_service_by_id(id)
        .await?
        .ok_or(AppError::NotFound)?;

    let mut result = String::new();
    let original_function_body = ai_service.original_function_body;
    let processed_function_body = ai_service.processed_function_body.unwrap_or(String::new());

    for diff in diff::lines(&original_function_body, &processed_function_body) {
        match diff {
            diff::Result::Left(l) => result.push_str(&format!("-{l}\n")),
            diff::Result::Both(l, _) => result.push_str(&format!(" {l}\n")),
            diff::Result::Right(r) => result.push_str(&format!("+{r}\n")),
        }
    }

    Ok((StatusCode::OK, result).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    get,
    path = "/api/v1/ai-services/:id/download-original-function-body",
    responses(
        (status = 200, description = "AI Service original function body.", body = String),
        (status = 401, description = "Unauthorized request.", body = ResponseError),
        (status = 403, description = "Forbidden.", body = ResponseError),
        (status = 404, description = "AI Service not found.", body = ResponseError),
    ),
    params(
        ("id" = String, Path, description = "AI Service id")
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
    let session = require_authenticated(extracted_session).await?;

    let session_user = context
        .octopus_database
        .try_get_user_by_id(session.user_id)
        .await?
        .ok_or(AppError::Forbidden)?;

    if !session_user
        .roles
        .contains(&ROLE_COMPANY_ADMIN_USER.to_string())
    {
        return Err(AppError::Forbidden);
    }

    let ai_service = context
        .octopus_database
        .try_get_ai_service_by_id(id)
        .await?
        .ok_or(AppError::NotFound)?;

    let original_function_body = ai_service.original_function_body;

    Ok((StatusCode::OK, PyFile(original_function_body)).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    get,
    path = "/api/v1/ai-services/:id/download-processed-function-body",
    responses(
        (status = 200, description = "AI Service processed function body.", body = String),
        (status = 401, description = "Unauthorized request.", body = ResponseError),
        (status = 403, description = "Forbidden.", body = ResponseError),
        (status = 404, description = "AI Service not found.", body = ResponseError),
    ),
    params(
        ("id" = String, Path, description = "AI Service id")
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn download_processed_function_body(
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

    if !session_user
        .roles
        .contains(&ROLE_COMPANY_ADMIN_USER.to_string())
    {
        return Err(AppError::Forbidden);
    }

    let ai_service = context
        .octopus_database
        .try_get_ai_service_by_id(id)
        .await?
        .ok_or(AppError::NotFound)?;

    let processed_function_body = ai_service.processed_function_body.unwrap_or(String::new());

    Ok((StatusCode::OK, PyFile(processed_function_body)).into_response())
}

#[derive(Clone, Copy, Debug)]
#[must_use]
pub struct PyFile<T>(pub T);

impl<T> IntoResponse for PyFile<T>
where
    T: Into<Body>,
{
    fn into_response(self) -> Response {
        (
            [
                (
                    header::CONTENT_TYPE,
                    HeaderValue::from_static(mime::OCTET_STREAM.as_ref()),
                ),
                (
                    header::CONTENT_DISPOSITION,
                    HeaderValue::from_static("attachment; filename=\"file.py\""),
                ),
            ],
            self.0.into(),
        )
            .into_response()
    }
}

#[axum_macros::debug_handler]
#[utoipa::path(
    put,
    path = "/api/v1/ai-services/:id/installation",
    responses(
        (status = 200, description = "AI Service configured.", body = AiService),
        (status = 401, description = "Unauthorized request.", body = ResponseError),
        (status = 403, description = "Forbidden.", body = ResponseError),
        (status = 404, description = "AI Service not found.", body = ResponseError),
        (status = 409, description = "Conflicting request.", body = ResponseError),
    ),
    params(
        ("id" = String, Path, description = "AI Service id")
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn installation(
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

    if !session_user
        .roles
        .contains(&ROLE_COMPANY_ADMIN_USER.to_string())
    {
        return Err(AppError::Forbidden);
    }

    let ai_service = context
        .octopus_database
        .try_get_ai_service_by_id(id)
        .await?
        .ok_or(AppError::NotFound)?;

    if ai_service.status == AiServiceStatus::Configuration
        || ai_service.status == AiServiceStatus::Initial
        || ai_service.status == AiServiceStatus::MaliciousCodeDetected
        || ai_service.status == AiServiceStatus::ParsingStarted
    {
        return Err(AppError::Conflict);
    }

    let cloned_context = context.clone();
    let cloned_ai_service = ai_service.clone();
    tokio::spawn(async move {
        let ai_service =
            process_manager::ai_service::install_and_run(cloned_ai_service, cloned_context).await;

        if let Err(e) = ai_service {
            tracing::error!("Error: {:?}", e);
        }
    });

    Ok((StatusCode::OK, Json(ai_service)).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    get,
    path = "/api/v1/ai-services",
    responses(
        (status = 200, description = "List of AI Services.", body = [AiService]),
        (status = 401, description = "Unauthorized request.", body = ResponseError),
        (status = 403, description = "Forbidden.", body = ResponseError),
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn list(
    State(context): State<Arc<Context>>,
    extracted_session: ExtractedSession,
) -> Result<impl IntoResponse, AppError> {
    let session = require_authenticated(extracted_session).await?;

    context
        .octopus_database
        .try_get_user_by_id(session.user_id)
        .await?
        .ok_or(AppError::Forbidden)?;

    let ai_services = context.octopus_database.get_ai_services().await?;

    Ok((StatusCode::OK, Json(ai_services)).into_response())
}

#[derive(Deserialize)]
pub struct LogsParameters {
    limit: Option<usize>,
}

#[axum_macros::debug_handler]
#[utoipa::path(
    get,
    path = "/api/v1/ai-services/:id/logs",
    responses(
        (status = 200, description = "AI Service logs.", body = String),
        (status = 401, description = "Unauthorized request.", body = ResponseError),
        (status = 403, description = "Forbidden.", body = ResponseError),
        (status = 404, description = "AI Service not found.", body = ResponseError),
    ),
    params(
        ("id" = String, Path, description = "AI Service id")
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn logs(
    State(context): State<Arc<Context>>,
    extracted_session: ExtractedSession,
    Path(id): Path<Uuid>,
    logs_parameters: Query<LogsParameters>,
) -> Result<impl IntoResponse, AppError> {
    let session = require_authenticated(extracted_session).await?;

    let session_user = context
        .octopus_database
        .try_get_user_by_id(session.user_id)
        .await?
        .ok_or(AppError::Forbidden)?;

    if !session_user
        .roles
        .contains(&ROLE_COMPANY_ADMIN_USER.to_string())
    {
        return Err(AppError::Forbidden);
    }

    let ai_service = context
        .octopus_database
        .try_get_ai_service_by_id(id)
        .await?
        .ok_or(AppError::NotFound)?;

    let limit = logs_parameters.limit.unwrap_or(50);

    let pwd = get_pwd()?;

    let path = format!(
        "{pwd}/{SERVICES_DIR}/{}/{}.log",
        ai_service.id, ai_service.id
    );

    let file_exists = path::Path::new(&path).is_file();

    let logs = if file_exists {
        let file = File::open(path)?;
        let buf = RevBufReader::new(file);
        let mut reversed = vec![];
        let mut result = String::new();
        let iterator = buf
            .lines()
            .take(limit)
            .map(|l| l.expect("Could not parse line"));

        for item in iterator {
            reversed.push(item);
        }

        for item in reversed.iter().rev() {
            result.push_str(&format!("{item}\n"));
        }

        result
    } else {
        String::new()
    };

    Ok((StatusCode::OK, logs).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    post,
    path = "/api/v1/ai-services/:id",
    request_body = AiServiceOperationPost,
    responses(
        (status = 201, description = "AI Service operation scheduled.", body = AiServiceOperationResponse),
        (status = 401, description = "Unauthorized request.", body = ResponseError),
        (status = 403, description = "Forbidden.", body = ResponseError),
        (status = 404, description = "AI Service not found.", body = ResponseError),
        (status = 409, description = "Conflicting request.", body = ResponseError),
    ),
    params(
        ("id" = String, Path, description = "AI Service id")
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn operation(
    State(context): State<Arc<Context>>,
    extracted_session: ExtractedSession,
    Path(id): Path<Uuid>,
    Json(input): Json<AiServiceOperationPost>,
) -> Result<impl IntoResponse, AppError> {
    let session = require_authenticated(extracted_session).await?;

    let session_user = context
        .octopus_database
        .try_get_user_by_id(session.user_id)
        .await?
        .ok_or(AppError::Forbidden)?;

    if !session_user
        .roles
        .contains(&ROLE_COMPANY_ADMIN_USER.to_string())
    {
        return Err(AppError::Forbidden);
    }

    input.validate()?;

    let ai_service = context
        .octopus_database
        .try_get_ai_service_by_id(id)
        .await?
        .ok_or(AppError::NotFound)?;

    match input.operation {
        AiServiceOperation::Disable => {
            if !(ai_service.status == AiServiceStatus::Restarting
                || ai_service.status == AiServiceStatus::Running
                || ai_service.status == AiServiceStatus::Setup
                || ai_service.status == AiServiceStatus::Stopped)
            {
                return Err(AppError::Conflict);
            }
        }
        AiServiceOperation::Enable => {
            if !(ai_service.status == AiServiceStatus::Restarting
                || ai_service.status == AiServiceStatus::Running
                || ai_service.status == AiServiceStatus::Stopped)
            {
                return Err(AppError::Conflict);
            }
        }
        AiServiceOperation::HealthCheck => {
            if ai_service.status != AiServiceStatus::Running {
                return Err(AppError::Conflict);
            }
        }
        AiServiceOperation::Setup => {
            if !(ai_service.status == AiServiceStatus::Running
                || ai_service.status == AiServiceStatus::Setup)
            {
                return Err(AppError::Conflict);
            }
        }
    }

    let cloned_context = context.clone();
    let cloned_ai_service = ai_service.clone();
    let cloned_input = input.clone();
    tokio::spawn(async move {
        let ai_service = match cloned_input.operation {
            AiServiceOperation::Disable => {
                let mut ai_service =
                    process_manager::ai_service::stop(cloned_ai_service, cloned_context).await;

                if let Ok(ref ai_service_ok) = ai_service {
                    let transaction = context.octopus_database.transaction_begin().await;

                    if let Ok(mut transaction) = transaction {
                        ai_service = context
                            .octopus_database
                            .update_ai_service_is_enabled_and_status(
                                &mut transaction,
                                ai_service_ok.id,
                                false,
                                100,
                                AiServiceStatus::Stopped,
                            )
                            .await;

                        let _ = context
                            .octopus_database
                            .transaction_commit(transaction)
                            .await;
                    }
                }

                ai_service
            }
            AiServiceOperation::Enable => {
                process_manager::ai_service::try_restart(cloned_ai_service, cloned_context).await
            }
            AiServiceOperation::HealthCheck => {
                ai::service::service_health_check(
                    cloned_ai_service.id,
                    cloned_context,
                    cloned_ai_service.port,
                    40,
                )
                .await
            }
            AiServiceOperation::Setup => {
                ai::service::service_setup(
                    cloned_ai_service.id,
                    cloned_context,
                    cloned_ai_service.port,
                )
                .await
            }
        };

        if let Err(e) = ai_service {
            tracing::error!("Error: {:?}", e);
        }
    });

    let execution_time = match input.operation {
        AiServiceOperation::Disable | AiServiceOperation::Enable => 1,
        AiServiceOperation::HealthCheck => ai_service.health_check_execution_time,
        AiServiceOperation::Setup => ai_service.setup_execution_time,
    };

    let estimated_operation_end_at = Utc::now()
        + Duration::try_seconds(i64::from(execution_time) + 1).ok_or(AppError::FromTime)?;

    let ai_service_operation_response = AiServiceOperationResponse {
        estimated_operation_end_at,
    };

    Ok((StatusCode::CREATED, Json(ai_service_operation_response)).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    put,
    path = "/api/v1/ai-services/:id/priority",
    request_body = AiServicePriorityPut,
    responses(
        (status = 200, description = "AI Service priority changed.", body = AiService),
        (status = 401, description = "Unauthorized request.", body = ResponseError),
        (status = 403, description = "Forbidden.", body = ResponseError),
        (status = 404, description = "AI Service not found.", body = ResponseError),
    ),
    params(
        ("id" = String, Path, description = "AI Service id")
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn priority(
    State(context): State<Arc<Context>>,
    extracted_session: ExtractedSession,
    Path(id): Path<Uuid>,
    Json(input): Json<AiServicePriorityPut>,
) -> Result<impl IntoResponse, AppError> {
    let session = require_authenticated(extracted_session).await?;

    let session_user = context
        .octopus_database
        .try_get_user_by_id(session.user_id)
        .await?
        .ok_or(AppError::Forbidden)?;

    if !session_user
        .roles
        .contains(&ROLE_COMPANY_ADMIN_USER.to_string())
    {
        return Err(AppError::Forbidden);
    }

    input.validate()?;

    let ai_service = context
        .octopus_database
        .try_get_ai_service_by_id(id)
        .await?
        .ok_or(AppError::NotFound)?;

    let mut transaction = context.octopus_database.transaction_begin().await?;

    let ai_service = context
        .octopus_database
        .update_ai_service_priority(&mut transaction, ai_service.id, input.priority)
        .await?;

    context
        .octopus_database
        .transaction_commit(transaction)
        .await?;

    Ok((StatusCode::OK, Json(ai_service)).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    get,
    path = "/api/v1/ai-services/:id",
    responses(
        (status = 200, description = "AI Service read.", body = AiService),
        (status = 401, description = "Unauthorized request.", body = ResponseError),
        (status = 403, description = "Forbidden.", body = ResponseError),
        (status = 404, description = "AI Service not found.", body = ResponseError),
    ),
    params(
        ("id" = String, Path, description = "AI Service id")
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

    context
        .octopus_database
        .try_get_user_by_id(session.user_id)
        .await?
        .ok_or(AppError::Forbidden)?;

    let ai_service = context
        .octopus_database
        .try_get_ai_service_by_id(id)
        .await?
        .ok_or(AppError::NotFound)?;

    Ok((StatusCode::OK, Json(ai_service)).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    put,
    path = "/api/v1/ai-services/:id",
    responses(
        (status = 200, description = "AI Service updated.", body = AiService),
        (status = 400, description = "Bad request.", body = ResponseError),
        (status = 401, description = "Unauthorized request.", body = ResponseError),
        (status = 403, description = "Forbidden.", body = ResponseError),
        (status = 404, description = "AI Service not found.", body = ResponseError),
    ),
    params(
        ("id" = String, Path, description = "AI Service id")
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
    let session = require_authenticated(extracted_session).await?;

    let session_user = context
        .octopus_database
        .try_get_user_by_id(session.user_id)
        .await?
        .ok_or(AppError::Forbidden)?;

    if !session_user
        .roles
        .contains(&ROLE_COMPANY_ADMIN_USER.to_string())
    {
        return Err(AppError::Forbidden);
    }

    let mut bypass_code_check = false;
    let mut data = None;
    let mut original_file_name = None;

    context
        .octopus_database
        .try_get_ai_service_id_by_id(id)
        .await?
        .ok_or(AppError::NotFound)?;

    while let Some(field) = multipart.next_field().await? {
        let field_name = (field.name().ok_or(AppError::Parsing)?).to_string();

        if field_name == "bypass_code_check" {
            bypass_code_check = (field.text().await?).parse::<bool>().unwrap_or(false);
        } else {
            original_file_name = Some((field.file_name().ok_or(AppError::File)?).to_string());
            let content_type = (field.content_type().ok_or(AppError::File)?).to_string();

            if content_type == "application/octet-stream" || content_type == "text/plain" {
                data = Some(field.bytes().await?.clone().to_vec());
            }
        }
    }

    if let (Some(data), Some(original_file_name)) = (data, original_file_name) {
        let original_function_body = String::from_utf8(data)?;

        let mut transaction = context.octopus_database.transaction_begin().await?;

        let ai_service = context
            .octopus_database
            .update_ai_service(
                &mut transaction,
                id,
                false,
                &original_file_name,
                &original_function_body,
            )
            .await?;

        context
            .octopus_database
            .transaction_commit(transaction)
            .await?;

        let ai_service =
            parser::ai_service_malicious_code_check(ai_service, bypass_code_check, context).await?;

        return Ok((StatusCode::OK, Json(ai_service)).into_response());
    }

    Err(AppError::BadRequest)
}

#[cfg(test)]
pub mod tests {
    use crate::{
        api, app,
        entity::{AiService, AiServiceStatus},
        multipart,
    };
    use axum::{
        body::Body,
        http::{self, Request, StatusCode},
        response::Response,
        Router,
    };
    use http_body_util::BodyExt;
    use tokio::time::{sleep, Duration};
    use tower::ServiceExt;
    use uuid::Uuid;

    pub async fn ai_service_request(
        router: Router,
        session_id: Uuid,
        body: &str,
        value: &str,
    ) -> Response<Body> {
        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/api/v1/ai-services")
            .header(http::header::CONTENT_TYPE, value)
            .header("X-Auth-Token".to_string(), session_id.to_string())
            .body(body.to_string())
            .unwrap();

        router.clone().oneshot(request).await.unwrap()
    }

    pub async fn ai_service_create(router: Router, session_id: Uuid) -> AiService {
        let body = multipart::tests::file_data(
            "application/octet-stream",
            "test.py",
            "data/test/test.py",
            true,
        )
        .unwrap();

        let value = format!(
            "{}; boundary={}",
            mime::MULTIPART_FORM_DATA,
            multipart::tests::BOUNDARY
        );

        loop {
            let response = ai_service_request(router.clone(), session_id, &body, &value).await;

            if response.status() == StatusCode::CREATED {
                assert_eq!(response.status(), StatusCode::CREATED);

                let body = BodyExt::collect(response.into_body())
                    .await
                    .unwrap()
                    .to_bytes()
                    .to_vec();
                let body: AiService = serde_json::from_slice(&body).unwrap();

                assert!(!body.is_enabled);
                assert_eq!(body.status, AiServiceStatus::Configuration);

                return body;
            }
        }
    }

    pub async fn ai_service_create_and_configure(router: Router, session_id: Uuid) -> AiService {
        let ai_service = ai_service_create(router.clone(), session_id).await;
        let ai_service_id = ai_service.id;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::PUT)
                    .uri(format!("/api/v1/ai-services/{ai_service_id}/configuration"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        "{\"device_map\": {
                            \"cpu\": \"22.8GiB\"
                        }}"
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = BodyExt::collect(response.into_body())
            .await
            .unwrap()
            .to_bytes()
            .to_vec();
        let body: AiService = serde_json::from_slice(&body).unwrap();

        assert!(!body.is_enabled);
        assert_eq!(body.status, AiServiceStatus::ParsingStarted);

        body
    }

    #[tokio::test]
    async fn allowed_users_200() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let ai_service = ai_service_create(router.clone(), session_id).await;
        let ai_service_id = ai_service.id;

        let allowed_user_ids = vec![user_id];

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::PUT)
                    .uri(format!("/api/v1/ai-services/{ai_service_id}/allowed-users"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "allowed_user_ids": &allowed_user_ids,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = BodyExt::collect(response.into_body())
            .await
            .unwrap()
            .to_bytes()
            .to_vec();
        let body: AiService = serde_json::from_slice(&body).unwrap();

        assert!(!body.is_enabled);
        assert_eq!(body.status, AiServiceStatus::Configuration);
        assert_eq!(body.allowed_user_ids, Some(allowed_user_ids));

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_ai_service_by_id(&mut transaction, ai_service_id)
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id],
            &[user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn allowed_users_401() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let ai_service = ai_service_create(router.clone(), session_id).await;
        let ai_service_id = ai_service.id;

        let allowed_user_ids = vec![user_id];

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::PUT)
                    .uri(format!("/api/v1/ai-services/{ai_service_id}/allowed-users"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "allowed_user_ids": &allowed_user_ids,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_ai_service_by_id(&mut transaction, ai_service_id)
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id],
            &[user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn allowed_users_403_deleted_user() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let ai_service = ai_service_create(router.clone(), session_id).await;
        let ai_service_id = ai_service.id;

        let allowed_user_ids = vec![user_id];

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(app.context.clone(), &mut transaction, &[], &[user_id])
            .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::PUT)
                    .uri(format!("/api/v1/ai-services/{ai_service_id}/allowed-users"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "allowed_user_ids": &allowed_user_ids,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_ai_service_by_id(&mut transaction, ai_service_id)
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(app.context.clone(), &mut transaction, &[company_id], &[])
            .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn allowed_users_404() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let ai_service_id = "33847746-0030-4964-a496-f75d04499160";

        let allowed_user_ids = vec![user_id];

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::PUT)
                    .uri(format!("/api/v1/ai-services/{ai_service_id}/allowed-users"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "allowed_user_ids": &allowed_user_ids,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id],
            &[user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn configuration_200() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let ai_service = ai_service_create_and_configure(router.clone(), session_id).await;
        let ai_service_id = ai_service.id;

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_ai_service_by_id(&mut transaction, ai_service_id)
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id],
            &[user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn configuration_401() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let ai_service = ai_service_create(router.clone(), session_id).await;
        let ai_service_id = ai_service.id;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::PUT)
                    .uri(format!("/api/v1/ai-services/{ai_service_id}/configuration"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        "{\"device_map\": {
                            \"cpu\": \"22.8GiB\"
                        }}"
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_ai_service_by_id(&mut transaction, ai_service_id)
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id],
            &[user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn configuration_403_deleted_user() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let ai_service = ai_service_create(router.clone(), session_id).await;
        let ai_service_id = ai_service.id;

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(app.context.clone(), &mut transaction, &[], &[user_id])
            .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::PUT)
                    .uri(format!("/api/v1/ai-services/{ai_service_id}/configuration"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        "{\"device_map\": {
                            \"cpu\": \"22.8GiB\"
                        }}"
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_ai_service_by_id(&mut transaction, ai_service_id)
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(app.context.clone(), &mut transaction, &[company_id], &[])
            .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn configuration_404() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let ai_service_id = "33847746-0030-4964-a496-f75d04499160";

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::PUT)
                    .uri(format!("/api/v1/ai-services/{ai_service_id}/configuration"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        "{\"device_map\": {
                            \"cpu\": \"22.8GiB\"
                        }}"
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id],
            &[user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn configuration_409() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let ai_service = ai_service_create(router.clone(), session_id).await;
        let ai_service_id = ai_service.id;

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        app.context
            .octopus_database
            .update_ai_service_status(&mut transaction, ai_service_id, 0, AiServiceStatus::Initial)
            .await
            .unwrap();

        api::tests::transaction_commit(app.context.clone(), transaction).await;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::PUT)
                    .uri(format!("/api/v1/ai-services/{ai_service_id}/configuration"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        "{\"device_map\": {
                            \"cpu\": \"22.8GiB\"
                        }}"
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CONFLICT);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_ai_service_by_id(&mut transaction, ai_service_id)
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id],
            &[user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn create_201() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let ai_service = ai_service_create(router, session_id).await;
        let ai_service_id = ai_service.id;

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_ai_service_by_id(&mut transaction, ai_service_id)
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id],
            &[user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn create_400() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/api/v1/ai-services")
            .header(
                http::header::CONTENT_TYPE,
                mime::MULTIPART_FORM_DATA.as_ref(),
            )
            .header("X-Auth-Token".to_string(), session_id.to_string())
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id],
            &[user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn create_401() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;

        let body = multipart::tests::file_data(
            "application/octet-stream",
            "test.py",
            "data/test/test.py",
            true,
        )
        .unwrap();

        let value = format!(
            "{}; boundary={}",
            mime::MULTIPART_FORM_DATA,
            multipart::tests::BOUNDARY
        );

        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/api/v1/ai-services")
            .header(http::header::CONTENT_TYPE, value)
            .body(body)
            .unwrap();

        let response = router.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id],
            &[user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn create_403_deleted_user() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(app.context.clone(), &mut transaction, &[], &[user_id])
            .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;

        let body = multipart::tests::file_data(
            "application/octet-stream",
            "test.py",
            "data/test/test.py",
            true,
        )
        .unwrap();

        let value = format!(
            "{}; boundary={}",
            mime::MULTIPART_FORM_DATA,
            multipart::tests::BOUNDARY
        );

        let response = ai_service_request(router.clone(), session_id, &body, &value).await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(app.context.clone(), &mut transaction, &[company_id], &[])
            .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn delete_204() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let ai_service = ai_service_create(router.clone(), session_id).await;
        let ai_service_id = ai_service.id;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::DELETE)
                    .uri(format!("/api/v1/ai-services/{ai_service_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id],
            &[user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn delete_401() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let ai_service = ai_service_create(router.clone(), session_id).await;
        let ai_service_id = ai_service.id;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::DELETE)
                    .uri(format!("/api/v1/ai-services/{ai_service_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_ai_service_by_id(&mut transaction, ai_service_id)
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id],
            &[user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn delete_403_deleted_user() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let ai_service = ai_service_create(router.clone(), session_id).await;
        let ai_service_id = ai_service.id;

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(app.context.clone(), &mut transaction, &[], &[user_id])
            .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::DELETE)
                    .uri(format!("/api/v1/ai-services/{ai_service_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_ai_service_by_id(&mut transaction, ai_service_id)
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id],
            &[user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn delete_404() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let ai_service_id = "33847746-0030-4964-a496-f75d04499160";

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::DELETE)
                    .uri(format!("/api/v1/ai-services/{ai_service_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id],
            &[user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn installation_200() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let ai_service = ai_service_create_and_configure(router.clone(), session_id).await;
        let ai_service_id = ai_service.id;

        sleep(Duration::from_secs(4)).await;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::PUT)
                    .uri(format!("/api/v1/ai-services/{ai_service_id}/installation"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = BodyExt::collect(response.into_body())
            .await
            .unwrap()
            .to_bytes()
            .to_vec();
        let body: AiService = serde_json::from_slice(&body).unwrap();

        assert!(!body.is_enabled);
        assert_eq!(body.status, AiServiceStatus::ParsingFinished);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_ai_service_by_id(&mut transaction, ai_service_id)
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id],
            &[user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn installation_401() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let ai_service = ai_service_create_and_configure(router.clone(), session_id).await;
        let ai_service_id = ai_service.id;

        sleep(Duration::from_secs(4)).await;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::PUT)
                    .uri(format!("/api/v1/ai-services/{ai_service_id}/installation"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_ai_service_by_id(&mut transaction, ai_service_id)
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id],
            &[user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn installation_403_deleted_user() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let ai_service = ai_service_create_and_configure(router.clone(), session_id).await;
        let ai_service_id = ai_service.id;

        sleep(Duration::from_secs(4)).await;

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(app.context.clone(), &mut transaction, &[], &[user_id])
            .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::PUT)
                    .uri(format!("/api/v1/ai-services/{ai_service_id}/installation"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_ai_service_by_id(&mut transaction, ai_service_id)
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(app.context.clone(), &mut transaction, &[company_id], &[])
            .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn installation_404() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let ai_service_id = "33847746-0030-4964-a496-f75d04499160";

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::PUT)
                    .uri(format!("/api/v1/ai-services/{ai_service_id}/installation"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id],
            &[user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn installation_409() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let ai_service = ai_service_create(router.clone(), session_id).await;
        let ai_service_id = ai_service.id;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::PUT)
                    .uri(format!("/api/v1/ai-services/{ai_service_id}/installation"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CONFLICT);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_ai_service_by_id(&mut transaction, ai_service_id)
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id],
            &[user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn list_200() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let ai_service = ai_service_create(router.clone(), session_id).await;
        let ai_service_id = ai_service.id;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri("/api/v1/ai-services")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = BodyExt::collect(response.into_body())
            .await
            .unwrap()
            .to_bytes()
            .to_vec();
        let body: Vec<AiService> = serde_json::from_slice(&body).unwrap();

        assert!(!body.is_empty());

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_ai_service_by_id(&mut transaction, ai_service_id)
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id],
            &[user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn list_401() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let ai_service = ai_service_create(router.clone(), session_id).await;
        let ai_service_id = ai_service.id;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri("/api/v1/ai-services")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_ai_service_by_id(&mut transaction, ai_service_id)
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id],
            &[user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn list_403_deleted_user() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let ai_service = ai_service_create(router.clone(), session_id).await;
        let ai_service_id = ai_service.id;

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(app.context.clone(), &mut transaction, &[], &[user_id])
            .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri("/api/v1/ai-services")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_ai_service_by_id(&mut transaction, ai_service_id)
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(app.context.clone(), &mut transaction, &[company_id], &[])
            .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn logs_200() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let ai_service = ai_service_create(router.clone(), session_id).await;
        let ai_service_id = ai_service.id;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("/api/v1/ai-services/{ai_service_id}/logs"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = BodyExt::collect(response.into_body())
            .await
            .unwrap()
            .to_bytes()
            .to_vec();
        let body = String::from_utf8(body).unwrap();

        assert_eq!(body, "");

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_ai_service_by_id(&mut transaction, ai_service_id)
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id],
            &[user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn logs_401() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let ai_service = ai_service_create(router.clone(), session_id).await;
        let ai_service_id = ai_service.id;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("/api/v1/ai-services/{ai_service_id}/logs"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_ai_service_by_id(&mut transaction, ai_service_id)
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id],
            &[user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn logs_403_deleted_user() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let ai_service = ai_service_create(router.clone(), session_id).await;
        let ai_service_id = ai_service.id;

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(app.context.clone(), &mut transaction, &[], &[user_id])
            .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("/api/v1/ai-services/{ai_service_id}/logs"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_ai_service_by_id(&mut transaction, ai_service_id)
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(app.context.clone(), &mut transaction, &[company_id], &[])
            .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn logs_404() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let ai_service_id = "33847746-0030-4964-a496-f75d04499160";

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("/api/v1/ai-services/{ai_service_id}/logs"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id],
            &[user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn priority_200() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let ai_service = ai_service_create(router.clone(), session_id).await;
        let ai_service_id = ai_service.id;

        let priority = 1;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::PUT)
                    .uri(format!("/api/v1/ai-services/{ai_service_id}/priority"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "priority": &priority,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = BodyExt::collect(response.into_body())
            .await
            .unwrap()
            .to_bytes()
            .to_vec();
        let body: AiService = serde_json::from_slice(&body).unwrap();

        assert!(!body.is_enabled);
        assert_eq!(body.status, AiServiceStatus::Configuration);
        assert_eq!(body.priority, priority);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_ai_service_by_id(&mut transaction, ai_service_id)
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id],
            &[user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn priority_401() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let ai_service = ai_service_create(router.clone(), session_id).await;
        let ai_service_id = ai_service.id;

        let priority = 1;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::PUT)
                    .uri(format!("/api/v1/ai-services/{ai_service_id}/priority"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "priority": &priority,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_ai_service_by_id(&mut transaction, ai_service_id)
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id],
            &[user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn priority_403_deleted_user() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let ai_service = ai_service_create(router.clone(), session_id).await;
        let ai_service_id = ai_service.id;

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(app.context.clone(), &mut transaction, &[], &[user_id])
            .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;

        let priority = 1;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::PUT)
                    .uri(format!("/api/v1/ai-services/{ai_service_id}/priority"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "priority": &priority,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_ai_service_by_id(&mut transaction, ai_service_id)
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(app.context.clone(), &mut transaction, &[company_id], &[])
            .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn priority_404() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let ai_service_id = "33847746-0030-4964-a496-f75d04499160";

        let priority = 1;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::PUT)
                    .uri(format!("/api/v1/ai-services/{ai_service_id}/priority"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "priority": &priority,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id],
            &[user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn read_200() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let ai_service = ai_service_create(router.clone(), session_id).await;
        let ai_service_id = ai_service.id;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("/api/v1/ai-services/{ai_service_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = BodyExt::collect(response.into_body())
            .await
            .unwrap()
            .to_bytes()
            .to_vec();
        let body: AiService = serde_json::from_slice(&body).unwrap();

        assert!(!body.is_enabled);
        assert_eq!(body.status, AiServiceStatus::Configuration);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_ai_service_by_id(&mut transaction, ai_service_id)
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id],
            &[user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn read_401() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let ai_service = ai_service_create(router.clone(), session_id).await;
        let ai_service_id = ai_service.id;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("/api/v1/ai-services/{ai_service_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_ai_service_by_id(&mut transaction, ai_service_id)
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id],
            &[user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn read_403_deleted_user() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let ai_service = ai_service_create(router.clone(), session_id).await;
        let ai_service_id = ai_service.id;

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(app.context.clone(), &mut transaction, &[], &[user_id])
            .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("/api/v1/ai-services/{ai_service_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_ai_service_by_id(&mut transaction, ai_service_id)
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(app.context.clone(), &mut transaction, &[company_id], &[])
            .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn read_404() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let ai_service_id = "33847746-0030-4964-a496-f75d04499160";

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("/api/v1/ai-services/{ai_service_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id],
            &[user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn update_200() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let ai_service = ai_service_create(router.clone(), session_id).await;
        let ai_service_id = ai_service.id;

        let body = multipart::tests::file_data(
            "application/octet-stream",
            "test.py",
            "data/test/test.py",
            true,
        )
        .unwrap();

        let value = format!(
            "{}; boundary={}",
            mime::MULTIPART_FORM_DATA,
            multipart::tests::BOUNDARY
        );

        let request = Request::builder()
            .method(http::Method::PUT)
            .uri(format!("/api/v1/ai-services/{ai_service_id}"))
            .header(http::header::CONTENT_TYPE, value)
            .header("X-Auth-Token".to_string(), session_id.to_string())
            .body(body)
            .unwrap();

        let response = router.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = BodyExt::collect(response.into_body())
            .await
            .unwrap()
            .to_bytes()
            .to_vec();
        let body: AiService = serde_json::from_slice(&body).unwrap();

        assert!(!body.is_enabled);
        assert_eq!(body.status, AiServiceStatus::Configuration);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_ai_service_by_id(&mut transaction, ai_service_id)
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id],
            &[user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn update_400() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let ai_service = ai_service_create(router.clone(), session_id).await;
        let ai_service_id = ai_service.id;

        let request = Request::builder()
            .method(http::Method::PUT)
            .uri(format!("/api/v1/ai-services/{ai_service_id}"))
            .header(
                http::header::CONTENT_TYPE,
                mime::MULTIPART_FORM_DATA.as_ref(),
            )
            .header("X-Auth-Token".to_string(), session_id.to_string())
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_ai_service_by_id(&mut transaction, ai_service_id)
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id],
            &[user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn update_401() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let ai_service = ai_service_create(router.clone(), session_id).await;
        let ai_service_id = ai_service.id;

        let body = multipart::tests::file_data(
            "application/octet-stream",
            "test.py",
            "data/test/test.py",
            true,
        )
        .unwrap();

        let value = format!(
            "{}; boundary={}",
            mime::MULTIPART_FORM_DATA,
            multipart::tests::BOUNDARY
        );

        let request = Request::builder()
            .method(http::Method::PUT)
            .uri(format!("/api/v1/ai-services/{ai_service_id}"))
            .header(http::header::CONTENT_TYPE, value)
            .body(body)
            .unwrap();

        let response = router.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_ai_service_by_id(&mut transaction, ai_service_id)
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id],
            &[user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn update_403_deleted_user() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let ai_service = ai_service_create(router.clone(), session_id).await;
        let ai_service_id = ai_service.id;

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(app.context.clone(), &mut transaction, &[], &[user_id])
            .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;

        let body = multipart::tests::file_data(
            "application/octet-stream",
            "test.py",
            "data/test/test.py",
            true,
        )
        .unwrap();

        let value = format!(
            "{}; boundary={}",
            mime::MULTIPART_FORM_DATA,
            multipart::tests::BOUNDARY
        );

        let request = Request::builder()
            .method(http::Method::PUT)
            .uri(format!("/api/v1/ai-services/{ai_service_id}"))
            .header(http::header::CONTENT_TYPE, value)
            .header("X-Auth-Token".to_string(), session_id.to_string())
            .body(body)
            .unwrap();

        let response = router.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_ai_service_by_id(&mut transaction, ai_service_id)
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(app.context.clone(), &mut transaction, &[company_id], &[])
            .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn update_404() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let ai_service_id = "33847746-0030-4964-a496-f75d04499160";

        let body = multipart::tests::file_data(
            "application/octet-stream",
            "test.py",
            "data/test/test.py",
            true,
        )
        .unwrap();

        let value = format!(
            "{}; boundary={}",
            mime::MULTIPART_FORM_DATA,
            multipart::tests::BOUNDARY
        );

        let request = Request::builder()
            .method(http::Method::PUT)
            .uri(format!("/api/v1/ai-services/{ai_service_id}"))
            .header(http::header::CONTENT_TYPE, value)
            .header("X-Auth-Token".to_string(), session_id.to_string())
            .body(body)
            .unwrap();

        let response = router.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id],
            &[user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }
}
