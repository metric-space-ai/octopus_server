use crate::{
    ai,
    context::Context,
    entity::{AiServiceStatus, ROLE_COMPANY_ADMIN_USER},
    error::AppError,
    get_pwd, parser, process_manager,
    session::{ensure_secured, require_authenticated_session, ExtractedSession},
    SERVICES_DIR,
};
use axum::{
    extract::{Multipart, Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::{fs::read_to_string, path, sync::Arc};
use tracing::debug;
use utoipa::ToSchema;
use uuid::Uuid;
use validator::Validate;

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
pub struct AiServiceConfigurationPut {
    pub device_map: serde_json::Value,
}

#[derive(Debug, Deserialize, ToSchema, Validate)]
pub struct AiServicePriorityPut {
    #[validate(range(min = 0, max = 31))]
    pub priority: i32,
}

#[axum_macros::debug_handler]
#[utoipa::path(
    post,
    path = "/api/v1/ai-services",
    responses(
        (status = 201, description = "AI Service created.", body = AiService),
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
        let original_file_name = (field.file_name().ok_or(AppError::File)?).to_string();
        let content_type = (field.content_type().ok_or(AppError::File)?).to_string();

        if content_type == "application/octet-stream" || content_type == "text/plain" {
            let data = field.bytes().await?.clone().to_vec();

            let port = context.octopus_database.get_ai_services_max_port().await?;

            let port = port.max.unwrap_or(9999) + 1;
            let original_function_body = String::from_utf8(data)?;

            let ai_service = context
                .octopus_database
                .insert_ai_service(&original_file_name, &original_function_body, port)
                .await?;

            let ai_service = parser::ai_service_malicious_code_check(ai_service, context).await?;

            return Ok((StatusCode::CREATED, Json(ai_service)).into_response());
        }
    }

    Err(AppError::BadRequest)
}

#[axum_macros::debug_handler]
#[utoipa::path(
    put,
    path = "/api/v1/ai-services/:id/configuration",
    request_body = AiServiceConfigurationPut,
    responses(
        (status = 200, description = "AI Service configured.", body = AiService),
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
    ensure_secured(context.clone(), extracted_session, ROLE_COMPANY_ADMIN_USER).await?;
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

    let ai_service = context
        .octopus_database
        .update_ai_service_device_map(
            ai_service.id,
            input.device_map,
            AiServiceStatus::ParsingStarted,
        )
        .await?;

    let cloned_context = context.clone();
    let cloned_ai_service = ai_service.clone();
    tokio::spawn(async move {
        let ai_service = parser::ai_service_parsing(cloned_ai_service, cloned_context).await;

        if let Err(e) = ai_service {
            debug!("Error: {:?}", e);
        }
    });

    Ok((StatusCode::OK, Json(ai_service)).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    delete,
    path = "/api/v1/ai-services/:id",
    responses(
        (status = 204, description = "AI Service deleted."),
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
    ensure_secured(context.clone(), extracted_session, ROLE_COMPANY_ADMIN_USER).await?;

    let ai_service = context
        .octopus_database
        .try_get_ai_service_by_id(id)
        .await?
        .ok_or(AppError::NotFound)?;

    let ai_service =
        process_manager::stop_and_remove_ai_service(ai_service, context.clone()).await?;

    context
        .octopus_database
        .try_delete_ai_service_by_id(ai_service.id)
        .await?
        .ok_or(AppError::NotFound)?;

    Ok((StatusCode::NO_CONTENT, ()).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    put,
    path = "/api/v1/ai-services/:id/installation",
    responses(
        (status = 200, description = "AI Service configured.", body = AiService),
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
    ensure_secured(context.clone(), extracted_session, ROLE_COMPANY_ADMIN_USER).await?;

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
            process_manager::install_and_run_ai_service(cloned_ai_service, cloned_context).await;

        if let Err(e) = ai_service {
            debug!("Error: {:?}", e);
        }
    });

    Ok((StatusCode::OK, Json(ai_service)).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    get,
    path = "/api/v1/ai-services/:id/logs",
    responses(
        (status = 200, description = "AI Service logs.", body = String),
        (status = 401, description = "Unauthorized request.", body = ResponseError),
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
) -> Result<impl IntoResponse, AppError> {
    ensure_secured(context.clone(), extracted_session, ROLE_COMPANY_ADMIN_USER).await?;

    let ai_service = context
        .octopus_database
        .try_get_ai_service_by_id(id)
        .await?
        .ok_or(AppError::NotFound)?;

    let pwd = get_pwd().await?;

    let path = format!(
        "{pwd}/{SERVICES_DIR}/{}/{}.log",
        ai_service.id, ai_service.id
    );

    let file_exists = path::Path::new(&path).is_file();

    let logs = if file_exists {
        read_to_string(path)?
    } else {
        String::new()
    };

    Ok((StatusCode::OK, logs).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    get,
    path = "/api/v1/ai-services",
    responses(
        (status = 200, description = "List of AI Services.", body = [AiService]),
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

    let ai_services = context.octopus_database.get_ai_services().await?;

    Ok((StatusCode::OK, Json(ai_services)).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    post,
    path = "/api/v1/ai-services/:id",
    request_body = AiServiceOperationPost,
    responses(
        (status = 201, description = "AI Service operation scheduled.", body = AiServiceOperationResponse),
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
    ensure_secured(context.clone(), extracted_session, ROLE_COMPANY_ADMIN_USER).await?;
    input.validate()?;

    let ai_service = context
        .octopus_database
        .try_get_ai_service_by_id(id)
        .await?
        .ok_or(AppError::NotFound)?;

    match input.operation {
        AiServiceOperation::Disable => {
            if !(ai_service.status == AiServiceStatus::Running
                || ai_service.status == AiServiceStatus::Setup)
            {
                return Err(AppError::Conflict);
            }
        }
        AiServiceOperation::Enable => {
            if ai_service.status != AiServiceStatus::Stopped {
                return Err(AppError::Conflict);
            }
        }
        AiServiceOperation::HealthCheck => {
            if ai_service.status != AiServiceStatus::Running {
                return Err(AppError::Conflict);
            }
        }
        AiServiceOperation::Setup => {
            if ai_service.status != AiServiceStatus::Running {
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
                    process_manager::stop_ai_service(cloned_ai_service, cloned_context).await;

                if let Ok(ai_service_ok) = ai_service {
                    ai_service = context
                        .octopus_database
                        .update_ai_service_is_enabled_and_status(
                            ai_service_ok.id,
                            false,
                            100,
                            AiServiceStatus::Stopped,
                        )
                        .await;
                }

                ai_service
            }
            AiServiceOperation::Enable => {
                process_manager::try_restart_ai_service(cloned_ai_service, cloned_context).await
            }
            AiServiceOperation::HealthCheck => {
                ai::service::service_health_check(
                    cloned_ai_service.id,
                    cloned_context,
                    cloned_ai_service.port,
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
            debug!("Error: {:?}", e);
        }
    });

    let execution_time = match input.operation {
        AiServiceOperation::Disable => 1,
        AiServiceOperation::Enable => 1,
        AiServiceOperation::HealthCheck => ai_service.health_check_execution_time,
        AiServiceOperation::Setup => ai_service.setup_execution_time,
    };

    let estimated_operation_end_at = Utc::now() + Duration::seconds(i64::from(execution_time) + 1);

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
    ensure_secured(context.clone(), extracted_session, ROLE_COMPANY_ADMIN_USER).await?;
    input.validate()?;

    let ai_service = context
        .octopus_database
        .try_get_ai_service_by_id(id)
        .await?
        .ok_or(AppError::NotFound)?;

    let ai_service = context
        .octopus_database
        .update_ai_service_priority(ai_service.id, input.priority)
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
    require_authenticated_session(extracted_session).await?;

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
    ensure_secured(context.clone(), extracted_session, ROLE_COMPANY_ADMIN_USER).await?;

    context
        .octopus_database
        .try_get_ai_service_id_by_id(id)
        .await?
        .ok_or(AppError::NotFound)?;

    while let Some(field) = multipart.next_field().await? {
        let original_file_name = (field.file_name().ok_or(AppError::File)?).to_string();
        let content_type = (field.content_type().ok_or(AppError::File)?).to_string();

        if content_type == "application/octet-stream" || content_type == "text/plain" {
            let data = field.bytes().await?.clone().to_vec();

            let original_function_body = String::from_utf8(data)?;

            let ai_service = context
                .octopus_database
                .update_ai_service(id, false, &original_file_name, &original_function_body)
                .await?;

            let ai_service = parser::ai_service_malicious_code_check(ai_service, context).await?;

            return Ok((StatusCode::OK, Json(ai_service)).into_response());
        }
    }

    Err(AppError::BadRequest)
}
/*
#[cfg(test)]
mod tests {
    use crate::{app, entity::AiService, entity::User, session::SessionResponse, Args};
    use axum::{
        body::Body,
        http::{self, Request, StatusCode},
    };
    use fake::{
        faker::{
            internet::en::SafeEmail,
            lorem::en::{Paragraph, Word},
            name::en::Name,
        },
        Fake,
    };
    use tower::ServiceExt;

    #[tokio::test]
    async fn create_201() {
        let args = Args {
            azure_openai_api_key: None,
            azure_openai_deployment_id: None,
            azure_openai_enabled: Some(true),
            database_url: Some(String::from(
                "postgres://admin:admin@db/octopus_server_test",
            )),
            openai_api_key: None,
            port: None,
        };
        let app = app::get_app(args).await.unwrap();
        let router = app.router;
        let second_router = router.clone();
        let third_router = router.clone();

        let company_name = Paragraph(1..2).fake::<String>();
        let email = format!(
            "{}{}{}",
            Word().fake::<String>(),
            Word().fake::<String>(),
            SafeEmail().fake::<String>()
        );
        let password = "password123".to_string();

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/setup")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "company_name": &company_name,
                            "email": &email,
                            "password": &password,
                            "repeat_password": &password,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: User = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.email, email);

        let company_id = body.company_id;
        let user_id = body.id;

        let response = second_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/auth")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "email": &email,
                            "password": &password,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: SessionResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);

        let session_id = body.id;

        let has_file_response = false;
        let is_available = true;
        let is_enabled = true;
        let name = format!(
            "function-foo-sync{}{}",
            Word().fake::<String>(),
            Word().fake::<String>()
        );

        let response = third_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/ai-services")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "base_function_url": "http://127.0.0.1:5000/v1/function-foo-sync",
                            "description": "Synchronous communication test function",
                            "device_map": {
                                "max_memory": {"0": "10GiB", "1": "10GiB", "cpu": "30GiB"}
                            },
                            "has_file_response": &has_file_response,
                            "health_check_url": "http://127.0.0.1:5000/v1/health-check",
                            "is_available": &is_available,
                            "is_enabled": &is_enabled,
                            "name": &name,
                            "parameters": {
                                "type": "object",
                                "properties": {
                                    "value1": {
                                        "type": "string",
                                        "description": "First value"
                                    },
                                    "value2": { "type": "string", "enum": ["abc", "def"], "description": "Second value" }
                                },
                                "required": ["value1", "value2"]
                            },
                            "setup_url": "http://127.0.0.1:5000/v1/setup"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: AiService = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.is_enabled, is_enabled);
        assert_eq!(body.name, name);

        let ai_service_id = body.id;

        app.context
            .octopus_database
            .try_delete_user_by_id(user_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_company_by_id(company_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_ai_service_by_id(ai_service_id)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn create_403() {
        let args = Args {
            azure_openai_api_key: None,
            azure_openai_deployment_id: None,
            azure_openai_enabled: Some(true),
            database_url: Some(String::from(
                "postgres://admin:admin@db/octopus_server_test",
            )),
            openai_api_key: None,
            port: None,
        };
        let app = app::get_app(args).await.unwrap();
        let router = app.router;
        let second_router = router.clone();
        let third_router = router.clone();
        let fourth_router = router.clone();

        let company_name = Paragraph(1..2).fake::<String>();
        let email = format!(
            "{}{}{}",
            Word().fake::<String>(),
            Word().fake::<String>(),
            SafeEmail().fake::<String>()
        );
        let password = "password123";

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/setup")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "company_name": &company_name,
                            "email": &email,
                            "password": &password,
                            "repeat_password": &password,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: User = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.email, email);

        let company_id = body.company_id;
        let user_id = body.id;

        let email = format!(
            "{}{}{}",
            Word().fake::<String>(),
            Word().fake::<String>(),
            SafeEmail().fake::<String>()
        );
        let job_title = Paragraph(1..2).fake::<String>();
        let name = Name().fake::<String>();
        let password = "password123";

        let response = second_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri(format!("/api/v1/auth/register/{company_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "email": &email,
                            "job_title": &job_title,
                            "name": &name,
                            "password": &password,
                            "repeat_password": &password,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: User = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.email, email);

        let user2_id = body.id;

        let response = third_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/auth")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "email": &email,
                            "password": &password,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: SessionResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user2_id);

        let session_id = body.id;

        let has_file_response = false;
        let is_available = true;
        let is_enabled = true;
        let name = format!(
            "function-foo-sync{}{}",
            Word().fake::<String>(),
            Word().fake::<String>()
        );

        let response = fourth_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/ai-services")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "base_function_url": "http://127.0.0.1:5000/v1/function-foo-sync",
                            "description": "Synchronous communication test function",
                            "device_map": {
                                "max_memory": {"0": "10GiB", "1": "10GiB", "cpu": "30GiB"}
                            },
                            "has_file_response": &has_file_response,
                            "health_check_url": "http://127.0.0.1:5000/v1/health-check",
                            "is_available": &is_available,
                            "is_enabled": &is_enabled,
                            "name": &name,
                            "parameters": {
                                "type": "object",
                                "properties": {
                                    "value1": {
                                        "type": "string",
                                        "description": "First value"
                                    },
                                    "value2": { "type": "string", "enum": ["abc", "def"], "description": "Second value" }
                                },
                                "required": ["value1", "value2"]
                            },
                            "setup_url": "http://127.0.0.1:5000/v1/setup"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        app.context
            .octopus_database
            .try_delete_user_by_id(user_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_user_by_id(user2_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_company_by_id(company_id)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn delete_204() {
        let args = Args {
            azure_openai_api_key: None,
            azure_openai_deployment_id: None,
            azure_openai_enabled: Some(true),
            database_url: Some(String::from(
                "postgres://admin:admin@db/octopus_server_test",
            )),
            openai_api_key: None,
            port: None,
        };
        let app = app::get_app(args).await.unwrap();
        let router = app.router;
        let second_router = router.clone();
        let third_router = router.clone();
        let fourth_router = router.clone();

        let company_name = Paragraph(1..2).fake::<String>();
        let email = format!(
            "{}{}{}",
            Word().fake::<String>(),
            Word().fake::<String>(),
            SafeEmail().fake::<String>()
        );
        let password = "password123";

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/setup")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "company_name": &company_name,
                            "email": &email,
                            "password": &password,
                            "repeat_password": &password,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: User = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.email, email);

        let company_id = body.company_id;
        let user_id = body.id;

        let response = second_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/auth")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "email": &email,
                            "password": &password,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: SessionResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);

        let session_id = body.id;

        let has_file_response = false;
        let is_available = true;
        let is_enabled = true;
        let name = format!(
            "function-foo-sync{}{}",
            Word().fake::<String>(),
            Word().fake::<String>()
        );

        let response = third_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/ai-services")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "base_function_url": "http://127.0.0.1:5000/v1/function-foo-sync",
                            "description": "Synchronous communication test function",
                            "device_map": {
                                "max_memory": {"0": "10GiB", "1": "10GiB", "cpu": "30GiB"}
                            },
                            "has_file_response": &has_file_response,
                            "health_check_url": "http://127.0.0.1:5000/v1/health-check",
                            "is_available": &is_available,
                            "is_enabled": &is_enabled,
                            "name": &name,
                            "parameters": {
                                "type": "object",
                                "properties": {
                                    "value1": {
                                        "type": "string",
                                        "description": "First value"
                                    },
                                    "value2": { "type": "string", "enum": ["abc", "def"], "description": "Second value" }
                                },
                                "required": ["value1", "value2"]
                            },
                            "setup_url": "http://127.0.0.1:5000/v1/setup"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: AiService = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.is_enabled, is_enabled);
        assert_eq!(body.name, name);

        let ai_service_id = body.id;

        let response = fourth_router
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

        app.context
            .octopus_database
            .try_delete_user_by_id(user_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_company_by_id(company_id)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn delete_403() {
        let args = Args {
            azure_openai_api_key: None,
            azure_openai_deployment_id: None,
            azure_openai_enabled: Some(true),
            database_url: Some(String::from(
                "postgres://admin:admin@db/octopus_server_test",
            )),
            openai_api_key: None,
            port: None,
        };
        let app = app::get_app(args).await.unwrap();
        let router = app.router;
        let second_router = router.clone();
        let third_router = router.clone();
        let fourth_router = router.clone();
        let fifth_router = router.clone();
        let sixth_router = router.clone();

        let company_name = Paragraph(1..2).fake::<String>();
        let email = format!(
            "{}{}{}",
            Word().fake::<String>(),
            Word().fake::<String>(),
            SafeEmail().fake::<String>()
        );
        let password = "password123";

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/setup")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "company_name": &company_name,
                            "email": &email,
                            "password": &password,
                            "repeat_password": &password,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: User = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.email, email);

        let company_id = body.company_id;

        let user_id = body.id;

        let response = second_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/auth")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "email": &email,
                            "password": &password,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: SessionResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);

        let session_id = body.id;

        let has_file_response = false;
        let is_available = true;
        let is_enabled = true;
        let name = format!(
            "function-foo-sync{}{}",
            Word().fake::<String>(),
            Word().fake::<String>()
        );

        let response = third_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/ai-services")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "base_function_url": "http://127.0.0.1:5000/v1/function-foo-sync",
                            "description": "Synchronous communication test function",
                            "device_map": {
                                "max_memory": {"0": "10GiB", "1": "10GiB", "cpu": "30GiB"}
                            },
                            "has_file_response": &has_file_response,
                            "health_check_url": "http://127.0.0.1:5000/v1/health-check",
                            "is_available": &is_available,
                            "is_enabled": &is_enabled,
                            "name": &name,
                            "parameters": {
                                "type": "object",
                                "properties": {
                                    "value1": {
                                        "type": "string",
                                        "description": "First value"
                                    },
                                    "value2": { "type": "string", "enum": ["abc", "def"], "description": "Second value" }
                                },
                                "required": ["value1", "value2"]
                            },
                            "setup_url": "http://127.0.0.1:5000/v1/setup"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: AiService = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.is_enabled, is_enabled);
        assert_eq!(body.name, name);

        let ai_service_id = body.id;

        let email = format!(
            "{}{}{}",
            Word().fake::<String>(),
            Word().fake::<String>(),
            SafeEmail().fake::<String>()
        );
        let job_title = Paragraph(1..2).fake::<String>();
        let name = Name().fake::<String>();
        let password = "password123";

        let response = fourth_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri(format!("/api/v1/auth/register/{company_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "email": &email,
                            "job_title": &job_title,
                            "name": &name,
                            "password": &password,
                            "repeat_password": &password,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: User = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.email, email);

        let company2_id = body.company_id;
        let user2_id = body.id;

        let response = fifth_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/auth")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "email": &email,
                            "password": &password,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: SessionResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user2_id);

        let session_id = body.id;

        let response = sixth_router
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

        app.context
            .octopus_database
            .try_delete_user_by_id(user_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_user_by_id(user2_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_company_by_id(company_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_company_by_id(company2_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_ai_service_by_id(ai_service_id)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn delete_404() {
        let args = Args {
            azure_openai_api_key: None,
            azure_openai_deployment_id: None,
            azure_openai_enabled: Some(true),
            database_url: Some(String::from(
                "postgres://admin:admin@db/octopus_server_test",
            )),
            openai_api_key: None,
            port: None,
        };
        let app = app::get_app(args).await.unwrap();
        let router = app.router;
        let second_router = router.clone();
        let third_router = router.clone();

        let company_name = Paragraph(1..2).fake::<String>();
        let email = format!(
            "{}{}{}",
            Word().fake::<String>(),
            Word().fake::<String>(),
            SafeEmail().fake::<String>()
        );
        let password = "password123";

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/setup")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "company_name": &company_name,
                            "email": &email,
                            "password": &password,
                            "repeat_password": &password,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: User = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.email, email);

        let company_id = body.company_id;
        let user_id = body.id;

        let response = second_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/auth")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "email": &email,
                            "password": &password,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: SessionResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);

        let session_id = body.id;

        let ai_service_id = "33847746-0030-4964-a496-f75d04499160";

        let response = third_router
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

        app.context
            .octopus_database
            .try_delete_user_by_id(user_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_company_by_id(company_id)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn list_200() {
        let args = Args {
            azure_openai_api_key: None,
            azure_openai_deployment_id: None,
            azure_openai_enabled: Some(true),
            database_url: Some(String::from(
                "postgres://admin:admin@db/octopus_server_test",
            )),
            openai_api_key: None,
            port: None,
        };
        let app = app::get_app(args).await.unwrap();
        let router = app.router;
        let second_router = router.clone();
        let third_router = router.clone();
        let fourth_router = router.clone();

        let company_name = Paragraph(1..2).fake::<String>();
        let email = format!(
            "{}{}{}",
            Word().fake::<String>(),
            Word().fake::<String>(),
            SafeEmail().fake::<String>()
        );
        let password = "password123";

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/setup")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "company_name": &company_name,
                            "email": &email,
                            "password": &password,
                            "repeat_password": &password,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: User = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.email, email);

        let company_id = body.company_id;
        let user_id = body.id;

        let response = second_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/auth")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "email": &email,
                            "password": &password,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: SessionResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);

        let session_id = body.id;

        let has_file_response = false;
        let is_available = true;
        let is_enabled = true;
        let name = format!(
            "function-foo-sync{}{}",
            Word().fake::<String>(),
            Word().fake::<String>()
        );

        let response = third_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/ai-services")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "base_function_url": "http://127.0.0.1:5000/v1/function-foo-sync",
                            "description": "Synchronous communication test function",
                            "device_map": {
                                "max_memory": {"0": "10GiB", "1": "10GiB", "cpu": "30GiB"}
                            },
                            "has_file_response": &has_file_response,
                            "health_check_url": "http://127.0.0.1:5000/v1/health-check",
                            "is_available": &is_available,
                            "is_enabled": &is_enabled,
                            "name": &name,
                            "parameters": {
                                "type": "object",
                                "properties": {
                                    "value1": {
                                        "type": "string",
                                        "description": "First value"
                                    },
                                    "value2": { "type": "string", "enum": ["abc", "def"], "description": "Second value" }
                                },
                                "required": ["value1", "value2"]
                            },
                            "setup_url": "http://127.0.0.1:5000/v1/setup"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: AiService = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.is_enabled, is_enabled);
        assert_eq!(body.name, name);

        let ai_service_id = body.id;

        let response = fourth_router
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

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: Vec<AiService> = serde_json::from_slice(&body).unwrap();

        assert!(!body.is_empty());

        app.context
            .octopus_database
            .try_delete_user_by_id(user_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_company_by_id(company_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_ai_service_by_id(ai_service_id)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn list_401() {
        let args = Args {
            azure_openai_api_key: None,
            azure_openai_deployment_id: None,
            azure_openai_enabled: Some(true),
            database_url: Some(String::from(
                "postgres://admin:admin@db/octopus_server_test",
            )),
            openai_api_key: None,
            port: None,
        };
        let app = app::get_app(args).await.unwrap();
        let router = app.router;
        let second_router = router.clone();
        let third_router = router.clone();
        let fourth_router = router.clone();

        let company_name = Paragraph(1..2).fake::<String>();
        let email = format!(
            "{}{}{}",
            Word().fake::<String>(),
            Word().fake::<String>(),
            SafeEmail().fake::<String>()
        );
        let password = "password123";

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/setup")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "company_name": &company_name,
                            "email": &email,
                            "password": &password,
                            "repeat_password": &password,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: User = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.email, email);

        let company_id = body.company_id;
        let user_id = body.id;

        let response = second_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/auth")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "email": &email,
                            "password": &password,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: SessionResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);

        let session_id = body.id;

        let has_file_response = false;
        let is_available = true;
        let is_enabled = true;
        let name = format!(
            "function-foo-sync{}{}",
            Word().fake::<String>(),
            Word().fake::<String>()
        );

        let response = third_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/ai-services")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "base_function_url": "http://127.0.0.1:5000/v1/function-foo-sync",
                            "description": "Synchronous communication test function",
                            "device_map": {
                                "max_memory": {"0": "10GiB", "1": "10GiB", "cpu": "30GiB"}
                            },
                            "has_file_response": &has_file_response,
                            "health_check_url": "http://127.0.0.1:5000/v1/health-check",
                            "is_available": &is_available,
                            "is_enabled": &is_enabled,
                            "name": &name,
                            "parameters": {
                                "type": "object",
                                "properties": {
                                    "value1": {
                                        "type": "string",
                                        "description": "First value"
                                    },
                                    "value2": { "type": "string", "enum": ["abc", "def"], "description": "Second value" }
                                },
                                "required": ["value1", "value2"]
                            },
                            "setup_url": "http://127.0.0.1:5000/v1/setup"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: AiService = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.is_enabled, is_enabled);
        assert_eq!(body.name, name);

        let ai_service_id = body.id;

        let response = fourth_router
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

        app.context
            .octopus_database
            .try_delete_user_by_id(user_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_company_by_id(company_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_ai_service_by_id(ai_service_id)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn read_200() {
        let args = Args {
            azure_openai_api_key: None,
            azure_openai_deployment_id: None,
            azure_openai_enabled: Some(true),
            database_url: Some(String::from(
                "postgres://admin:admin@db/octopus_server_test",
            )),
            openai_api_key: None,
            port: None,
        };
        let app = app::get_app(args).await.unwrap();
        let router = app.router;
        let second_router = router.clone();
        let third_router = router.clone();
        let fourth_router = router.clone();

        let company_name = Paragraph(1..2).fake::<String>();
        let email = format!(
            "{}{}{}",
            Word().fake::<String>(),
            Word().fake::<String>(),
            SafeEmail().fake::<String>()
        );
        let password = "password123";

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/setup")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "company_name": &company_name,
                            "email": &email,
                            "password": &password,
                            "repeat_password": &password,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: User = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.email, email);

        let company_id = body.company_id;
        let user_id = body.id;

        let response = second_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/auth")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "email": &email,
                            "password": &password,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: SessionResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);

        let session_id = body.id;

        let has_file_response = false;
        let is_available = true;
        let is_enabled = true;
        let name = format!(
            "function-foo-sync{}{}",
            Word().fake::<String>(),
            Word().fake::<String>()
        );

        let response = third_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/ai-services")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "base_function_url": "http://127.0.0.1:5000/v1/function-foo-sync",
                            "description": "Synchronous communication test function",
                            "device_map": {
                                "max_memory": {"0": "10GiB", "1": "10GiB", "cpu": "30GiB"}
                            },
                            "has_file_response": &has_file_response,
                            "health_check_url": "http://127.0.0.1:5000/v1/health-check",
                            "is_available": &is_available,
                            "is_enabled": &is_enabled,
                            "name": &name,
                            "parameters": {
                                "type": "object",
                                "properties": {
                                    "value1": {
                                        "type": "string",
                                        "description": "First value"
                                    },
                                    "value2": { "type": "string", "enum": ["abc", "def"], "description": "Second value" }
                                },
                                "required": ["value1", "value2"]
                            },
                            "setup_url": "http://127.0.0.1:5000/v1/setup"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: AiService = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.is_enabled, is_enabled);
        assert_eq!(body.name, name);

        let ai_service_id = body.id;

        let response = fourth_router
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

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: AiService = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.is_enabled, is_enabled);
        assert_eq!(body.name, name);

        app.context
            .octopus_database
            .try_delete_user_by_id(user_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_company_by_id(company_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_ai_service_by_id(ai_service_id)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn read_401() {
        let args = Args {
            azure_openai_api_key: None,
            azure_openai_deployment_id: None,
            azure_openai_enabled: Some(true),
            database_url: Some(String::from(
                "postgres://admin:admin@db/octopus_server_test",
            )),
            openai_api_key: None,
            port: None,
        };
        let app = app::get_app(args).await.unwrap();
        let router = app.router;
        let second_router = router.clone();
        let third_router = router.clone();
        let fourth_router = router.clone();

        let company_name = Paragraph(1..2).fake::<String>();
        let email = format!(
            "{}{}{}",
            Word().fake::<String>(),
            Word().fake::<String>(),
            SafeEmail().fake::<String>()
        );
        let password = "password123";

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/setup")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "company_name": &company_name,
                            "email": &email,
                            "password": &password,
                            "repeat_password": &password,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: User = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.email, email);

        let company_id = body.company_id;
        let user_id = body.id;

        let response = second_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/auth")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "email": &email,
                            "password": &password,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: SessionResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);

        let session_id = body.id;

        let has_file_response = false;
        let is_available = true;
        let is_enabled = true;
        let name = format!(
            "function-foo-sync{}{}",
            Word().fake::<String>(),
            Word().fake::<String>()
        );

        let response = third_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/ai-services")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "base_function_url": "http://127.0.0.1:5000/v1/function-foo-sync",
                            "description": "Synchronous communication test function",
                            "device_map": {
                                "max_memory": {"0": "10GiB", "1": "10GiB", "cpu": "30GiB"}
                            },
                            "has_file_response": &has_file_response,
                            "health_check_url": "http://127.0.0.1:5000/v1/health-check",
                            "is_available": &is_available,
                            "is_enabled": &is_enabled,
                            "name": &name,
                            "parameters": {
                                "type": "object",
                                "properties": {
                                    "value1": {
                                        "type": "string",
                                        "description": "First value"
                                    },
                                    "value2": { "type": "string", "enum": ["abc", "def"], "description": "Second value" }
                                },
                                "required": ["value1", "value2"]
                            },
                            "setup_url": "http://127.0.0.1:5000/v1/setup"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: AiService = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.is_enabled, is_enabled);
        assert_eq!(body.name, name);

        let ai_service_id = body.id;

        let response = fourth_router
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

        app.context
            .octopus_database
            .try_delete_user_by_id(user_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_company_by_id(company_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_ai_service_by_id(ai_service_id)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn read_404() {
        let args = Args {
            azure_openai_api_key: None,
            azure_openai_deployment_id: None,
            azure_openai_enabled: Some(true),
            database_url: Some(String::from(
                "postgres://admin:admin@db/octopus_server_test",
            )),
            openai_api_key: None,
            port: None,
        };
        let app = app::get_app(args).await.unwrap();
        let router = app.router;
        let second_router = router.clone();
        let third_router = router.clone();

        let company_name = Paragraph(1..2).fake::<String>();
        let email = format!(
            "{}{}{}",
            Word().fake::<String>(),
            Word().fake::<String>(),
            SafeEmail().fake::<String>()
        );
        let password = "password123";

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/setup")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "company_name": &company_name,
                            "email": &email,
                            "password": &password,
                            "repeat_password": &password,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: User = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.email, email);

        let company_id = body.company_id;
        let user_id = body.id;

        let response = second_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/auth")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "email": &email,
                            "password": &password,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: SessionResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);

        let session_id = body.id;

        let ai_service_id = "33847746-0030-4964-a496-f75d04499160";

        let response = third_router
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

        app.context
            .octopus_database
            .try_delete_user_by_id(user_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_company_by_id(company_id)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn update_200() {
        let args = Args {
            azure_openai_api_key: None,
            azure_openai_deployment_id: None,
            azure_openai_enabled: Some(true),
            database_url: Some(String::from(
                "postgres://admin:admin@db/octopus_server_test",
            )),
            openai_api_key: None,
            port: None,
        };
        let app = app::get_app(args).await.unwrap();
        let router = app.router;
        let second_router = router.clone();
        let third_router = router.clone();
        let fourth_router = router.clone();

        let company_name = Paragraph(1..2).fake::<String>();
        let email = format!(
            "{}{}{}",
            Word().fake::<String>(),
            Word().fake::<String>(),
            SafeEmail().fake::<String>()
        );
        let password = "password123";

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/setup")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "company_name": &company_name,
                            "email": &email,
                            "password": &password,
                            "repeat_password": &password,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: User = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.email, email);

        let company_id = body.company_id;
        let user_id = body.id;

        let response = second_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/auth")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "email": &email,
                            "password": &password,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: SessionResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);

        let session_id = body.id;

        let has_file_response = false;
        let is_available = true;
        let is_enabled = true;
        let name = format!(
            "function-foo-sync{}{}",
            Word().fake::<String>(),
            Word().fake::<String>()
        );

        let response = third_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/ai-services")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "base_function_url": "http://127.0.0.1:5000/v1/function-foo-sync",
                            "description": "Synchronous communication test function",
                            "device_map": {
                                "max_memory": {"0": "10GiB", "1": "10GiB", "cpu": "30GiB"}
                            },
                            "has_file_response": &has_file_response,
                            "health_check_url": "http://127.0.0.1:5000/v1/health-check",
                            "is_available": &is_available,
                            "is_enabled": &is_enabled,
                            "name": &name,
                            "parameters": {
                                "type": "object",
                                "properties": {
                                    "value1": {
                                        "type": "string",
                                        "description": "First value"
                                    },
                                    "value2": { "type": "string", "enum": ["abc", "def"], "description": "Second value" }
                                },
                                "required": ["value1", "value2"]
                            },
                            "setup_url": "http://127.0.0.1:5000/v1/setup"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: AiService = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.is_enabled, is_enabled);
        assert_eq!(body.name, name);

        let ai_service_id = body.id;

        let has_file_response = false;
        let is_available = false;
        let is_enabled = false;

        let response = fourth_router
            .oneshot(
                Request::builder()
                    .method(http::Method::PUT)
                    .uri(format!("/api/v1/ai-services/{ai_service_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "base_function_url": "http://127.0.0.1:5000/v1/function-foo-sync",
                            "description": "Synchronous communication test function",
                            "device_map": {
                                "max_memory": {"0": "10GiB", "1": "10GiB", "cpu": "30GiB"}
                            },
                            "has_file_response": &has_file_response,
                            "health_check_url": "http://127.0.0.1:5000/v1/health-check",
                            "is_available": &is_available,
                            "is_enabled": &is_enabled,
                            "name": &name,
                            "parameters": {
                                "type": "object",
                                "properties": {
                                    "value1": {
                                        "type": "string",
                                        "description": "First value"
                                    },
                                    "value2": { "type": "string", "enum": ["abc", "def"], "description": "Second value" }
                                },
                                "required": ["value1", "value2"]
                            },
                            "setup_url": "http://127.0.0.1:5000/v1/setup"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: AiService = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.is_enabled, is_enabled);
        assert_eq!(body.name, name);

        app.context
            .octopus_database
            .try_delete_user_by_id(user_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_company_by_id(company_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_ai_service_by_id(ai_service_id)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn update_403() {
        let args = Args {
            azure_openai_api_key: None,
            azure_openai_deployment_id: None,
            azure_openai_enabled: Some(true),
            database_url: Some(String::from(
                "postgres://admin:admin@db/octopus_server_test",
            )),
            openai_api_key: None,
            port: None,
        };
        let app = app::get_app(args).await.unwrap();
        let router = app.router;
        let second_router = router.clone();
        let third_router = router.clone();
        let fourth_router = router.clone();
        let fifth_router = router.clone();
        let sixth_router = router.clone();

        let company_name = Paragraph(1..2).fake::<String>();
        let email = format!(
            "{}{}{}",
            Word().fake::<String>(),
            Word().fake::<String>(),
            SafeEmail().fake::<String>()
        );
        let password = "password123";

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/setup")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "company_name": &company_name,
                            "email": &email,
                            "password": &password,
                            "repeat_password": &password,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: User = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.email, email);

        let company_id = body.company_id;
        let user_id = body.id;

        let response = second_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/auth")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "email": &email,
                            "password": &password,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: SessionResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);

        let session_id = body.id;

        let has_file_response = false;
        let is_available = true;
        let is_enabled = true;
        let name = format!(
            "function-foo-sync{}{}",
            Word().fake::<String>(),
            Word().fake::<String>()
        );

        let response = third_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/ai-services")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "base_function_url": "http://127.0.0.1:5000/v1/function-foo-sync",
                            "description": "Synchronous communication test function",
                            "device_map": {
                                "max_memory": {"0": "10GiB", "1": "10GiB", "cpu": "30GiB"}
                            },
                            "has_file_response": &has_file_response,
                            "health_check_url": "http://127.0.0.1:5000/v1/health-check",
                            "is_available": &is_available,
                            "is_enabled": &is_enabled,
                            "name": &name,
                            "parameters": {
                                "type": "object",
                                "properties": {
                                    "value1": {
                                        "type": "string",
                                        "description": "First value"
                                    },
                                    "value2": { "type": "string", "enum": ["abc", "def"], "description": "Second value" }
                                },
                                "required": ["value1", "value2"]
                            },
                            "setup_url": "http://127.0.0.1:5000/v1/setup"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: AiService = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.is_enabled, is_enabled);
        assert_eq!(body.name, name);

        let ai_service_id = body.id;

        let email = format!(
            "{}{}{}",
            Word().fake::<String>(),
            Word().fake::<String>(),
            SafeEmail().fake::<String>()
        );
        let job_title = Paragraph(1..2).fake::<String>();
        let name = Name().fake::<String>();
        let password = "password123";

        let response = fourth_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri(format!("/api/v1/auth/register/{company_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "email": &email,
                            "job_title": &job_title,
                            "name": &name,
                            "password": &password,
                            "repeat_password": &password,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: User = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.email, email);

        let company2_id = body.company_id;
        let user2_id = body.id;

        let response = fifth_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/auth")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "email": &email,
                            "password": &password,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: SessionResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user2_id);

        let session_id = body.id;

        let has_file_response = false;
        let is_available = false;
        let is_enabled = false;

        let response = sixth_router
            .oneshot(
                Request::builder()
                    .method(http::Method::PUT)
                    .uri(format!("/api/v1/ai-services/{ai_service_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "base_function_url": "http://127.0.0.1:5000/v1/function-foo-sync",
                            "description": "Synchronous communication test function",
                            "device_map": {
                                "max_memory": {"0": "10GiB", "1": "10GiB", "cpu": "30GiB"}
                            },
                            "has_file_response": &has_file_response,
                            "health_check_url": "http://127.0.0.1:5000/v1/health-check",
                            "is_available": &is_available,
                            "is_enabled": &is_enabled,
                            "name": &name,
                            "parameters": {
                                "type": "object",
                                "properties": {
                                    "value1": {
                                        "type": "string",
                                        "description": "First value"
                                    },
                                    "value2": { "type": "string", "enum": ["abc", "def"], "description": "Second value" }
                                },
                                "required": ["value1", "value2"]
                            },
                            "setup_url": "http://127.0.0.1:5000/v1/setup"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        app.context
            .octopus_database
            .try_delete_user_by_id(user_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_user_by_id(user2_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_company_by_id(company_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_company_by_id(company2_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_ai_service_by_id(ai_service_id)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn update_404() {
        let args = Args {
            azure_openai_api_key: None,
            azure_openai_deployment_id: None,
            azure_openai_enabled: Some(true),
            database_url: Some(String::from(
                "postgres://admin:admin@db/octopus_server_test",
            )),
            openai_api_key: None,
            port: None,
        };
        let app = app::get_app(args).await.unwrap();
        let router = app.router;
        let second_router = router.clone();
        let third_router = router.clone();

        let company_name = Paragraph(1..2).fake::<String>();
        let email = format!(
            "{}{}{}",
            Word().fake::<String>(),
            Word().fake::<String>(),
            SafeEmail().fake::<String>()
        );
        let password = "password123";

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/setup")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "company_name": &company_name,
                            "email": &email,
                            "password": &password,
                            "repeat_password": &password,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: User = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.email, email);

        let company_id = body.company_id;
        let user_id = body.id;

        let response = second_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/auth")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "email": &email,
                            "password": &password,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: SessionResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);

        let session_id = body.id;

        let ai_service_id = "33847746-0030-4964-a496-f75d04499160";

        let has_file_response = false;
        let is_available = true;
        let is_enabled = true;
        let name = format!(
            "function-foo-sync{}{}",
            Word().fake::<String>(),
            Word().fake::<String>()
        );

        let response = third_router
            .oneshot(
                Request::builder()
                    .method(http::Method::PUT)
                    .uri(format!("/api/v1/ai-services/{ai_service_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "base_function_url": "http://127.0.0.1:5000/v1/function-foo-sync",
                            "description": "Synchronous communication test function",
                            "device_map": {
                                "max_memory": {"0": "10GiB", "1": "10GiB", "cpu": "30GiB"}
                            },
                            "has_file_response": &has_file_response,
                            "health_check_url": "http://127.0.0.1:5000/v1/health-check",
                            "is_available": &is_available,
                            "is_enabled": &is_enabled,
                            "name": &name,
                            "parameters": {
                                "type": "object",
                                "properties": {
                                    "value1": {
                                        "type": "string",
                                        "description": "First value"
                                    },
                                    "value2": { "type": "string", "enum": ["abc", "def"], "description": "Second value" }
                                },
                                "required": ["value1", "value2"]
                            },
                            "setup_url": "http://127.0.0.1:5000/v1/setup"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        app.context
            .octopus_database
            .try_delete_user_by_id(user_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_company_by_id(company_id)
            .await
            .unwrap();
    }
}
*/
