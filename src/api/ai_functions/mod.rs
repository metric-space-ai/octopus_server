use crate::{
    ai,
    context::Context,
    entity::ROLE_ADMIN,
    error::AppError,
    session::{ensure_secured, ExtractedSession},
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
pub struct AiFunctionPost {
    pub base_function_url: String,
    pub description: String,
    pub hardware_bindings: Vec<String>,
    pub health_check_url: String,
    pub is_available: bool,
    pub is_enabled: bool,
    pub k8s_configuration: Option<String>,
    pub name: String,
    pub parameters: serde_json::Value,
}

#[derive(Debug, Deserialize, ToSchema, Validate)]
pub struct AiFunctionPut {
    pub base_function_url: String,
    pub description: String,
    pub hardware_bindings: Vec<String>,
    pub health_check_url: String,
    pub is_available: bool,
    pub is_enabled: bool,
    pub k8s_configuration: Option<String>,
    pub name: String,
    pub parameters: serde_json::Value,
}

#[axum_macros::debug_handler]
#[utoipa::path(
    post,
    path = "/api/v1/ai-functions",
    request_body = AiFunctionPost,
    responses(
        (status = 201, description = "AI Function created.", body = AiFunction),
        (status = 401, description = "Unauthorized request.", body = ResponseError),
        (status = 409, description = "Conflicting request.", body = ResponseError),
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn create(
    State(context): State<Arc<Context>>,
    extracted_session: ExtractedSession,
    Json(input): Json<AiFunctionPost>,
) -> Result<impl IntoResponse, AppError> {
    ensure_secured(context.clone(), extracted_session, ROLE_ADMIN).await?;
    input.validate()?;

    let ai_function_exists = context
        .octopus_database
        .try_get_ai_function_by_name(&input.name)
        .await?;

    match ai_function_exists {
        None => {
            let ai_function = context
                .octopus_database
                .insert_ai_function(
                    &input.base_function_url,
                    &input.description,
                    &input.hardware_bindings,
                    &input.health_check_url,
                    input.is_available,
                    input.is_enabled,
                    input.k8s_configuration,
                    &input.name,
                    input.parameters,
                )
                .await?;

            let cloned_context = context.clone();
            let cloned_ai_function = ai_function.clone();
            tokio::spawn(async move {
                let ai_function = ai::prepare_ai_function(cloned_context, cloned_ai_function).await;

                if let Err(e) = ai_function {
                    debug!("Error: {:?}", e);
                }
            });

            Ok((StatusCode::CREATED, Json(ai_function)).into_response())
        }
        Some(_ai_function) => Err(AppError::Conflict),
    }
}

#[axum_macros::debug_handler]
#[utoipa::path(
    delete,
    path = "/api/v1/ai-functions/:id",
    responses(
        (status = 204, description = "AI Function deleted."),
        (status = 401, description = "Unauthorized request.", body = ResponseError),
        (status = 404, description = "AI Function not found.", body = ResponseError),
    ),
    params(
        ("id" = String, Path, description = "AI Function id")
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
    ensure_secured(context.clone(), extracted_session, ROLE_ADMIN).await?;

    context
        .octopus_database
        .try_delete_ai_function_by_id(id)
        .await?
        .ok_or(AppError::NotFound)?;

    Ok((StatusCode::NO_CONTENT, ()).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    get,
    path = "/api/v1/ai-functions",
    responses(
        (status = 200, description = "List of AI Functions.", body = [AiFunction]),
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
    ensure_secured(context.clone(), extracted_session, ROLE_ADMIN).await?;

    let ai_functions = context.octopus_database.get_ai_functions().await?;

    Ok((StatusCode::OK, Json(ai_functions)).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    get,
    path = "/api/v1/ai-functions/:id",
    responses(
        (status = 200, description = "AI Function read.", body = AiFunction),
        (status = 401, description = "Unauthorized request.", body = ResponseError),
        (status = 404, description = "AI Function not found.", body = ResponseError),
    ),
    params(
        ("id" = String, Path, description = "AI Function id")
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
    ensure_secured(context.clone(), extracted_session, ROLE_ADMIN).await?;

    let ai_function = context
        .octopus_database
        .try_get_ai_function_by_id(id)
        .await?
        .ok_or(AppError::NotFound)?;

    Ok((StatusCode::OK, Json(ai_function)).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    put,
    path = "/api/v1/ai-functions/:id",
    request_body = AiFunctionPut,
    responses(
        (status = 200, description = "AI Function updated.", body = AiFunction),
        (status = 401, description = "Unauthorized request.", body = ResponseError),
        (status = 404, description = "AI Function not found.", body = ResponseError),
        (status = 409, description = "Conflicting request.", body = ResponseError),
    ),
    params(
        ("id" = String, Path, description = "AI Function id")
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn update(
    State(context): State<Arc<Context>>,
    extracted_session: ExtractedSession,
    Path(id): Path<Uuid>,
    Json(input): Json<AiFunctionPut>,
) -> Result<impl IntoResponse, AppError> {
    ensure_secured(context.clone(), extracted_session, ROLE_ADMIN).await?;
    input.validate()?;

    context
        .octopus_database
        .try_get_ai_function_id_by_id(id)
        .await?
        .ok_or(AppError::NotFound)?;

    let ai_function_exists = context
        .octopus_database
        .try_get_ai_function_by_name(&input.name)
        .await?
        .ok_or(AppError::NotFound)?;

    if ai_function_exists.id != id {
        return Err(AppError::Conflict);
    }

    let ai_function = context
        .octopus_database
        .update_ai_function(
            id,
            &input.base_function_url,
            &input.description,
            &input.hardware_bindings,
            &input.health_check_url,
            input.is_available,
            input.is_enabled,
            input.k8s_configuration,
            &input.name,
            input.parameters,
        )
        .await?;

    let cloned_context = context.clone();
    let cloned_ai_function = ai_function.clone();
    tokio::spawn(async move {
        let ai_function = ai::prepare_ai_function(cloned_context, cloned_ai_function).await;

        if let Err(e) = ai_function {
            debug!("Error: {:?}", e);
        }
    });

    Ok((StatusCode::OK, Json(ai_function)).into_response())
}

#[cfg(test)]
mod tests {
    use crate::{
        app,
        entity::AiFunction,
        entity::{User, ROLE_ADMIN, ROLE_COMPANY_ADMIN_USER, ROLE_PRIVATE_USER, ROLE_PUBLIC_USER},
        session::SessionResponse,
        Args,
    };
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

        app.context
            .octopus_database
            .update_user_roles(
                user_id,
                &[
                    ROLE_ADMIN.to_string(),
                    ROLE_COMPANY_ADMIN_USER.to_string(),
                    ROLE_PRIVATE_USER.to_string(),
                    ROLE_PUBLIC_USER.to_string(),
                ],
            )
            .await
            .unwrap();

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
                    .uri("/api/v1/ai-functions")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "base_function_url": "http://127.0.0.1:5000/v1/function-foo-sync",
                            "description": "Synchronous communication test function",
                            "hardware_bindings": ["CPU 0", "GPU 0"],
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
                            }
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: AiFunction = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.is_available, is_available);
        assert_eq!(body.is_enabled, is_enabled);
        assert_eq!(body.name, name);

        let ai_function_id = body.id;

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
            .try_delete_ai_function_by_id(ai_function_id)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn create_401() {
        let args = Args {
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
                    .uri("/api/v1/ai-functions")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "base_function_url": "http://127.0.0.1:5000/v1/function-foo-sync",
                            "description": "Synchronous communication test function",
                            "hardware_bindings": ["CPU 0", "GPU 0"],
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
                            }
                        })
                        .to_string(),
                    ))
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
    async fn create_409() {
        let args = Args {
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

        app.context
            .octopus_database
            .update_user_roles(
                user_id,
                &[
                    ROLE_ADMIN.to_string(),
                    ROLE_COMPANY_ADMIN_USER.to_string(),
                    ROLE_PRIVATE_USER.to_string(),
                    ROLE_PUBLIC_USER.to_string(),
                ],
            )
            .await
            .unwrap();

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
                    .uri("/api/v1/ai-functions")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "base_function_url": "http://127.0.0.1:5000/v1/function-foo-sync",
                            "description": "Synchronous communication test function",
                            "hardware_bindings": ["CPU 0", "GPU 0"],
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
                            }
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: AiFunction = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.is_available, is_available);
        assert_eq!(body.is_enabled, is_enabled);
        assert_eq!(body.name, name);

        let ai_function_id = body.id;

        let response = fourth_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/ai-functions")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "base_function_url": "http://127.0.0.1:5000/v1/function-foo-sync",
                            "description": "Synchronous communication test function",
                            "hardware_bindings": ["CPU 0", "GPU 0"],
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
                            }
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CONFLICT);

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
            .try_delete_ai_function_by_id(ai_function_id)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn delete_204() {
        let args = Args {
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

        app.context
            .octopus_database
            .update_user_roles(
                user_id,
                &[
                    ROLE_ADMIN.to_string(),
                    ROLE_COMPANY_ADMIN_USER.to_string(),
                    ROLE_PRIVATE_USER.to_string(),
                    ROLE_PUBLIC_USER.to_string(),
                ],
            )
            .await
            .unwrap();

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
                    .uri("/api/v1/ai-functions")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "base_function_url": "http://127.0.0.1:5000/v1/function-foo-sync",
                            "description": "Synchronous communication test function",
                            "hardware_bindings": ["CPU 0", "GPU 0"],
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
                            }
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: AiFunction = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.is_available, is_available);
        assert_eq!(body.is_enabled, is_enabled);
        assert_eq!(body.name, name);

        let ai_function_id = body.id;

        let response = fourth_router
            .oneshot(
                Request::builder()
                    .method(http::Method::DELETE)
                    .uri(format!("/api/v1/ai-functions/{ai_function_id}"))
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
    async fn delete_401() {
        let args = Args {
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

        app.context
            .octopus_database
            .update_user_roles(
                user_id,
                &[
                    ROLE_ADMIN.to_string(),
                    ROLE_COMPANY_ADMIN_USER.to_string(),
                    ROLE_PRIVATE_USER.to_string(),
                    ROLE_PUBLIC_USER.to_string(),
                ],
            )
            .await
            .unwrap();

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
                    .uri("/api/v1/ai-functions")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "base_function_url": "http://127.0.0.1:5000/v1/function-foo-sync",
                            "description": "Synchronous communication test function",
                            "hardware_bindings": ["CPU 0", "GPU 0"],
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
                            }
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: AiFunction = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.is_available, is_available);
        assert_eq!(body.is_enabled, is_enabled);
        assert_eq!(body.name, name);

        let ai_function_id = body.id;

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
                    .uri(format!("/api/v1/ai-functions/{ai_function_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
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
            .try_delete_ai_function_by_id(ai_function_id)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn delete_404() {
        let args = Args {
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

        app.context
            .octopus_database
            .update_user_roles(
                user_id,
                &[
                    ROLE_ADMIN.to_string(),
                    ROLE_COMPANY_ADMIN_USER.to_string(),
                    ROLE_PRIVATE_USER.to_string(),
                    ROLE_PUBLIC_USER.to_string(),
                ],
            )
            .await
            .unwrap();

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

        let ai_function_id = "33847746-0030-4964-a496-f75d04499160";

        let response = third_router
            .oneshot(
                Request::builder()
                    .method(http::Method::DELETE)
                    .uri(format!("/api/v1/ai-functions/{ai_function_id}"))
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

        app.context
            .octopus_database
            .update_user_roles(
                user_id,
                &[
                    ROLE_ADMIN.to_string(),
                    ROLE_COMPANY_ADMIN_USER.to_string(),
                    ROLE_PRIVATE_USER.to_string(),
                    ROLE_PUBLIC_USER.to_string(),
                ],
            )
            .await
            .unwrap();

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
                    .uri("/api/v1/ai-functions")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "base_function_url": "http://127.0.0.1:5000/v1/function-foo-sync",
                            "description": "Synchronous communication test function",
                            "hardware_bindings": ["CPU 0", "GPU 0"],
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
                            }
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: AiFunction = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.is_available, is_available);
        assert_eq!(body.is_enabled, is_enabled);
        assert_eq!(body.name, name);

        let ai_function_id = body.id;

        let response = fourth_router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri("/api/v1/ai-functions")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: Vec<AiFunction> = serde_json::from_slice(&body).unwrap();

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
            .try_delete_ai_function_by_id(ai_function_id)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn list_401() {
        let args = Args {
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

        app.context
            .octopus_database
            .update_user_roles(
                user_id,
                &[
                    ROLE_ADMIN.to_string(),
                    ROLE_COMPANY_ADMIN_USER.to_string(),
                    ROLE_PRIVATE_USER.to_string(),
                    ROLE_PUBLIC_USER.to_string(),
                ],
            )
            .await
            .unwrap();

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
                    .uri("/api/v1/ai-functions")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "base_function_url": "http://127.0.0.1:5000/v1/function-foo-sync",
                            "description": "Synchronous communication test function",
                            "hardware_bindings": ["CPU 0", "GPU 0"],
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
                            }
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: AiFunction = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.is_available, is_available);
        assert_eq!(body.is_enabled, is_enabled);
        assert_eq!(body.name, name);

        let ai_function_id = body.id;

        let response = fourth_router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri("/api/v1/ai-functions")
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
            .try_delete_ai_function_by_id(ai_function_id)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn read_200() {
        let args = Args {
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

        app.context
            .octopus_database
            .update_user_roles(
                user_id,
                &[
                    ROLE_ADMIN.to_string(),
                    ROLE_COMPANY_ADMIN_USER.to_string(),
                    ROLE_PRIVATE_USER.to_string(),
                    ROLE_PUBLIC_USER.to_string(),
                ],
            )
            .await
            .unwrap();

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
                    .uri("/api/v1/ai-functions")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "base_function_url": "http://127.0.0.1:5000/v1/function-foo-sync",
                            "description": "Synchronous communication test function",
                            "hardware_bindings": ["CPU 0", "GPU 0"],
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
                            }
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: AiFunction = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.is_available, is_available);
        assert_eq!(body.is_enabled, is_enabled);
        assert_eq!(body.name, name);

        let ai_function_id = body.id;

        let response = fourth_router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("/api/v1/ai-functions/{ai_function_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: AiFunction = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.is_available, is_available);
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
            .try_delete_ai_function_by_id(ai_function_id)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn read_401() {
        let args = Args {
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

        app.context
            .octopus_database
            .update_user_roles(
                user_id,
                &[
                    ROLE_ADMIN.to_string(),
                    ROLE_COMPANY_ADMIN_USER.to_string(),
                    ROLE_PRIVATE_USER.to_string(),
                    ROLE_PUBLIC_USER.to_string(),
                ],
            )
            .await
            .unwrap();

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
                    .uri("/api/v1/ai-functions")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "base_function_url": "http://127.0.0.1:5000/v1/function-foo-sync",
                            "description": "Synchronous communication test function",
                            "hardware_bindings": ["CPU 0", "GPU 0"],
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
                            }
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: AiFunction = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.is_available, is_available);
        assert_eq!(body.is_enabled, is_enabled);
        assert_eq!(body.name, name);

        let ai_function_id = body.id;

        let response = fourth_router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("/api/v1/ai-functions/{ai_function_id}"))
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
            .try_delete_ai_function_by_id(ai_function_id)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn read_404() {
        let args = Args {
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

        app.context
            .octopus_database
            .update_user_roles(
                user_id,
                &[
                    ROLE_ADMIN.to_string(),
                    ROLE_COMPANY_ADMIN_USER.to_string(),
                    ROLE_PRIVATE_USER.to_string(),
                    ROLE_PUBLIC_USER.to_string(),
                ],
            )
            .await
            .unwrap();

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

        let ai_function_id = "33847746-0030-4964-a496-f75d04499160";

        let response = third_router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("/api/v1/ai-functions/{ai_function_id}"))
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

        app.context
            .octopus_database
            .update_user_roles(
                user_id,
                &[
                    ROLE_ADMIN.to_string(),
                    ROLE_COMPANY_ADMIN_USER.to_string(),
                    ROLE_PRIVATE_USER.to_string(),
                    ROLE_PUBLIC_USER.to_string(),
                ],
            )
            .await
            .unwrap();

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
                    .uri("/api/v1/ai-functions")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "base_function_url": "http://127.0.0.1:5000/v1/function-foo-sync",
                            "description": "Synchronous communication test function",
                            "hardware_bindings": ["CPU 0", "GPU 0"],
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
                            }
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: AiFunction = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.is_available, is_available);
        assert_eq!(body.is_enabled, is_enabled);
        assert_eq!(body.name, name);

        let ai_function_id = body.id;

        let is_available = false;
        let is_enabled = false;

        let response = fourth_router
            .oneshot(
                Request::builder()
                    .method(http::Method::PUT)
                    .uri(format!("/api/v1/ai-functions/{ai_function_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "base_function_url": "http://127.0.0.1:5000/v1/function-foo-sync",
                            "description": "Synchronous communication test function",
                            "hardware_bindings": ["CPU 0", "GPU 0"],
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
                            }
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: AiFunction = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.is_available, is_available);
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
            .try_delete_ai_function_by_id(ai_function_id)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn update_401() {
        let args = Args {
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

        app.context
            .octopus_database
            .update_user_roles(
                user_id,
                &[
                    ROLE_ADMIN.to_string(),
                    ROLE_COMPANY_ADMIN_USER.to_string(),
                    ROLE_PRIVATE_USER.to_string(),
                    ROLE_PUBLIC_USER.to_string(),
                ],
            )
            .await
            .unwrap();

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
                    .uri("/api/v1/ai-functions")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "base_function_url": "http://127.0.0.1:5000/v1/function-foo-sync",
                            "description": "Synchronous communication test function",
                            "hardware_bindings": ["CPU 0", "GPU 0"],
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
                            }
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: AiFunction = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.is_available, is_available);
        assert_eq!(body.is_enabled, is_enabled);
        assert_eq!(body.name, name);

        let ai_function_id = body.id;

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

        let is_available = false;
        let is_enabled = false;

        let response = sixth_router
            .oneshot(
                Request::builder()
                    .method(http::Method::PUT)
                    .uri(format!("/api/v1/ai-functions/{ai_function_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "base_function_url": "http://127.0.0.1:5000/v1/function-foo-sync",
                            "description": "Synchronous communication test function",
                            "hardware_bindings": ["CPU 0", "GPU 0"],
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
                            }
                        })
                        .to_string(),
                    ))
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
            .try_delete_ai_function_by_id(ai_function_id)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn update_404() {
        let args = Args {
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

        app.context
            .octopus_database
            .update_user_roles(
                user_id,
                &[
                    ROLE_ADMIN.to_string(),
                    ROLE_COMPANY_ADMIN_USER.to_string(),
                    ROLE_PRIVATE_USER.to_string(),
                    ROLE_PUBLIC_USER.to_string(),
                ],
            )
            .await
            .unwrap();

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

        let ai_function_id = "33847746-0030-4964-a496-f75d04499160";

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
                    .uri(format!("/api/v1/ai-functions/{ai_function_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "base_function_url": "http://127.0.0.1:5000/v1/function-foo-sync",
                            "description": "Synchronous communication test function",
                            "hardware_bindings": ["CPU 0", "GPU 0"],
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
                            }
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

    #[tokio::test]
    async fn update_409() {
        let args = Args {
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

        app.context
            .octopus_database
            .update_user_roles(
                user_id,
                &[
                    ROLE_ADMIN.to_string(),
                    ROLE_COMPANY_ADMIN_USER.to_string(),
                    ROLE_PRIVATE_USER.to_string(),
                    ROLE_PUBLIC_USER.to_string(),
                ],
            )
            .await
            .unwrap();

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
                    .uri("/api/v1/ai-functions")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "base_function_url": "http://127.0.0.1:5000/v1/function-foo-sync",
                            "description": "Synchronous communication test function",
                            "hardware_bindings": ["CPU 0", "GPU 0"],
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
                            }
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: AiFunction = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.is_available, is_available);
        assert_eq!(body.is_enabled, is_enabled);
        assert_eq!(body.name, name);

        let ai_function_id = body.id;

        let name2 = format!(
            "function-foo-sync{}{}",
            Word().fake::<String>(),
            Word().fake::<String>()
        );

        let response = fourth_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/ai-functions")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "base_function_url": "http://127.0.0.1:5000/v1/function-foo-sync",
                            "description": "Synchronous communication test function",
                            "hardware_bindings": ["CPU 0", "GPU 0"],
                            "health_check_url": "http://127.0.0.1:5000/v1/health-check",
                            "is_available": &is_available,
                            "is_enabled": &is_enabled,
                            "name": &name2,
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
                            }
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: AiFunction = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.is_available, is_available);
        assert_eq!(body.is_enabled, is_enabled);
        assert_eq!(body.name, name2);

        let ai_function2_id = body.id;

        let is_available = false;
        let is_enabled = false;

        let response = fifth_router
            .oneshot(
                Request::builder()
                    .method(http::Method::PUT)
                    .uri(format!("/api/v1/ai-functions/{ai_function_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "base_function_url": "http://127.0.0.1:5000/v1/function-foo-sync",
                            "description": "Synchronous communication test function",
                            "hardware_bindings": ["CPU 0", "GPU 0"],
                            "health_check_url": "http://127.0.0.1:5000/v1/health-check",
                            "is_available": &is_available,
                            "is_enabled": &is_enabled,
                            "name": &name2,
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
                            }
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CONFLICT);

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
            .try_delete_ai_function_by_id(ai_function_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_ai_function_by_id(ai_function2_id)
            .await
            .unwrap();
    }
}
