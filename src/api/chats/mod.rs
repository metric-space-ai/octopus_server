use crate::{
    context::Context,
    error::AppError,
    session::{require_authenticated_session, ExtractedSession},
};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use std::sync::Arc;
use utoipa::ToSchema;
use uuid::Uuid;
use validator::Validate;

#[derive(Debug, Deserialize, ToSchema, Validate)]
pub struct ChatPut {
    pub name: String,
}

#[axum_macros::debug_handler]
#[utoipa::path(
    post,
    path = "/api/v1/chats",
    responses(
        (status = 201, description = "Chat created.", body = Chat),
        (status = 401, description = "Unauthorized request.", body = ResponseError),
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn create(
    State(context): State<Arc<Context>>,
    extracted_session: ExtractedSession,
) -> Result<impl IntoResponse, AppError> {
    let session = require_authenticated_session(extracted_session).await?;

    let chat = context
        .octopus_database
        .insert_chat(session.user_id)
        .await?;

    Ok((StatusCode::CREATED, Json(chat)).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    delete,
    path = "/api/v1/chats/:id",
    responses(
        (status = 204, description = "Chat deleted."),
        (status = 401, description = "Unauthorized request.", body = ResponseError),
        (status = 404, description = "Chat not found.", body = ResponseError),
    ),
    params(
        ("id" = String, Path, description = "Chat id")
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
    let session = require_authenticated_session(extracted_session).await?;

    let chat = context.octopus_database.try_get_chat_by_id(id).await?;

    match chat {
        None => Err(AppError::NotFound),
        Some(chat) => {
            if chat.user_id != session.user_id {
                return Err(AppError::Unauthorized);
            }

            let chat = context.octopus_database.try_delete_chat_by_id(id).await?;

            match chat {
                None => Err(AppError::NotFound),
                Some(_chat) => Ok((StatusCode::NO_CONTENT, ()).into_response()),
            }
        }
    }
}

#[axum_macros::debug_handler]
#[utoipa::path(
    get,
    path = "/api/v1/chats",
    responses(
        (status = 200, description = "List of chats.", body = [Chat]),
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
    let session = require_authenticated_session(extracted_session).await?;

    let chats = context
        .octopus_database
        .get_chats_by_user_id(session.user_id)
        .await?;

    Ok((StatusCode::OK, Json(chats)).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    get,
    path = "/api/v1/chats/:id",
    responses(
        (status = 200, description = "Chat read.", body = Chat),
        (status = 401, description = "Unauthorized request.", body = ResponseError),
        (status = 404, description = "Chat not found.", body = ResponseError),
    ),
    params(
        ("id" = String, Path, description = "Chat id")
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
    let session = require_authenticated_session(extracted_session).await?;

    let chat = context.octopus_database.try_get_chat_by_id(id).await?;

    match chat {
        None => Err(AppError::NotFound),
        Some(chat) => {
            if chat.user_id != session.user_id {
                return Err(AppError::Unauthorized);
            }

            Ok((StatusCode::OK, Json(chat)).into_response())
        }
    }
}

#[axum_macros::debug_handler]
#[utoipa::path(
    put,
    path = "/api/v1/chats/:id",
    request_body = ChatPut,
    responses(
        (status = 200, description = "Chat updated.", body = Chat),
        (status = 401, description = "Unauthorized request.", body = ResponseError),
        (status = 404, description = "Chat not found.", body = ResponseError),
    ),
    params(
        ("id" = String, Path, description = "Chat id")
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn update(
    State(context): State<Arc<Context>>,
    extracted_session: ExtractedSession,
    Path(id): Path<Uuid>,
    Json(input): Json<ChatPut>,
) -> Result<impl IntoResponse, AppError> {
    let session = require_authenticated_session(extracted_session).await?;
    input.validate()?;

    let chat = context.octopus_database.try_get_chat_by_id(id).await?;

    match chat {
        None => Err(AppError::NotFound),
        Some(chat) => {
            if chat.user_id != session.user_id {
                return Err(AppError::Unauthorized);
            }

            let chat = context
                .octopus_database
                .update_chat(id, &input.name)
                .await?;

            Ok((StatusCode::OK, Json(chat)).into_response())
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{app, entity::Chat, entity::User, session::SessionResponse, Args};
    use axum::{
        body::Body,
        http::{self, Request, StatusCode},
    };
    use fake::{
        faker::{internet::en::SafeEmail, lorem::en::Word},
        Fake,
    };
    use tower::ServiceExt;

    #[tokio::test]
    async fn create_201() {
        let args = Args {
            openai_api_key: None,
            port: None,
        };
        let app = app::get_app(args).await.unwrap();
        let router = app.router;
        let second_router = router.clone();
        let third_router = router.clone();

        let company_name = Word().fake::<String>();
        let email = SafeEmail().fake::<String>();
        let password = "password123";

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/auth/register")
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

        let response = third_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/chats")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: Chat = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);

        let chat_id = body.id;

        app.context
            .octopus_database
            .try_delete_company_by_id(company_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_chat_by_id(chat_id)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn create_401() {
        let args = Args {
            openai_api_key: None,
            port: None,
        };
        let app = app::get_app(args).await.unwrap();
        let router = app.router;
        let second_router = router.clone();
        let third_router = router.clone();

        let company_name = Word().fake::<String>();
        let email = SafeEmail().fake::<String>();
        let password = "password123";

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/auth/register")
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

        let response = third_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/chats")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        app.context
            .octopus_database
            .try_delete_company_by_id(company_id)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn delete_204() {
        let args = Args {
            openai_api_key: None,
            port: None,
        };
        let app = app::get_app(args).await.unwrap();
        let router = app.router;
        let second_router = router.clone();
        let third_router = router.clone();
        let fourth_router = router.clone();

        let company_name = Word().fake::<String>();
        let email = SafeEmail().fake::<String>();
        let password = "password123";

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/auth/register")
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

        let response = third_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/chats")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: Chat = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);

        let chat_id = body.id;

        let response = fourth_router
            .oneshot(
                Request::builder()
                    .method(http::Method::DELETE)
                    .uri(format!("/api/v1/chats/{}", chat_id))
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
            .try_delete_company_by_id(company_id)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn delete_401() {
        let args = Args {
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

        let company_name = Word().fake::<String>();
        let email = SafeEmail().fake::<String>();
        let password = "password123";

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/auth/register")
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

        let response = third_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/chats")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: Chat = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);

        let chat_id = body.id;

        let company_name = Word().fake::<String>();
        let email = SafeEmail().fake::<String>();
        let password = "password123";

        let response = fourth_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/auth/register")
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

        let company2_id = body.company_id;
        let user_id = body.id;

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

        assert_eq!(body.user_id, user_id);

        let session_id = body.id;

        let response = sixth_router
            .oneshot(
                Request::builder()
                    .method(http::Method::DELETE)
                    .uri(format!("/api/v1/chats/{}", chat_id))
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
            .try_delete_chat_by_id(chat_id)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn delete_404() {
        let args = Args {
            openai_api_key: None,
            port: None,
        };
        let app = app::get_app(args).await.unwrap();
        let router = app.router;
        let second_router = router.clone();
        let third_router = router.clone();

        let company_name = Word().fake::<String>();
        let email = SafeEmail().fake::<String>();
        let password = "password123";

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/auth/register")
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

        let chat_id = "33847746-0030-4964-a496-f75d04499160";

        let response = third_router
            .oneshot(
                Request::builder()
                    .method(http::Method::DELETE)
                    .uri(format!("/api/v1/chats/{}", chat_id))
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
            .try_delete_company_by_id(company_id)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn list_200() {
        let args = Args {
            openai_api_key: None,
            port: None,
        };
        let app = app::get_app(args).await.unwrap();
        let router = app.router;
        let second_router = router.clone();
        let third_router = router.clone();
        let fourth_router = router.clone();

        let company_name = Word().fake::<String>();
        let email = SafeEmail().fake::<String>();
        let password = "password123";

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/auth/register")
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

        let response = third_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/chats")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: Chat = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);

        let chat_id = body.id;

        let response = fourth_router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri("/api/v1/chats")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: Vec<Chat> = serde_json::from_slice(&body).unwrap();

        assert!(body.len() > 0);

        app.context
            .octopus_database
            .try_delete_company_by_id(company_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_chat_by_id(chat_id)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn list_401() {
        let args = Args {
            openai_api_key: None,
            port: None,
        };
        let app = app::get_app(args).await.unwrap();
        let router = app.router;
        let second_router = router.clone();
        let third_router = router.clone();
        let fourth_router = router.clone();

        let company_name = Word().fake::<String>();
        let email = SafeEmail().fake::<String>();
        let password = "password123";

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/auth/register")
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

        let response = third_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/chats")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: Chat = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);

        let chat_id = body.id;

        let response = fourth_router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri("/api/v1/chats")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        app.context
            .octopus_database
            .try_delete_company_by_id(company_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_chat_by_id(chat_id)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn read_200() {
        let args = Args {
            openai_api_key: None,
            port: None,
        };
        let app = app::get_app(args).await.unwrap();
        let router = app.router;
        let second_router = router.clone();
        let third_router = router.clone();
        let fourth_router = router.clone();

        let company_name = Word().fake::<String>();
        let email = SafeEmail().fake::<String>();
        let password = "password123";

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/auth/register")
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

        let response = third_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/chats")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: Chat = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);

        let chat_id = body.id;

        let response = fourth_router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("/api/v1/chats/{}", chat_id))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: Chat = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);

        app.context
            .octopus_database
            .try_delete_company_by_id(company_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_chat_by_id(chat_id)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn read_401() {
        let args = Args {
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

        let company_name = Word().fake::<String>();
        let email = SafeEmail().fake::<String>();
        let password = "password123";

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/auth/register")
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

        let response = third_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/chats")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: Chat = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);

        let chat_id = body.id;

        let company_name = Word().fake::<String>();
        let email = SafeEmail().fake::<String>();
        let password = "password123";

        let response = fourth_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/auth/register")
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

        let company2_id = body.company_id;
        let user_id = body.id;

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

        assert_eq!(body.user_id, user_id);

        let session_id = body.id;

        let response = sixth_router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("/api/v1/chats/{}", chat_id))
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
            .try_delete_chat_by_id(chat_id)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn read_404() {
        let args = Args {
            openai_api_key: None,
            port: None,
        };
        let app = app::get_app(args).await.unwrap();
        let router = app.router;
        let second_router = router.clone();
        let third_router = router.clone();

        let company_name = Word().fake::<String>();
        let email = SafeEmail().fake::<String>();
        let password = "password123";

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/auth/register")
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

        let chat_id = "33847746-0030-4964-a496-f75d04499160";

        let response = third_router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("/api/v1/chats/{}", chat_id))
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
            .try_delete_company_by_id(company_id)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn update_200() {
        let args = Args {
            openai_api_key: None,
            port: None,
        };
        let app = app::get_app(args).await.unwrap();
        let router = app.router;
        let second_router = router.clone();
        let third_router = router.clone();
        let fourth_router = router.clone();

        let company_name = Word().fake::<String>();
        let email = SafeEmail().fake::<String>();
        let password = "password123";

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/auth/register")
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

        let response = third_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/chats")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: Chat = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);

        let chat_id = body.id;

        let name = "updated name";

        let response = fourth_router
            .oneshot(
                Request::builder()
                    .method(http::Method::PUT)
                    .uri(format!("/api/v1/chats/{}", chat_id))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "name": &name,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: Chat = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.name.unwrap(), name);

        app.context
            .octopus_database
            .try_delete_company_by_id(company_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_chat_by_id(chat_id)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn update_401() {
        let args = Args {
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

        let company_name = Word().fake::<String>();
        let email = SafeEmail().fake::<String>();
        let password = "password123";

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/auth/register")
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

        let response = third_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/chats")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: Chat = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);

        let chat_id = body.id;

        let company_name = Word().fake::<String>();
        let email = SafeEmail().fake::<String>();
        let password = "password123";

        let response = fourth_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/auth/register")
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

        let company2_id = body.company_id;
        let user_id = body.id;

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

        assert_eq!(body.user_id, user_id);

        let session_id = body.id;

        let name = "updated name";

        let response = sixth_router
            .oneshot(
                Request::builder()
                    .method(http::Method::PUT)
                    .uri(format!("/api/v1/chats/{}", chat_id))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "name": &name,
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
            .try_delete_chat_by_id(chat_id)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn update_404() {
        let args = Args {
            openai_api_key: None,
            port: None,
        };
        let app = app::get_app(args).await.unwrap();
        let router = app.router;
        let second_router = router.clone();
        let third_router = router.clone();

        let company_name = Word().fake::<String>();
        let email = SafeEmail().fake::<String>();
        let password = "password123";

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/auth/register")
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

        let chat_id = "33847746-0030-4964-a496-f75d04499160";

        let name = "updated name";

        let response = third_router
            .oneshot(
                Request::builder()
                    .method(http::Method::PUT)
                    .uri(format!("/api/v1/chats/{}", chat_id))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "name": &name,
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
            .try_delete_company_by_id(company_id)
            .await
            .unwrap();
    }
}
