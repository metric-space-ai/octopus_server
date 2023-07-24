use crate::{
    api::auth,
    context::Context,
    entity::ROLE_COMPANY_ADMIN,
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

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct ChangePasswordPut {
    old_password: Option<String>,
    #[validate(length(min = 8))]
    password: String,
    #[validate(length(min = 8))]
    repeat_password: String,
}

#[axum_macros::debug_handler]
#[utoipa::path(
    put,
    path = "/api/v1/auth/:user_id",
    request_body = ChangePasswordPut,
    params(
        ("user_id" = String, Path, description = "User id")
    ),
    responses(
        (status = 200, description = "User password updated.", body = User),
        (status = 400, description = "Bad request.", body = ResponseError),
        (status = 401, description = "Unauthorized request.", body = ResponseError),
        (status = 404, description = "User not found.", body = ResponseError)
    )
)]
pub async fn change_password(
    State(context): State<Arc<Context>>,
    extracted_session: ExtractedSession,
    Path(user_id): Path<Uuid>,
    Json(input): Json<ChangePasswordPut>,
) -> Result<impl IntoResponse, AppError> {
    let session = require_authenticated_session(extracted_session).await?;

    input.validate()?;

    let session_user = context
        .octopus_database
        .try_get_user_by_id(session.user_id)
        .await?
        .ok_or(AppError::Unauthorized)?;

    let user = context
        .octopus_database
        .try_get_user_by_id(user_id)
        .await?
        .ok_or(AppError::NotFound)?;

    if session_user.id != user_id
        && (!session_user.roles.contains(&ROLE_COMPANY_ADMIN.to_string())
            || session_user.company_id != user.company_id)
    {
        return Err(AppError::Unauthorized);
    }

    if input.password != input.repeat_password {
        return Err(AppError::PasswordDoesNotMatch);
    }

    let cloned_context = context.clone();
    let cloned_password = input.password.clone();
    let pw_hash =
        tokio::task::spawn_blocking(move || auth::hash_password(cloned_context, cloned_password))
            .await??;

    if session_user.id == user_id {
        let hash = context
            .octopus_database
            .try_get_hash_for_user_id(user_id)
            .await?;
        let Some(hash) = hash else { return Err(AppError::NotRegistered) };

        let old_password = input.old_password.ok_or(AppError::Unauthorized)?;
        let is_valid = auth::verify_password(context.clone(), hash, old_password).await?;
        if !is_valid {
            return Err(AppError::Unauthorized);
        }

        let user = context
            .octopus_database
            .update_user_password(user_id, &pw_hash)
            .await?;

        Ok((StatusCode::OK, Json(user)).into_response())
    } else if session_user.roles.contains(&ROLE_COMPANY_ADMIN.to_string()) {
        let user = context
            .octopus_database
            .update_user_password(user_id, &pw_hash)
            .await?;

        Ok((StatusCode::OK, Json(user)).into_response())
    } else {
        Err(AppError::Unauthorized)
    }
}

#[cfg(test)]
mod tests {
    use crate::{app, entity::User, session::SessionResponse, Args};
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
                    .uri("/api/v1/auth/register-company")
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

        let session_id = body.id;

        let old_password = "password123";
        let password = "passwordABC";
        let repeat_password = "passwordABC";

        let response = fourth_router
            .oneshot(
                Request::builder()
                    .method(http::Method::PUT)
                    .uri(format!("/api/v1/auth/{user2_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "old_password": &old_password,
                            "password": &password,
                            "repeat_password": &repeat_password,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: User = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.id, user2_id);

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
    async fn update_200_company_admin() {
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
                    .uri("/api/v1/auth/register-company")
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

        let admin_session_id = body.id;

        let email = format!(
            "{}{}{}",
            Word().fake::<String>(),
            Word().fake::<String>(),
            SafeEmail().fake::<String>()
        );
        let job_title = Paragraph(1..2).fake::<String>();
        let name = Name().fake::<String>();
        let password = "password123";

        let response = third_router
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

        let password = "passwordABC";
        let repeat_password = "passwordABC";

        let response = fourth_router
            .oneshot(
                Request::builder()
                    .method(http::Method::PUT)
                    .uri(format!("/api/v1/auth/{user2_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), admin_session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "password": &password,
                            "repeat_password": &repeat_password,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: User = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.id, user2_id);

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
    async fn update_400() {
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
                    .uri("/api/v1/auth/register-company")
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

        let session_id = body.id;

        let old_password = "password123";
        let password = "passwordABC";
        let repeat_password = "passwordABC123";

        let response = fourth_router
            .oneshot(
                Request::builder()
                    .method(http::Method::PUT)
                    .uri(format!("/api/v1/auth/{user2_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "old_password": &old_password,
                            "password": &password,
                            "repeat_password": &repeat_password,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

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
                    .uri("/api/v1/auth/register-company")
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

        let session_id = body.id;

        let old_password = "password123";
        let password = "passwordABC";
        let repeat_password = "passwordABC";

        let response = fourth_router
            .oneshot(
                Request::builder()
                    .method(http::Method::PUT)
                    .uri(format!("/api/v1/auth/{user_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "old_password": &old_password,
                            "password": &password,
                            "repeat_password": &repeat_password,
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
    async fn update_401_different_company_admin() {
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
                    .uri("/api/v1/auth/register-company")
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

        let company_name = Paragraph(1..2).fake::<String>();
        let email = format!(
            "{}{}{}",
            Word().fake::<String>(),
            Word().fake::<String>(),
            SafeEmail().fake::<String>()
        );
        let password = "password123";

        let response = second_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/auth/register-company")
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

        let session_id = body.id;

        let password = "passwordABC";
        let repeat_password = "passwordABC";

        let response = fourth_router
            .oneshot(
                Request::builder()
                    .method(http::Method::PUT)
                    .uri(format!("/api/v1/auth/{user_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "password": &password,
                            "repeat_password": &repeat_password,
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
                    .uri("/api/v1/auth/register-company")
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

        let session_id = body.id;

        let user2_id = "33847746-0030-4964-a496-f75d04499160";

        let password = "passwordABC";
        let repeat_password = "passwordABC";

        let response = third_router
            .oneshot(
                Request::builder()
                    .method(http::Method::PUT)
                    .uri(format!("/api/v1/auth/{user2_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "password": &password,
                            "repeat_password": &repeat_password,
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
