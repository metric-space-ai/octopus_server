use crate::{
    api::auth, context::Context, email_service::send_password_reset_request_email, error::AppError,
};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use chrono::Utc;
use rand::{distributions::Alphanumeric, Rng};
use serde::Deserialize;
use std::sync::Arc;
use utoipa::ToSchema;
use validator::Validate;

#[derive(Debug, Deserialize, ToSchema, Validate)]
pub struct PasswordResetPost {
    #[validate(email, length(max = 256))]
    email: String,
}

#[derive(Debug, Deserialize, ToSchema, Validate)]
pub struct PasswordResetPut {
    #[validate(length(min = 8))]
    password: String,
    #[validate(length(min = 8))]
    repeat_password: String,
}

#[axum_macros::debug_handler]
#[utoipa::path(
    put,
    path = "/api/v1/password-resets/:token",
    request_body = PasswordResetPut,
    responses(
        (status = 200, description = "User password updated.", body = User),
        (status = 400, description = "Bad request.", body = ResponseError),
        (status = 404, description = "Password reset token not found.", body = ResponseError),
        (status = 410, description = "Resource gone.", body = ResponseError),
    ),
    security(
        ()
    )
)]
pub async fn change_password(
    State(context): State<Arc<Context>>,
    Path(token): Path<String>,
    Json(input): Json<PasswordResetPut>,
) -> Result<impl IntoResponse, AppError> {
    input.validate()?;

    if input.password != input.repeat_password {
        return Err(AppError::PasswordDoesNotMatch);
    }

    let password_reset_token = context
        .octopus_database
        .try_get_password_reset_token_by_token(&token)
        .await?
        .ok_or(AppError::NotFound)?;

    let now = Utc::now();
    if password_reset_token.expires_at < now {
        context
            .octopus_database
            .try_delete_password_reset_token_by_id(password_reset_token.id)
            .await?;

        return Err(AppError::Gone);
    }

    let cloned_context = context.clone();
    let cloned_password = input.password.clone();
    let pw_hash =
        tokio::task::spawn_blocking(move || auth::hash_password(cloned_context, cloned_password))
            .await??;

    let user = context
        .octopus_database
        .update_user_password(password_reset_token.user_id, &pw_hash)
        .await?;

    context
        .octopus_database
        .try_delete_password_reset_token_by_id(password_reset_token.id)
        .await?;

    Ok((StatusCode::OK, Json(user)).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    post,
    path = "/api/v1/password-resets",
    request_body = PasswordResetPost,
    responses(
        (status = 201, description = "Password reset token created.", body = PasswordResetToken),
        (status = 404, description = "User not found.", body = ResponseError),
        (status = 409, description = "Conflicting request.", body = ResponseError),
        (status = 410, description = "Resource gone.", body = ResponseError),
    ),
    security(
        ()
    )
)]
pub async fn request(
    State(context): State<Arc<Context>>,
    Json(input): Json<PasswordResetPost>,
) -> Result<impl IntoResponse, AppError> {
    input.validate()?;

    let user = context
        .octopus_database
        .try_get_user_by_email(&input.email)
        .await?
        .ok_or(AppError::NotFound)?;

    let password_reset_token = context
        .octopus_database
        .try_get_password_reset_token_by_user_id(user.id)
        .await?;

    if let Some(password_reset_token) = password_reset_token {
        let now = Utc::now();
        if password_reset_token.expires_at > now {
            return Err(AppError::Conflict);
        } else {
            context
                .octopus_database
                .try_delete_password_reset_token_by_id(password_reset_token.id)
                .await?;

            return Err(AppError::Gone);
        }
    }

    let mut token: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(8)
        .map(char::from)
        .collect();

    token.make_ascii_uppercase();

    let password_reset_token = context
        .octopus_database
        .insert_password_reset_token(user.id, &input.email, &token)
        .await?;

    send_password_reset_request_email(context, &input.email, &token).await?;

    Ok((StatusCode::CREATED, Json(password_reset_token)).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    get,
    path = "/api/v1/password-resets/:token",
    responses(
        (status = 200, description = "Password reset token validated.", body = PasswordResetToken),
        (status = 404, description = "Password reset token not found.", body = ResponseError),
        (status = 410, description = "Resource gone.", body = ResponseError),
    ),
    security(
        ()
    )
)]
pub async fn validate(
    State(context): State<Arc<Context>>,
    Path(token): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let password_reset_token = context
        .octopus_database
        .try_get_password_reset_token_by_token(&token)
        .await?
        .ok_or(AppError::NotFound)?;

    let now = Utc::now();
    if password_reset_token.expires_at < now {
        context
            .octopus_database
            .try_delete_password_reset_token_by_id(password_reset_token.id)
            .await?;

        return Err(AppError::Gone);
    }

    Ok((StatusCode::OK, Json(password_reset_token)).into_response())
}

#[cfg(test)]
mod tests {
    use crate::{
        app,
        entity::{PasswordResetToken, User},
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
        },
        Fake,
    };
    use tower::ServiceExt;

    #[tokio::test]
    async fn request_201() {
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
                    .uri("/api/v1/password-resets")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "email": &email,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: PasswordResetToken = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);
        assert_eq!(body.email, email);

        let password_reset_token_id = body.id;

        app.context
            .octopus_database
            .try_delete_password_reset_token_by_id(password_reset_token_id)
            .await
            .unwrap();

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
    async fn request_404() {
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

        let email = "wrong@email.com";

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/password-resets")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "email": &email,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn request_409() {
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
                    .uri("/api/v1/password-resets")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "email": &email,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: PasswordResetToken = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);
        assert_eq!(body.email, email);

        let password_reset_token_id = body.id;

        let response = third_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/password-resets")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "email": &email,
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
            .try_delete_password_reset_token_by_id(password_reset_token_id)
            .await
            .unwrap();

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
    async fn request_410() {
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
                    .uri("/api/v1/password-resets")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "email": &email,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: PasswordResetToken = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);
        assert_eq!(body.email, email);

        let password_reset_token_id = body.id;

        app.context
            .octopus_database
            .expire_password_reset_token(password_reset_token_id)
            .await
            .unwrap();

        let response = third_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/password-resets")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "email": &email,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert!(response.status() == StatusCode::GONE || response.status() == StatusCode::CONFLICT);

        app.context
            .octopus_database
            .try_delete_password_reset_token_by_id(password_reset_token_id)
            .await
            .unwrap();

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
    async fn validate_200() {
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
                    .uri("/api/v1/password-resets")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "email": &email,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: PasswordResetToken = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);
        assert_eq!(body.email, email);

        let password_reset_token_id = body.id;

        let token = app
            .context
            .octopus_database
            .try_get_password_reset_token_token_by_id(password_reset_token_id)
            .await
            .unwrap()
            .unwrap();

        let response = third_router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("/api/v1/password-resets/{token}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: PasswordResetToken = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);
        assert_eq!(body.email, email);

        app.context
            .octopus_database
            .try_delete_password_reset_token_by_id(password_reset_token_id)
            .await
            .unwrap();

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
    async fn validate_404() {
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

        let token = "WRONGTOKEN";

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("/api/v1/password-resets/{token}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn validate_410() {
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
                    .uri("/api/v1/password-resets")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "email": &email,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: PasswordResetToken = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);
        assert_eq!(body.email, email);

        let password_reset_token_id = body.id;

        let token = app
            .context
            .octopus_database
            .try_get_password_reset_token_token_by_id(password_reset_token_id)
            .await
            .unwrap()
            .unwrap();

        app.context
            .octopus_database
            .expire_password_reset_token(password_reset_token_id)
            .await
            .unwrap();

        let response = third_router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("/api/v1/password-resets/{token}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert!(response.status() == StatusCode::GONE || response.status() == StatusCode::OK);

        app.context
            .octopus_database
            .try_delete_password_reset_token_by_id(password_reset_token_id)
            .await
            .unwrap();

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
    async fn change_password_200() {
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
                    .uri("/api/v1/password-resets")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "email": &email,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: PasswordResetToken = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);
        assert_eq!(body.email, email);

        let password_reset_token_id = body.id;

        let token = app
            .context
            .octopus_database
            .try_get_password_reset_token_token_by_id(password_reset_token_id)
            .await
            .unwrap()
            .unwrap();

        let response = third_router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("/api/v1/password-resets/{token}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: PasswordResetToken = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);
        assert_eq!(body.email, email);

        let new_password = "newpassword123";

        let response = fourth_router
            .oneshot(
                Request::builder()
                    .method(http::Method::PUT)
                    .uri(format!("/api/v1/password-resets/{token}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "password": &new_password,
                            "repeat_password": &new_password,
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

        assert_eq!(body.id, user_id);
        assert_eq!(body.email, email);

        let response = fifth_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/auth")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "email": &email,
                            "password": &new_password,
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

        app.context
            .octopus_database
            .try_delete_password_reset_token_by_id(password_reset_token_id)
            .await
            .unwrap();

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
    async fn change_password_400() {
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
                    .uri("/api/v1/password-resets")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "email": &email,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: PasswordResetToken = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);
        assert_eq!(body.email, email);

        let password_reset_token_id = body.id;

        let token = app
            .context
            .octopus_database
            .try_get_password_reset_token_token_by_id(password_reset_token_id)
            .await
            .unwrap()
            .unwrap();

        let response = third_router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("/api/v1/password-resets/{token}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: PasswordResetToken = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);
        assert_eq!(body.email, email);

        let new_password = "newpassword123";

        let response = fourth_router
            .oneshot(
                Request::builder()
                    .method(http::Method::PUT)
                    .uri(format!("/api/v1/password-resets/{token}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "password": &new_password,
                            "repeat_password": "bad",
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
            .try_delete_password_reset_token_by_id(password_reset_token_id)
            .await
            .unwrap();

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
    async fn change_password_404() {
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

        let token = "WRONGTOKEN";
        let new_password = "newpassword123";

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::PUT)
                    .uri(format!("/api/v1/password-resets/{token}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "password": &new_password,
                            "repeat_password": &new_password,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn change_password_410() {
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
                    .uri("/api/v1/password-resets")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "email": &email,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: PasswordResetToken = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);
        assert_eq!(body.email, email);

        let password_reset_token_id = body.id;

        let token = app
            .context
            .octopus_database
            .try_get_password_reset_token_token_by_id(password_reset_token_id)
            .await
            .unwrap()
            .unwrap();

        let response = third_router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("/api/v1/password-resets/{token}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: PasswordResetToken = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);
        assert_eq!(body.email, email);

        app.context
            .octopus_database
            .expire_password_reset_token(password_reset_token_id)
            .await
            .unwrap();

        let new_password = "newpassword123";

        let response = fourth_router
            .oneshot(
                Request::builder()
                    .method(http::Method::PUT)
                    .uri(format!("/api/v1/password-resets/{token}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "password": &new_password,
                            "repeat_password": &new_password,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert!(response.status() == StatusCode::GONE || response.status() == StatusCode::OK);

        app.context
            .octopus_database
            .try_delete_password_reset_token_by_id(password_reset_token_id)
            .await
            .unwrap();

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
