use crate::{
    api::auth,
    context::Context,
    entity::{ROLE_PRIVATE_USER, ROLE_PUBLIC_USER},
    error::AppError,
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

#[axum_macros::debug_handler]
#[utoipa::path(
    post,
    path = "/api/v1/auth/register",
    request_body = RegisterPost,
    responses(
        (status = 201, description = "Account created.", body = User),
        (status = 400, description = "Bad request.", body = ResponseError),
        (status = 409, description = "Conflicting request.", body = ResponseError),
    ),
    security(
        ()
    )
)]
pub async fn register(
    State(context): State<Arc<Context>>,
    Json(input): Json<RegisterPost>,
) -> Result<impl IntoResponse, AppError> {
    input.validate()?;

    let user_exists = context
        .octopus_database
        .try_get_user_by_email(&input.email)
        .await?;

    match user_exists {
        None => {
            if input.password != input.repeat_password {
                return Err(AppError::PasswordDoesNotMatch);
            }

            let cloned_context = context.clone();
            let cloned_password = input.password.clone();
            let pw_hash = tokio::task::spawn_blocking(move || {
                auth::hash_password(cloned_context, cloned_password)
            })
            .await??;

            let company = context
                .octopus_database
                .try_get_company_primary()
                .await?
                .ok_or(AppError::CompanyNotFound)?;

            let user = context
                .octopus_database
                .insert_user(
                    company.id,
                    &input.email,
                    true,
                    context.config.pepper_id,
                    &pw_hash,
                    &[ROLE_PUBLIC_USER.to_string(), ROLE_PRIVATE_USER.to_string()],
                )
                .await?;

            context
                .octopus_database
                .insert_profile(user.id, Some(input.job_title), Some(input.name))
                .await?;

            Ok((StatusCode::CREATED, Json(user)).into_response())
        }
        Some(_user_exists) => Err(AppError::UserAlreadyExists),
    }
}

pub async fn register_with_company_id(
    State(context): State<Arc<Context>>,
    Path(company_id): Path<Uuid>,
    Json(input): Json<RegisterPost>,
) -> Result<impl IntoResponse, AppError> {
    input.validate()?;

    let user_exists = context
        .octopus_database
        .try_get_user_by_email(&input.email)
        .await?;

    match user_exists {
        None => {
            if input.password != input.repeat_password {
                return Err(AppError::PasswordDoesNotMatch);
            }

            let cloned_context = context.clone();
            let cloned_password = input.password.clone();
            let pw_hash = tokio::task::spawn_blocking(move || {
                auth::hash_password(cloned_context, cloned_password)
            })
            .await??;

            let user = context
                .octopus_database
                .insert_user(
                    company_id,
                    &input.email,
                    true,
                    context.config.pepper_id,
                    &pw_hash,
                    &[ROLE_PUBLIC_USER.to_string()],
                )
                .await?;

            context
                .octopus_database
                .insert_profile(user.id, Some(input.job_title), Some(input.name))
                .await?;

            Ok((StatusCode::CREATED, Json(user)).into_response())
        }
        Some(_user_exists) => Err(AppError::UserAlreadyExists),
    }
}

#[derive(Debug, Deserialize, ToSchema, Validate)]
pub struct RegisterPost {
    #[validate(email, length(max = 256))]
    email: String,
    #[validate(length(max = 256, min = 1))]
    job_title: String,
    #[validate(length(max = 256, min = 1))]
    name: String,
    #[validate(length(min = 8))]
    password: String,
    #[validate(length(min = 8))]
    repeat_password: String,
}

#[cfg(test)]
mod tests {
    use crate::{app, entity::User, Args};
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
    async fn register_201() {
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
    async fn register_400() {
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

        let email = format!(
            "{}{}{}",
            Word().fake::<String>(),
            Word().fake::<String>(),
            SafeEmail().fake::<String>()
        );
        let job_title = Paragraph(1..2).fake::<String>();
        let name = Name().fake::<String>();
        let password = "password123";
        let repeat_password = "password1234";

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
            .try_delete_company_by_id(company_id)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn register_409() {
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
    }
}
