use crate::{api::auth, context::Context, error::AppError};
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::Deserialize;
use std::sync::Arc;
use utoipa::ToSchema;
use validator::Validate;

#[axum_macros::debug_handler]
#[utoipa::path(
    post,
    path = "/api/v1/auth/register-company",
    request_body = RegisterCompanyPost,
    responses(
        (status = 201, description = "Account created.", body = User),
        (status = 400, description = "Bad request.", body = ResponseError),
    ),
    security(
        ()
    )
)]
pub async fn register_company(
    State(context): State<Arc<Context>>,
    Json(input): Json<RegisterCompanyPost>,
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
                .insert_company(None, &input.company_name)
                .await?;

            let user = context
                .octopus_database
                .insert_user(
                    company.id,
                    &input.email,
                    true,
                    context.config.pepper_id,
                    &pw_hash,
                    &[
                        "ROLE_COMPANY_ADMIN".to_string(),
                        "ROLE_PRIVATE_USER".to_string(),
                        "ROLE_PUBLIC_USER".to_string(),
                    ],
                    None,
                    None,
                )
                .await?;

            Ok((StatusCode::CREATED, Json(user)).into_response())
        }
        Some(_user_exists) => Err(AppError::UserAlreadyExists),
    }
}

#[derive(Debug, Deserialize, ToSchema, Validate)]
pub struct RegisterCompanyPost {
    #[validate(length(max = 256, min = 1))]
    company_name: String,
    #[validate(email, length(max = 256))]
    email: String,
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
        faker::{internet::en::SafeEmail, lorem::en::Word},
        Fake,
    };
    use tower::ServiceExt;

    #[tokio::test]
    async fn register_201() {
        let args = Args {
            openai_api_key: None,
            port: None,
        };
        let app = app::get_app(args).await.unwrap();
        let router = app.router;

        let company_name = Word().fake::<String>();
        let email = SafeEmail().fake::<String>();
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

        app.context
            .octopus_database
            .try_delete_company_by_id(company_id)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn register_400() {
        let args = Args {
            openai_api_key: None,
            port: None,
        };
        let app = app::get_app(args).await.unwrap();
        let router = app.router;
        let cloned_router = router.clone();

        let company_name = Word().fake::<String>();
        let email = SafeEmail().fake::<String>();
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

        let response = cloned_router
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

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        app.context
            .octopus_database
            .try_delete_company_by_id(company_id)
            .await
            .unwrap();
    }
}
