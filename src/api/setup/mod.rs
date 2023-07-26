use crate::{
    api::auth,
    context::Context,
    entity::{WorkspacesType, ROLE_COMPANY_ADMIN_USER, ROLE_PRIVATE_USER, ROLE_PUBLIC_USER},
    error::AppError,
};
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use utoipa::ToSchema;
use validator::Validate;

#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct SetupInfoResponse {
    setup_required: bool,
}

#[axum_macros::debug_handler]
#[utoipa::path(
    get,
    path = "/api/v1/setup",
    responses(
        (status = 200, description = "Setup info read.", body = SetupInfoResponse),
    ),
    security(
        ()
    )
)]
pub async fn info(State(context): State<Arc<Context>>) -> Result<impl IntoResponse, AppError> {
    let companies = context.octopus_database.get_companies().await?;

    let setup_info_response = SetupInfoResponse {
        setup_required: companies.is_empty(),
    };

    Ok((StatusCode::OK, Json(setup_info_response)).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    post,
    path = "/api/v1/setup",
    request_body = SetupPost,
    responses(
        (status = 201, description = "Account created.", body = User),
        (status = 400, description = "Bad request.", body = ResponseError),
        (status = 409, description = "Conflicting request.", body = ResponseError),
    ),
    security(
        ()
    )
)]
pub async fn setup(
    State(context): State<Arc<Context>>,
    Json(input): Json<SetupPost>,
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
                        ROLE_COMPANY_ADMIN_USER.to_string(),
                        ROLE_PRIVATE_USER.to_string(),
                        ROLE_PUBLIC_USER.to_string(),
                    ],
                )
                .await?;

            context
                .octopus_database
                .insert_profile(user.id, None, None)
                .await?;

            context
                .octopus_database
                .insert_workspace(
                    user.company_id,
                    user.id,
                    "Public Group",
                    WorkspacesType::Public,
                )
                .await?;

            let example_prompts = context.octopus_database.get_example_prompts().await?;

            if example_prompts.is_empty() {
                let example_prompts = vec![
                    "How can I optimize the assembly line process to improve efficiency and reduce errors?",
                    "Provide me with safety guidelines for operating heavy machinery in the factory.",
                    "What are the best practices for quality control during the production process?",
                    "How can I troubleshoot common technical issues with the machinery on the factory floor?",
                    "Suggest ways to minimize waste and promote sustainability in our manufacturing processes.",
                    "What are the latest advancements in automation that could be implemented in our factory?",
                    "Help me understand the new regulatory requirements and compliance standards relevant to our industry.",
                    "Recommend training programs or courses to enhance my skills as a factory worker.",
                    "Assist me in conducting a risk assessment for our production line to identify potential hazards.",
                    "How can I improve communication and collaboration among team members on the factory floor?",
                ];

                for example_prompt in example_prompts {
                    context
                        .octopus_database
                        .insert_example_prompt(true, 0, example_prompt)
                        .await?;
                }
            }

            Ok((StatusCode::CREATED, Json(user)).into_response())
        }
        Some(_user_exists) => Err(AppError::UserAlreadyExists),
    }
}

#[derive(Debug, Deserialize, ToSchema, Validate)]
pub struct SetupPost {
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
    use crate::{api::setup::SetupInfoResponse, app, entity::User, Args};
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
    async fn info_200() {
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

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri("/api/v1/setup")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: SetupInfoResponse = serde_json::from_slice(&body).unwrap();

        assert!(body.setup_required == true || body.setup_required == false);

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

        let response = third_router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri("/api/v1/setup")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: SetupInfoResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.setup_required, false);

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
    async fn register_201() {
        let args = Args {
            database_url: Some(String::from(
                "postgres://admin:admin@db/octopus_server_test",
            )),
            openai_api_key: None,
            port: None,
        };
        let app = app::get_app(args).await.unwrap();
        let router = app.router;

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
            database_url: Some(String::from(
                "postgres://admin:admin@db/octopus_server_test",
            )),
            openai_api_key: None,
            port: None,
        };
        let app = app::get_app(args).await.unwrap();
        let router = app.router;

        let company_name = Paragraph(1..2).fake::<String>();
        let email = format!(
            "{}{}{}",
            Word().fake::<String>(),
            Word().fake::<String>(),
            SafeEmail().fake::<String>()
        );
        let password = "password123";
        let repeat_password = "password1234";

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
                            "repeat_password": &repeat_password,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn register_409() {
        let args = Args {
            database_url: Some(String::from(
                "postgres://admin:admin@db/octopus_server_test",
            )),
            openai_api_key: None,
            port: None,
        };
        let app = app::get_app(args).await.unwrap();
        let router = app.router;
        let cloned_router = router.clone();

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

        let response = cloned_router
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
