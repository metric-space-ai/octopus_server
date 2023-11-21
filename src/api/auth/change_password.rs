use crate::{
    api::auth,
    context::Context,
    entity::ROLE_COMPANY_ADMIN_USER,
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
        (status = 401, description = "Unauthorized.", body = ResponseError),
        (status = 403, description = "Forbidden.", body = ResponseError),
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
        .ok_or(AppError::Forbidden)?;

    let user = context
        .octopus_database
        .try_get_user_by_id(user_id)
        .await?
        .ok_or(AppError::NotFound)?;

    if session_user.id != user_id
        && (!session_user
            .roles
            .contains(&ROLE_COMPANY_ADMIN_USER.to_string())
            || session_user.company_id != user.company_id)
    {
        return Err(AppError::Forbidden);
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
        let Some(hash) = hash else {
            return Err(AppError::NotRegistered);
        };

        let old_password = input.old_password.ok_or(AppError::Forbidden)?;
        let is_valid = auth::verify_password(context.clone(), hash, old_password).await?;
        if !is_valid {
            return Err(AppError::Forbidden);
        }

        let mut transaction = context.octopus_database.transaction_begin().await?;

        let user = context
            .octopus_database
            .update_user_password(&mut transaction, user_id, &pw_hash)
            .await?;

        context
            .octopus_database
            .transaction_commit(transaction)
            .await?;

        Ok((StatusCode::OK, Json(user)).into_response())
    } else if session_user
        .roles
        .contains(&ROLE_COMPANY_ADMIN_USER.to_string())
    {
        let mut transaction = context.octopus_database.transaction_begin().await?;

        let user = context
            .octopus_database
            .update_user_password(&mut transaction, user_id, &pw_hash)
            .await?;

        context
            .octopus_database
            .transaction_commit(transaction)
            .await?;

        Ok((StatusCode::OK, Json(user)).into_response())
    } else {
        Err(AppError::Forbidden)
    }
}

#[cfg(test)]
mod tests {
    use crate::{api, app, entity::User, Args};
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
            azure_openai_api_key: None,
            azure_openai_deployment_id: None,
            azure_openai_enabled: Some(true),
            database_url: Some(String::from(
                "postgres://admin:admin@db/octopus_server_test",
            )),
            openai_api_key: None,
            port: None,
            test_mode: Some(true),
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

        let user = api::setup::tests::setup_post(router, &company_name, &email, password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let email = format!(
            "{}{}{}",
            Word().fake::<String>(),
            Word().fake::<String>(),
            SafeEmail().fake::<String>()
        );
        let job_title = Paragraph(1..2).fake::<String>();
        let name = Name().fake::<String>();
        let password = "password123";

        let user = api::auth::register::tests::register_with_company_id_post(
            second_router,
            company_id,
            &email,
            &job_title,
            &name,
            password,
        )
        .await;
        let second_user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(third_router, &email, password, second_user_id)
                .await;
        let session_id = session_response.id;

        let old_password = "password123";
        let password = "passwordABC";
        let repeat_password = "passwordABC";

        let response = fourth_router
            .oneshot(
                Request::builder()
                    .method(http::Method::PUT)
                    .uri(format!("/api/v1/auth/{second_user_id}"))
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

        assert_eq!(body.id, second_user_id);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_user_by_id(&mut transaction, user_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_user_by_id(&mut transaction, second_user_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_company_by_id(&mut transaction, company_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .transaction_commit(transaction)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn update_200_company_admin() {
        let args = Args {
            azure_openai_api_key: None,
            azure_openai_deployment_id: None,
            azure_openai_enabled: Some(true),
            database_url: Some(String::from(
                "postgres://admin:admin@db/octopus_server_test",
            )),
            openai_api_key: None,
            port: None,
            test_mode: Some(true),
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

        let user = api::setup::tests::setup_post(router, &company_name, &email, password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(second_router, &email, password, user_id).await;
        let admin_session_id = session_response.id;

        let email = format!(
            "{}{}{}",
            Word().fake::<String>(),
            Word().fake::<String>(),
            SafeEmail().fake::<String>()
        );
        let job_title = Paragraph(1..2).fake::<String>();
        let name = Name().fake::<String>();
        let password = "password123";

        let user = api::auth::register::tests::register_with_company_id_post(
            third_router,
            company_id,
            &email,
            &job_title,
            &name,
            password,
        )
        .await;
        let second_user_id = user.id;

        let password = "passwordABC";
        let repeat_password = "passwordABC";

        let response = fourth_router
            .oneshot(
                Request::builder()
                    .method(http::Method::PUT)
                    .uri(format!("/api/v1/auth/{second_user_id}"))
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

        assert_eq!(body.id, second_user_id);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_user_by_id(&mut transaction, user_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_user_by_id(&mut transaction, second_user_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_company_by_id(&mut transaction, company_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .transaction_commit(transaction)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn update_400() {
        let args = Args {
            azure_openai_api_key: None,
            azure_openai_deployment_id: None,
            azure_openai_enabled: Some(true),
            database_url: Some(String::from(
                "postgres://admin:admin@db/octopus_server_test",
            )),
            openai_api_key: None,
            port: None,
            test_mode: Some(true),
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

        let user = api::setup::tests::setup_post(router, &company_name, &email, password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let email = format!(
            "{}{}{}",
            Word().fake::<String>(),
            Word().fake::<String>(),
            SafeEmail().fake::<String>()
        );
        let job_title = Paragraph(1..2).fake::<String>();
        let name = Name().fake::<String>();
        let password = "password123";

        let user = api::auth::register::tests::register_with_company_id_post(
            second_router,
            company_id,
            &email,
            &job_title,
            &name,
            password,
        )
        .await;
        let second_user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(third_router, &email, password, second_user_id)
                .await;
        let session_id = session_response.id;

        let old_password = "password123";
        let password = "passwordABC";
        let repeat_password = "passwordABC123";

        let response = fourth_router
            .oneshot(
                Request::builder()
                    .method(http::Method::PUT)
                    .uri(format!("/api/v1/auth/{second_user_id}"))
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

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_user_by_id(&mut transaction, user_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_user_by_id(&mut transaction, second_user_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_company_by_id(&mut transaction, company_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .transaction_commit(transaction)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn update_401() {
        let args = Args {
            azure_openai_api_key: None,
            azure_openai_deployment_id: None,
            azure_openai_enabled: Some(true),
            database_url: Some(String::from(
                "postgres://admin:admin@db/octopus_server_test",
            )),
            openai_api_key: None,
            port: None,
            test_mode: Some(true),
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

        let user = api::setup::tests::setup_post(router, &company_name, &email, password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let email = format!(
            "{}{}{}",
            Word().fake::<String>(),
            Word().fake::<String>(),
            SafeEmail().fake::<String>()
        );
        let job_title = Paragraph(1..2).fake::<String>();
        let name = Name().fake::<String>();
        let password = "password123";

        let user = api::auth::register::tests::register_with_company_id_post(
            second_router,
            company_id,
            &email,
            &job_title,
            &name,
            password,
        )
        .await;
        let second_user_id = user.id;

        api::auth::login::tests::login_post(third_router, &email, password, second_user_id).await;

        let old_password = "password123";
        let password = "passwordABC";
        let repeat_password = "passwordABC";

        let response = fourth_router
            .oneshot(
                Request::builder()
                    .method(http::Method::PUT)
                    .uri(format!("/api/v1/auth/{second_user_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
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

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_user_by_id(&mut transaction, user_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_user_by_id(&mut transaction, second_user_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_company_by_id(&mut transaction, company_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .transaction_commit(transaction)
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
            test_mode: Some(true),
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

        let user = api::setup::tests::setup_post(router, &company_name, &email, password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let email = format!(
            "{}{}{}",
            Word().fake::<String>(),
            Word().fake::<String>(),
            SafeEmail().fake::<String>()
        );
        let job_title = Paragraph(1..2).fake::<String>();
        let name = Name().fake::<String>();
        let password = "password123";

        let user = api::auth::register::tests::register_with_company_id_post(
            second_router,
            company_id,
            &email,
            &job_title,
            &name,
            password,
        )
        .await;
        let second_user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(third_router, &email, password, second_user_id)
                .await;
        let session_id = session_response.id;

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

        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_user_by_id(&mut transaction, user_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_user_by_id(&mut transaction, second_user_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_company_by_id(&mut transaction, company_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .transaction_commit(transaction)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn update_403_different_company_admin() {
        let args = Args {
            azure_openai_api_key: None,
            azure_openai_deployment_id: None,
            azure_openai_enabled: Some(true),
            database_url: Some(String::from(
                "postgres://admin:admin@db/octopus_server_test",
            )),
            openai_api_key: None,
            port: None,
            test_mode: Some(true),
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

        let user = api::setup::tests::setup_post(router, &company_name, &email, password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let company_name = Paragraph(1..2).fake::<String>();
        let email = format!(
            "{}{}{}",
            Word().fake::<String>(),
            Word().fake::<String>(),
            SafeEmail().fake::<String>()
        );
        let password = "password123";

        let user =
            api::setup::tests::setup_post(second_router, &company_name, &email, password).await;
        let second_company_id = user.company_id;
        let second_user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(third_router, &email, password, second_user_id)
                .await;
        let session_id = session_response.id;

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

        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_user_by_id(&mut transaction, user_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_user_by_id(&mut transaction, second_user_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_company_by_id(&mut transaction, company_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_company_by_id(&mut transaction, second_company_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .transaction_commit(transaction)
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
            test_mode: Some(true),
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

        let user = api::setup::tests::setup_post(router, &company_name, &email, password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(second_router, &email, password, user_id).await;
        let session_id = session_response.id;

        let second_user_id = "33847746-0030-4964-a496-f75d04499160";

        let password = "passwordABC";
        let repeat_password = "passwordABC";

        let response = third_router
            .oneshot(
                Request::builder()
                    .method(http::Method::PUT)
                    .uri(format!("/api/v1/auth/{second_user_id}"))
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

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_user_by_id(&mut transaction, user_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_company_by_id(&mut transaction, company_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .transaction_commit(transaction)
            .await
            .unwrap();
    }
}
