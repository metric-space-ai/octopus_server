use crate::{
    api::auth,
    canon,
    context::Context,
    error::{AppError, ResponseError},
    session::{SessionResponse, SessionResponseData},
};
use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use chrono::{Duration, Utc};
use serde::Deserialize;
use std::sync::Arc;
use utoipa::ToSchema;
use validator::Validate;

#[allow(clippy::module_name_repetitions)]
#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct LoginPost {
    #[validate(email)]
    pub email: String,
    #[validate(length(min = 8))]
    pub password: String,
}

#[axum_macros::debug_handler]
#[utoipa::path(
    post,
    path = "/api/v1/auth",
    request_body = LoginPost,
    responses(
        (status = 201, description = "User authenticated.", body = SessionResponse),
        (status = 401, description = "Unauthorized request.", body = ResponseError),
        (status = 404, description = "User not found.", body = ResponseError)
    )
)]
pub async fn login(
    State(context): State<Arc<Context>>,
    Json(input): Json<LoginPost>,
) -> Result<impl IntoResponse, AppError> {
    input.validate()?;

    let email = canon::canonicalize(&input.email);

    let hash = context
        .octopus_database
        .try_get_hash_for_email(&email)
        .await?;
    let Some(hash) = hash else {
        return Err(AppError::NotRegistered);
    };

    let is_valid = auth::verify_password(context.clone(), hash, input.password).await?;
    if !is_valid {
        return Err(AppError::Unauthorized);
    }

    let user = context
        .octopus_database
        .try_get_user_by_email(&email)
        .await?
        .ok_or(AppError::NotRegistered)?;

    if !user.is_enabled {
        return Err(AppError::Unauthorized);
    }

    let session_response_data = SessionResponseData { roles: user.roles };
    let data = serde_json::to_string(&session_response_data)?;
    let expired_at = Utc::now() + Duration::try_days(365).ok_or(AppError::FromTime)?;

    let mut transaction = context.octopus_database.transaction_begin().await?;

    let session = context
        .octopus_database
        .insert_session(&mut transaction, user.id, &data, expired_at)
        .await?;

    context
        .octopus_database
        .transaction_commit(transaction)
        .await?;

    let session_response = SessionResponse {
        id: session.id,
        user_id: session.user_id,
        data: session_response_data,
        expired_at: session.expired_at,
    };

    Ok((StatusCode::CREATED, Json(session_response)).into_response())
}

#[cfg(test)]
pub mod tests {
    use crate::{api, app, session::SessionResponse};
    use axum::{
        Router,
        body::Body,
        http::{self, Request, StatusCode},
    };
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    use uuid::Uuid;

    pub async fn login_post(
        router: Router,
        email: &str,
        password: &str,
        user_id: Uuid,
    ) -> SessionResponse {
        let response = router
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

        let body = BodyExt::collect(response.into_body())
            .await
            .unwrap()
            .to_bytes()
            .to_vec();
        let body: SessionResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);

        body
    }

    #[tokio::test]
    async fn login_201() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        login_post(router, &email, &password, user_id).await;

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
    async fn login_401() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/auth")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "email": &email,
                            "password": "wrong_password",
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
    async fn login_404() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/auth")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "email": "wrong@email.com",
                            "password": "wrong_password",
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
