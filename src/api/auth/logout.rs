use crate::{context::Context, error::AppError};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use std::{str::FromStr, sync::Arc};
use uuid::Uuid;

#[axum_macros::debug_handler]
#[utoipa::path(
    delete,
    path = "/api/v1/auth",
    responses(
        (status = 204, description = "User logged out.")
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn logout(
    State(context): State<Arc<Context>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, AppError> {
    let token = headers.get("X-Auth-Token");

    if let Some(token) = token {
        let session_id = Uuid::from_str(token.to_str()?)?;

        context
            .octopus_database
            .try_delete_session_by_id(session_id)
            .await?;
    }

    Ok((StatusCode::NO_CONTENT, ()).into_response())
}

#[cfg(test)]
mod tests {
    use crate::{api, app, Args};
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
    async fn logout_204() {
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
        let session_id = session_response.id;

        let response = third_router
            .oneshot(
                Request::builder()
                    .method(http::Method::DELETE)
                    .uri("/api/v1/auth")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let response = fourth_router
            .oneshot(
                Request::builder()
                    .method(http::Method::DELETE)
                    .uri("/api/v1/auth")
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
    async fn logout_204_no_authentication() {
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

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::DELETE)
                    .uri("/api/v1/auth")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }
}
