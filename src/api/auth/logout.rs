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
    use crate::{app, entity::User, session::SessionResponse, Args};
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
    async fn logout_204() {
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
            .try_delete_company_by_id(company_id)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn logout_204_no_authentication() {
        let args = Args {
            openai_api_key: None,
            port: None,
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
