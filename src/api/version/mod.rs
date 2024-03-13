use crate::error::AppError;
use axum::{http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct VersionInfoResponse {
    version: String,
}

#[axum_macros::debug_handler]
#[utoipa::path(
    get,
    path = "/api/v1/version",
    responses(
        (status = 200, description = "Version info read.", body = VersionInfoResponse),
    ),
    security(
        ()
    )
)]
pub async fn info() -> Result<impl IntoResponse, AppError> {
    let version = env!("CARGO_PKG_VERSION").to_string();
    let version = format!("v{version}");
    let version_info_response = VersionInfoResponse { version };

    Ok((StatusCode::OK, Json(version_info_response)).into_response())
}

#[cfg(test)]
pub mod tests {
    use crate::app;
    use axum::{
        body::Body,
        http::{self, Request, StatusCode},
    };
    use tower::ServiceExt;

    #[tokio::test]
    async fn info_200() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri("/api/v1/version")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }
}
