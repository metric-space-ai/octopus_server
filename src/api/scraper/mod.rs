use crate::{context::Context, error::AppError, scraper};
use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::Deserialize;
use std::sync::Arc;

#[derive(Deserialize)]
pub struct ScraperParameters {
    url: String,
}

#[derive(Deserialize)]
pub struct SearchParameters {
    prompt: String,
}

#[axum_macros::debug_handler]
#[utoipa::path(
    get,
    path = "/api/v1/scraper",
    responses(
        (status = 200, description = "Scraper.", body = String),
    ),
    security(
        ()
    )
)]
pub async fn scraper(
    State(context): State<Arc<Context>>,
    scraper_parameters: Query<ScraperParameters>,
) -> Result<impl IntoResponse, AppError> {
    let result = scraper::scraper(context, &scraper_parameters.url).await?;

    Ok((StatusCode::OK, result).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    get,
    path = "/api/v1/scraper-service",
    responses(
        (status = 200, description = "Scraper service.", body = String),
    ),
    security(
        ()
    )
)]
pub async fn scraper_service(
    State(context): State<Arc<Context>>,
    scraper_parameters: Query<ScraperParameters>,
) -> Result<impl IntoResponse, AppError> {
    let result = scraper::scraper_service(context, &scraper_parameters.url).await?;

    Ok((StatusCode::OK, result).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    get,
    path = "/api/v1/scraper-search-service",
    responses(
        (status = 200, description = "Scraper search service.", body = [String]),
    ),
    security(
        ()
    )
)]
pub async fn scraper_search_service(
    State(context): State<Arc<Context>>,
    search_parameters: Query<SearchParameters>,
) -> Result<impl IntoResponse, AppError> {
    let result = scraper::scraper_search_service(context, &search_parameters.prompt).await?;
    let result = result.replace('\'', "\"");
    let result: Vec<String> = serde_json::from_str(&result)?;

    Ok((StatusCode::OK, Json(result)).into_response())
}

#[cfg(test)]
mod tests {
    use crate::app;
    use axum::{
        body::Body,
        http::{self, Request, StatusCode},
    };
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    #[tokio::test]
    async fn scraper_200() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri("/api/v1/scraper?url=https://octopus-ai.app")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = BodyExt::collect(response.into_body())
            .await
            .unwrap()
            .to_bytes()
            .to_vec();
        let body = String::from_utf8(body).unwrap();

        assert_eq!("", body);
    }

    #[tokio::test]
    async fn scraper_service_200() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri("/api/v1/scraper-service?url=https://octopus-ai.app")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = BodyExt::collect(response.into_body())
            .await
            .unwrap()
            .to_bytes()
            .to_vec();
        let body = String::from_utf8(body).unwrap();

        assert_eq!("", body);
    }

    #[tokio::test]
    async fn scraper_search_service_200() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri("/api/v1/scraper-search-service?prompt=test")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = BodyExt::collect(response.into_body())
            .await
            .unwrap()
            .to_bytes()
            .to_vec();
        let body: Vec<String> = serde_json::from_slice(&body).unwrap();

        assert!(body.is_empty());
    }
}
