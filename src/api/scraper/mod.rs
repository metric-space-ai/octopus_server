use crate::{context::Context, error::AppError, scraper};
use axum::{
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
