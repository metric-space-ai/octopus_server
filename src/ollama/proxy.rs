use crate::{context::Context, error::AppError, Result};
use axum::{
    body::Body,
    extract::Request,
    http::{Method, StatusCode},
    response::{IntoResponse, Json, Response},
};
use http_body_util::BodyExt;
use std::{str::FromStr, sync::Arc};

pub async fn request(
    context: Arc<Context>,
    pass: Option<String>,
    request: Request<Body>,
) -> Result<Response> {
    if !context.get_config().await?.test_mode {
        let ollama_host = context.get_config().await?.ollama_host;

        if let Some(ollama_host) = ollama_host {
            let url = match pass.clone() {
                None => ollama_host,
                Some(ref pass) => format!("{ollama_host}/{pass}"),
            };

            let client = reqwest::Client::new();

            let method = request.method().clone();

            let request_builder = match method {
                Method::DELETE => client.delete(url.clone()),
                Method::POST => client.post(url.clone()),
                Method::PUT => client.put(url.clone()),
                _ => client.get(url.clone()),
            };

            let body = BodyExt::collect(request.into_body())
                .await?
                .to_bytes()
                .to_vec();
            let body = String::from_utf8(body.clone())?;

            let request_builder = match method {
                Method::POST | Method::PUT => request_builder
                    .header(
                        reqwest::header::CONTENT_TYPE,
                        mime::APPLICATION_JSON.as_ref(),
                    )
                    .body(body),
                _ => request_builder,
            };

            let response = request_builder.send().await?;

            let status_code = format!("{}", response.status().as_u16());
            let status_code = StatusCode::from_str(&status_code)?;

            let content_type = response
                .headers()
                .get("Content-Type")
                .ok_or(AppError::Conflict)?
                .to_str()?;

            match content_type {
                "application/json" => {
                    let bytes = response.bytes().await?.to_vec();
                    let body: serde_json::Value = serde_json::from_slice(&bytes)?;
                    let response = (status_code, Json(body)).into_response();

                    return Ok(response);
                }
                "application/json; charset=utf-8" => {
                    let bytes = response.bytes().await?.to_vec();
                    let body: serde_json::Value = serde_json::from_slice(&bytes)?;
                    let response = (status_code, Json(body)).into_response();

                    return Ok(response);
                }
                "application/x-ndjson" => {
                    let bytes = response.bytes().await?.to_vec();
                    let mut last_line = vec![];
                    let mut skipped_first_lf = false;

                    for byte in bytes.into_iter().rev() {
                        if byte == 10 && !skipped_first_lf {
                            skipped_first_lf = true;
                        } else if byte == 10 {
                            break;
                        }

                        last_line.push(byte);
                    }

                    last_line = last_line.into_iter().rev().collect();

                    let body: serde_json::Value = serde_json::from_slice(&last_line)?;
                    let response = (status_code, Json(body)).into_response();

                    return Ok(response);
                }
                &_ => {
                    let response = (StatusCode::OK, Json("{}")).into_response();

                    return Ok(response);
                }
            }
        }
    }

    let response = (StatusCode::OK, Json("{}")).into_response();

    Ok(response)
}
