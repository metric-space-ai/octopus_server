use crate::{
    ai::{update_chat_message_with_file_response, AiFunctionResponseFile},
    context::Context,
    entity::{AiFunction, ChatMessage},
    error::AppError,
    Result,
};
use axum::http::StatusCode;
use http::header::CONTENT_TYPE;
use serde::Serialize;
use serde_json::value::Value;
use std::sync::Arc;
use tokio::time::{sleep, Duration};

#[derive(Debug, Serialize)]
pub struct FunctionOrbitCameraPost {
    pub device_map: serde_json::Value,
    pub position: u64,
    pub tilt: String,
    pub zoom: String,
    pub resolution: String,
}

pub async fn handle_function_orbit_camera(
    ai_function: &AiFunction,
    chat_message: &ChatMessage,
    context: Arc<Context>,
    function_args: &Value,
) -> Result<Option<ChatMessage>> {
    let position = function_args["position"]
        .as_u64()
        .ok_or(AppError::Casting)?;
    let tilt = function_args["tilt"].as_str().ok_or(AppError::Casting)?;
    let zoom = function_args["zoom"].as_str().ok_or(AppError::Casting)?;
    let resolution = function_args["resolution"]
        .as_str()
        .ok_or(AppError::Casting)?;
    let mut failed_connection_attempts = 0;

    loop {
        let response = function_orbit_camera(ai_function, position, tilt, zoom, resolution).await?;
        if let Some(response) = response {
            let chat_message: ChatMessage = update_chat_message_with_file_response(
                ai_function,
                &response,
                context.clone(),
                chat_message,
            )
            .await?;

            return Ok(Some(chat_message));
        } else {
            failed_connection_attempts += 1;

            if failed_connection_attempts > 10 {
                break;
            }

            sleep(Duration::from_secs(2)).await;
        }
    }

    Ok(None)
}

async fn function_orbit_camera(
    ai_function: &AiFunction,
    position: u64,
    tilt: &str,
    zoom: &str,
    resolution: &str,
) -> Result<Option<AiFunctionResponseFile>> {
    let function_orbit_camera_post = FunctionOrbitCameraPost {
        device_map: ai_function.device_map.clone(),
        position,
        tilt: tilt.to_string(),
        zoom: zoom.to_string(),
        resolution: resolution.to_string(),
    };

    let response = reqwest::Client::new()
        .post(ai_function.base_function_url.clone())
        .json(&function_orbit_camera_post)
        .send()
        .await;

    if let Ok(response) = response {
        if response.status() == StatusCode::CREATED {
            let headers_map = response.headers();
            let content_type_header = headers_map.get(CONTENT_TYPE).ok_or(AppError::File)?;
            let media_type = content_type_header.to_str()?.to_string();
            let content = response.bytes().await?;

            let ai_function_response_file = AiFunctionResponseFile {
                content,
                media_type,
            };

            return Ok(Some(ai_function_response_file));
        }
    }

    Ok(None)
}
