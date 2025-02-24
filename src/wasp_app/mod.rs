use crate::{Result, context::Context, error::AppError};
use axum::{
    body::Body,
    extract::{
        Request,
        ws::{Message as AxumMessage, WebSocket},
    },
    http::{HeaderValue, Method, StatusCode, header},
    response::{Html, IntoResponse, Json, Response},
};
use futures::{sink::SinkExt, stream::StreamExt};
use http_body_util::BodyExt;
use regex::Regex;
use std::{str::FromStr, sync::Arc};
use tokio::time::{Duration, sleep};
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message};
use uuid::Uuid;

pub mod generator;

pub const BASE_WASP_APP_URL: &str = "http://127.0.0.1";
pub const BASE_WASP_APP_WS_URL: &str = "ws://127.0.0.1";

#[allow(clippy::too_many_arguments)]
pub async fn request(
    context: Arc<Context>,
    chat_message_id: Option<Uuid>,
    pass: Option<String>,
    port: i32,
    proxy_url: &str,
    request: Request<Body>,
    server_port: i32,
    uri_append: Option<&str>,
    warmed_up: bool,
    wasp_app_id: Option<Uuid>,
    wasp_generator_id: Option<Uuid>,
) -> Result<Response> {
    let url = match pass.clone() {
        None => match uri_append {
            None => format!("{BASE_WASP_APP_URL}:{port}"),
            Some(uri_append) => format!("{BASE_WASP_APP_URL}:{port}?{uri_append}"),
        },
        Some(ref pass) => match uri_append {
            None => format!("{BASE_WASP_APP_URL}:{port}/{pass}"),
            Some(uri_append) => format!("{BASE_WASP_APP_URL}:{port}/{pass}?{uri_append}"),
        },
    };

    let server_url_to_replace = format!("http://127.0.0.1:{server_port}");
    let octopus_url = context.get_config().await?.get_parameter_octopus_api_url();
    let server_path = if wasp_app_id.is_some() && chat_message_id.is_some() {
        format!(
            "/api/v1/wasp-apps/{}/{}/proxy-backend/",
            wasp_app_id.ok_or(AppError::BadRequest)?,
            chat_message_id.ok_or(AppError::BadRequest)?
        )
    } else if wasp_generator_id.is_some() {
        format!(
            "/api/v1/wasp-generators/{}/proxy-backend/",
            wasp_generator_id.ok_or(AppError::BadRequest)?
        )
    } else {
        String::new()
    };
    let server_url = match octopus_url.clone() {
        None => String::new(),
        Some(server_url) => {
            format!("{server_url}{server_path}")
        }
    };

    let server_ws_url_to_replace = format!("localhost:{port}/");
    let octopus_ws_url = context.get_config().await?.get_parameter_octopus_ws_url();
    let server_path = if wasp_app_id.is_some() && chat_message_id.is_some() {
        format!(
            "/api/v1/wasp-apps/{}/{}/proxy-backend/",
            wasp_app_id.ok_or(AppError::BadRequest)?,
            chat_message_id.ok_or(AppError::BadRequest)?
        )
    } else if wasp_generator_id.is_some() {
        format!(
            "/api/v1/wasp-generators/{}/proxy-backend/",
            wasp_generator_id.ok_or(AppError::BadRequest)?
        )
    } else {
        String::new()
    };
    let server_ws_url = match octopus_ws_url {
        None => String::new(),
        Some(server_ws_url) => {
            format!("{server_ws_url}{server_path}")
        }
    };

    let client = reqwest::Client::new();

    if !warmed_up {
        loop {
            let response = client.get(url.clone()).send().await;

            if let Ok(_response) = response {
                sleep(Duration::from_secs(10)).await;

                break;
            }

            sleep(Duration::from_secs(1)).await;
        }
    }

    let headers = request.headers().clone();
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

    let request_builder = if headers.get("authorization").is_some() {
        match headers.get("authorization") {
            Some(authorization) => {
                request_builder.header(reqwest::header::AUTHORIZATION, authorization.as_ref())
            }
            _ => request_builder,
        }
    } else {
        request_builder
    };

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
    tracing::info!("CONTENT_TYPE = {:?}", content_type);

    let url_prefix = match pass.clone() {
        None => {
            if wasp_app_id.is_some() && chat_message_id.is_some() {
                format!(
                    "/api/v1/wasp-apps/{}/{}/{proxy_url}",
                    wasp_app_id.ok_or(AppError::BadRequest)?,
                    chat_message_id.ok_or(AppError::BadRequest)?
                )
            } else if wasp_generator_id.is_some() {
                format!(
                    "/api/v1/wasp-generators/{}/{proxy_url}",
                    wasp_generator_id.ok_or(AppError::BadRequest)?
                )
            } else {
                String::new()
            }
        }
        Some(pass) => {
            if wasp_app_id.is_some() && chat_message_id.is_some() {
                format!(
                    "/api/v1/wasp-apps/{}/{}/{proxy_url}/:{pass}",
                    wasp_app_id.ok_or(AppError::BadRequest)?,
                    chat_message_id.ok_or(AppError::BadRequest)?
                )
            } else if wasp_generator_id.is_some() {
                format!(
                    "/api/v1/wasp-generators/{}/{proxy_url}/:{pass}",
                    wasp_generator_id.ok_or(AppError::BadRequest)?
                )
            } else {
                String::new()
            }
        }
    };

    let html_server_url = match octopus_url {
        None => String::new(),
        Some(server_url) => server_url.to_string(),
    };

    let html_url_prefix = match pass {
        None => {
            if wasp_app_id.is_some() && chat_message_id.is_some() {
                format!(
                    "{html_server_url}/api/v1/wasp-apps/{}/{}/{proxy_url}",
                    wasp_app_id.ok_or(AppError::BadRequest)?,
                    chat_message_id.ok_or(AppError::BadRequest)?
                )
            } else if wasp_generator_id.is_some() {
                format!(
                    "{html_server_url}/api/v1/wasp-generators/{}/{proxy_url}",
                    wasp_generator_id.ok_or(AppError::BadRequest)?
                )
            } else {
                String::new()
            }
        }
        Some(pass) => {
            if wasp_app_id.is_some() && chat_message_id.is_some() {
                format!(
                    "{html_server_url}/api/v1/wasp-apps/{}/{}/{proxy_url}/:{pass}",
                    wasp_app_id.ok_or(AppError::BadRequest)?,
                    chat_message_id.ok_or(AppError::BadRequest)?
                )
            } else if wasp_generator_id.is_some() {
                format!(
                    "{html_server_url}/api/v1/wasp-generators/{}/{proxy_url}/:{pass}",
                    wasp_generator_id.ok_or(AppError::BadRequest)?
                )
            } else {
                String::new()
            }
        }
    };

    match content_type {
        "application/javascript" => {
            let text = response.text().await?;
            let text = update_urls_in_javascript(
                &text,
                &server_path,
                &server_url,
                &server_url_to_replace,
                &server_ws_url,
                &server_ws_url_to_replace,
                &url,
                &url_prefix,
            )?;

            Ok((status_code, JavaScript(text)).into_response())
        }
        "application/json" => {
            let bytes = response.bytes().await?.to_vec();
            let body: serde_json::Value = serde_json::from_slice(&bytes)?;

            Ok((status_code, Json(body)).into_response())
        }
        "application/json; charset=utf-8" => {
            let bytes = response.bytes().await?.to_vec();
            let body: serde_json::Value = serde_json::from_slice(&bytes)?;

            Ok((status_code, Json(body)).into_response())
        }
        "image/png" => {
            let bytes = response.bytes().await?;

            Ok((status_code, Png(bytes)).into_response())
        }
        "image/x-icon" => {
            let bytes = response.bytes().await?;

            Ok((status_code, Xicon(bytes)).into_response())
        }
        "text/html" => {
            let text = response.text().await?;
            let text = update_urls_in_html(&text, &html_url_prefix)?;

            Ok((status_code, Html(text)).into_response())
        }
        &_ => Ok((StatusCode::OK, Json("{}")).into_response()),
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn request_ws(port: i32, server_web_socket: WebSocket) {
    let url = format!("{BASE_WASP_APP_WS_URL}:{port}/");

    let client_web_socket_stream = match connect_async(url).await {
        Ok((stream, _response)) => stream,
        Err(e) => {
            tracing::error!("WebSocket handshake for client failed with {e}!");

            return;
        }
    };

    let (mut client_sender, mut client_receiver) = client_web_socket_stream.split();
    let (mut server_sender, mut server_receiver) = server_web_socket.split();

    let mut send_task = tokio::spawn(async move {
        if let Some(Ok(msg)) = server_receiver.next().await {
            let text = msg.to_text();

            if let Ok(text) = text {
                tracing::error!("CLIENT_SENDER MESSAGE = {:?}", text);
                let message = Message::from(text);

                let result = client_sender.send(message).await;

                if let Err(error) = result {
                    tracing::error!("CLIENT_SENDER ERROR = {:?}", error);
                }
            }
        }
    });

    let mut recv_task = tokio::spawn(async move {
        while let Some(Ok(msg)) = client_receiver.next().await {
            let text = msg.to_text();

            if let Ok(text) = text {
                tracing::error!("SERVER_SENDER MESSAGE = {:?}", text);
                let message = AxumMessage::from(text);

                let result = server_sender.send(message).await;

                if let Err(error) = result {
                    tracing::error!("SERVER_SENDER ERROR = {:?}", error);
                }
            }
        }
    });

    tokio::select! {
        _ = (&mut send_task) => {
        },
        _ = (&mut recv_task) => {
        }
    }
}

pub fn update_urls_in_html(code: &str, url_prefix: &str) -> Result<String> {
    let mut code = code.to_string();

    let to: String = format!("href=\"{url_prefix}/");
    code = code.replace("href=\"/", &to);
    let to: String = format!("src=\"{url_prefix}/");
    code = code.replace("src=\"/", &to);
    let to: String = format!("from \"{url_prefix}/");
    code = code.replace("from \"/", &to);

    let re = Regex::new(r":login\/")?;
    code = re.replace_all(&code, "").to_string();

    Ok(code)
}

#[allow(clippy::too_many_arguments)]
pub fn update_urls_in_javascript(
    code: &str,
    server_path: &str,
    server_url: &str,
    server_url_to_replace: &str,
    server_ws_url: &str,
    server_ws_url_to_replace: &str,
    url: &str,
    url_prefix: &str,
) -> Result<String> {
    let mut code = code.to_string();
    let url = url.to_string();

    let to: String = format!("import \"{url_prefix}/");
    code = code.replace("import \"/", &to);
    let to: String = format!("from \"{url_prefix}/");
    code = code.replace("from \"/", &to);

    if code.contains(server_url_to_replace) {
        code = code.replace(server_url_to_replace, server_url);
    }

    if code.contains(server_ws_url_to_replace) {
        code = code.replace(server_ws_url_to_replace, server_ws_url);
    }

    if url.contains("src/router.tsx") {
        let to: String = format!("    basename: \"{url_prefix}/\",");
        code = code.replace("    basename: \"/\",", &to);
    }

    if url.contains("react-router-dom.js") {
        let from: String = "    true ? tiny_warning_esm_default(!basename || hasBasename(path, basename), 'You are attempting to use a basename on a page whose URL path does not begin with the basename.".to_string();
        let to: String = "    //true ? tiny_warning_esm_default(!basename || hasBasename(path, basename), 'You are attempting to use a basename on a page whose URL path does not begin with the basename.".to_string();
        code = code.replace(&from, &to);
    }

    if url.contains("@vite/client") {
        let from = "${hmrPort || importMetaUrl.port}${\"/\"}";
        if code.contains(from) {
            let to = format!("/ws${{\"{server_path}\"}}");
            code = code.replace(from, &to);
        }

        let from = "{
        // A fetch on a websocket URL will return a successful promise with status 400,
        // but will reject a networking error.
        // When running on middleware mode, it returns status 426, and an cors error happens if mode is not no-cors
        try {
            await fetch(`${pingHostProtocol}://${hostAndPath}`, {
                mode: 'no-cors',
                headers: {
                    // Custom headers won't be included in a request with no-cors so (ab)use one of the
                    // safelisted headers to identify the ping request
                    Accept: 'text/x-vite-ping',
                },
            });
            return true;
        }
        catch { }
        return false;
    };";
        let to = "{ return true; };";
        code = code.replace(from, to);
    }

    if url.contains("?import") {
        let to: String = format!("export default \"{url_prefix}/");
        code = code.replace("export default \"/", &to);
    }

    let re = Regex::new(r":node_modules\/[^\s]+\.js\/")?;
    code = re.replace_all(&code, "").to_string();
    let re = Regex::new(r":src\/[^\s]+\.css\/")?;
    code = re.replace_all(&code, "").to_string();
    let re = Regex::new(r":src\/[^\s]+\.js\/")?;
    code = re.replace_all(&code, "").to_string();
    let re = Regex::new(r":src\/[^\s]+\.jsx\/")?;
    code = re.replace_all(&code, "").to_string();
    let re = Regex::new(r":src\/[^\s]+\.png\/")?;
    code = re.replace_all(&code, "").to_string();
    let re = Regex::new(r":src\/[^\s]+\.ts\/")?;
    code = re.replace_all(&code, "").to_string();
    let re = Regex::new(r":src\/[^\s]+\.tsx\/")?;
    code = re.replace_all(&code, "").to_string();
    let re = Regex::new(r".vite\/[^\s]+\.js\/")?;
    code = re.replace_all(&code, "").to_string();
    let re = Regex::new(r":@vite\/client\/")?;
    code = re.replace_all(&code, "").to_string();
    let re = Regex::new(r":@react-refresh\/")?;
    code = re.replace_all(&code, "").to_string();

    Ok(code)
}

#[derive(Clone, Copy, Debug)]
#[must_use]
pub struct JavaScript<T>(pub T);

impl<T> IntoResponse for JavaScript<T>
where
    T: Into<Body>,
{
    fn into_response(self) -> Response {
        (
            [(
                header::CONTENT_TYPE,
                HeaderValue::from_static(mime::TEXT_JAVASCRIPT.as_ref()),
            )],
            self.0.into(),
        )
            .into_response()
    }
}

impl<T> From<T> for JavaScript<T> {
    fn from(inner: T) -> Self {
        Self(inner)
    }
}

#[derive(Clone, Copy, Debug)]
#[must_use]
pub struct Png<T>(pub T);

impl<T> IntoResponse for Png<T>
where
    T: Into<Body>,
{
    fn into_response(self) -> Response {
        (
            [(
                header::CONTENT_TYPE,
                HeaderValue::from_static(mime::IMAGE_PNG.as_ref()),
            )],
            self.0.into(),
        )
            .into_response()
    }
}

impl<T> From<T> for Png<T> {
    fn from(inner: T) -> Self {
        Self(inner)
    }
}

#[derive(Clone, Copy, Debug)]
#[must_use]
pub struct Xicon<T>(pub T);

impl<T> IntoResponse for Xicon<T>
where
    T: Into<Body>,
{
    fn into_response(self) -> Response {
        (
            [(
                header::CONTENT_TYPE,
                HeaderValue::from_static("image/x-icon"),
            )],
            self.0.into(),
        )
            .into_response()
    }
}

impl<T> From<T> for Xicon<T> {
    fn from(inner: T) -> Self {
        Self(inner)
    }
}
