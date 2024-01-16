use crate::{context::Context, error::AppError, Result};
use axum::{
    body::Body,
    extract::{
        ws::{Message as AxumMessage, WebSocket},
        Request,
    },
    http::{header, HeaderValue, Method, StatusCode},
    response::{Html, IntoResponse, Json, Response},
};
use futures::{sink::SinkExt, stream::StreamExt};
use regex::Regex;
use std::{str::FromStr, sync::Arc};
use tokio::time::{sleep, Duration};
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message};
use uuid::Uuid;

pub const BASE_WASP_APP_URL: &str = "http://127.0.0.1";
pub const BASE_WASP_APP_WS_URL: &str = "ws://127.0.0.1";

#[allow(clippy::too_many_arguments)]
pub async fn request(
    context: Arc<Context>,
    chat_message_id: Uuid,
    pass: Option<String>,
    port: i32,
    proxy_url: &str,
    request: Request<Body>,
    uri_append: Option<&str>,
    warmed_up: bool,
    wasp_app_id: Uuid,
) -> Result<Response> {
    let url = match pass {
        None => match uri_append {
            None => format!("{BASE_WASP_APP_URL}:{port}"),
            Some(uri_append) => format!("{BASE_WASP_APP_URL}:{port}?{uri_append}"),
        },
        Some(ref pass) => match uri_append {
            None => format!("{BASE_WASP_APP_URL}:{port}/{pass}"),
            Some(uri_append) => format!("{BASE_WASP_APP_URL}:{port}/{pass}?{uri_append}"),
        },
    };

    let server_url_to_replace = format!("localhost:{port}/");
    let octopus_ws_url = context.get_config().await?.get_parameter_octopus_ws_url();
    let server_path = format!("/api/v1/wasp-apps/{wasp_app_id}/{chat_message_id}/proxy-backend/");
    let server_url = match octopus_ws_url {
        None => String::new(),
        Some(server_url) => {
            format!("{server_url}{server_path}")
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

    let request_builder = match *request.method() {
        Method::DELETE => client.delete(url.clone()),
        Method::POST => client.post(url.clone()),
        Method::PUT => client.put(url.clone()),
        _ => client.get(url.clone()),
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

    let url_prefix = match pass {
        None => format!("/api/v1/wasp-apps/{wasp_app_id}/{chat_message_id}/{proxy_url}"),
        Some(pass) => {
            format!("/api/v1/wasp-apps/{wasp_app_id}/{chat_message_id}/{proxy_url}/:{pass}")
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
                &url,
                &url_prefix,
                context.get_config().await?.ws_port,
            )?;

            Ok((status_code, JavaScript(text)).into_response())
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
            let text = update_urls_in_html(&text, &url_prefix);

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
                let message = Message::from(text);

                let _ = client_sender.send(message).await;
            }
        }
    });

    let mut recv_task = tokio::spawn(async move {
        while let Some(Ok(msg)) = client_receiver.next().await {
            let text = msg.to_text();

            if let Ok(text) = text {
                let message = AxumMessage::from(text);

                let _ = server_sender.send(message).await;
            }
        }
    });

    tokio::select! {
        _ = (&mut send_task) => {
            recv_task.abort();
        },
        _ = (&mut recv_task) => {
            send_task.abort();
        }
    }
}

pub fn update_urls_in_html(code: &str, url_prefix: &str) -> String {
    let mut code = code.to_string();

    let to: String = format!("href=\"{url_prefix}/");
    code = code.replace("href=\"/", &to);
    let to: String = format!("src=\"{url_prefix}/");
    code = code.replace("src=\"/", &to);
    let to: String = format!("from \"{url_prefix}/");
    code = code.replace("from \"/", &to);

    code
}

pub fn update_urls_in_javascript(
    code: &str,
    server_path: &str,
    server_url: &str,
    server_url_to_replace: &str,
    url: &str,
    url_prefix: &str,
    ws_port: u16,
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

    if url.contains("src/router.tsx") {
        let to: String = format!("    basename: \"{url_prefix}/\",");
        code = code.replace("    basename: \"/\",", &to);
    }

    if url.contains("@vite/client") {
        let from = "${hmrPort || importMetaUrl.port}${\"/\"}";
        if code.contains(from) {
            let to = format!("{ws_port}${{\"{server_path}\"}}");
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

    let re = Regex::new(r":node_modules\/[^\s]+.js\/")?;
    code = re.replace_all(&code, "").to_string();
    let re = Regex::new(r":src\/[^\s]+.css\/")?;
    code = re.replace_all(&code, "").to_string();
    let re = Regex::new(r":src\/[^\s]+.js\/")?;
    code = re.replace_all(&code, "").to_string();
    let re = Regex::new(r":src\/[^\s]+.jsx\/")?;
    code = re.replace_all(&code, "").to_string();
    let re = Regex::new(r":src\/[^\s]+.png\/")?;
    code = re.replace_all(&code, "").to_string();
    let re = Regex::new(r":src\/[^\s]+.ts\/")?;
    code = re.replace_all(&code, "").to_string();
    let re = Regex::new(r":src\/[^\s]+.tsx\/")?;
    code = re.replace_all(&code, "").to_string();
    let re = Regex::new(r".vite\/[^\s]+.js\/")?;
    code = re.replace_all(&code, "").to_string();
    let re = Regex::new(r":@vite\/client\/")?;
    code = re.replace_all(&code, "").to_string();
    let re = Regex::new(r":@react-refresh\/")?;
    code = re.replace_all(&code, "").to_string();

    //code = code.replace(":@vite/client/", "");
    //code = code.replace(":node_modules/", "");
    //code = code.replace(":@react-refresh/", "");

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
