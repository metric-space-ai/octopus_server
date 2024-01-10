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
use std::{str::FromStr, sync::Arc};
use tokio::time::{sleep, Duration};
use tokio_tungstenite::{
    connect_async,
    tungstenite::protocol::Message,
};
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
    warmed_up: bool,
    wasp_app_id: Uuid,
) -> Result<Response> {
    let url = match pass {
        None => format!("{BASE_WASP_APP_URL}:{port}"),
        Some(ref pass) => format!("{BASE_WASP_APP_URL}:{port}/{pass}"),
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
    tracing::info!("content_type = {:?}", content_type);

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
            );

            Ok((status_code, JavaScript(text)).into_response())
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
pub async fn request_ws(port: i32, web_socket: WebSocket) {
    let (mut server_sender, mut server_receiver) = web_socket.split();
    let url = format!("{BASE_WASP_APP_WS_URL}:{port}/");
    tracing::info!("url = {:?}", url);
    let ws_stream = match connect_async(url).await {
        Ok((stream, response)) => {
            tracing::info!("Handshake for client has been completed");
            // This will be the HTTP response, same as with server this is the last moment we
            // can still access HTTP stuff.
            tracing::info!("Server response was {response:?}");
            stream
        }
        Err(e) => {
            tracing::info!("WebSocket handshake for client failed with {e}!");

            return;
        }
    };
    tracing::info!("AFTER HANDSHAKE!");
    let (mut client_sender, mut client_receiver) = ws_stream.split();

    let mut send_task = tokio::spawn(async move {
        if let Some(msg) = server_receiver.next().await {
            if let Ok(msg) = msg {
                let text = msg.to_text().unwrap();
                tracing::info!("SERVER RECEIVER TEXT = {}", text);
                let message = Message::from(text);
                /*
                                let message = match msg {
                                    AxumMessage::Binary(binary) => Message::Binary(binary),
                                    AxumMessage::Close(close) => {
                                        let close_frame = if let Some(close) = close {
                                            let close_frame = CloseFrame {
                                                code: CloseCode::from(close.code),
                                                reason: close.reason,
                                            };

                                            Some(close_frame)
                                        } else {
                                            None
                                        };

                                        Message::Close(close_frame)
                                    }
                                    AxumMessage::Ping(ping) => Message::Ping(ping),
                                    AxumMessage::Pong(pong) => Message::Pong(pong),
                                    AxumMessage::Text(text) => Message::Text(text),
                                };
                */
                client_sender.send(message).await.expect("Can not send!");
            } else {
                tracing::info!("client abruptly disconnected");
            }
        }
    });

    //receiver just prints whatever it gets
    let mut recv_task = tokio::spawn(async move {
        while let Some(Ok(msg)) = client_receiver.next().await {
            // print message and break if instructed to do so
            let text = msg.to_text().unwrap();
            tracing::info!("CLIENT RECEIVER TEXT = {}", text);
            let message = AxumMessage::from(text);

            let _ = server_sender.send(message).await;
            /*
                        let message = match msg {
                            Message::Binary(binary) => AxumMessage::Binary(binary),
                            Message::Close(close) => {

                            }
                            Message::Frame(frame) =>,
                            Message::Ping(ping) => AxumMessage::Ping(ping),
                            Message::Pong(pong) => AxumMessage::Pong(pong),
                            Message::Text(text) => AxumMessage::Text(text),
                        };
            */
        }
    });

    //wait for either task to finish and kill the other task
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

    /*
        let to: String = format!("href=\"");
        code = code.replace("href=\"/", &to);
        let to: String = format!("src=\"");
        code = code.replace("src=\"/", &to);
        let to: String = format!("from \"");
        code = code.replace("from \"/", &to);
    */

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
) -> String {
    let mut code = code.to_string();
    let url = url.to_string();

    let to: String = format!("import \"{url_prefix}/");
    code = code.replace("import \"/", &to);
    let to: String = format!("from \"{url_prefix}/");
    code = code.replace("from \"/", &to);

    if code.contains(server_url_to_replace) {
        code = code.replace(server_url_to_replace, server_url);
    }

    let find = "importMetaUrl.port}${\"/\"}";
    if code.contains(find) {
        let to = format!("importMetaUrl.port}}${{\"{server_path}\"}}");
        code = code.replace(find, &to);
    }

    if url.contains("src/router.tsx") {
        let to: String = format!("        to: \"{url_prefix}/\",");
        code = code.replace("        to: \"/\",", &to);

        let to: String = format!("        build: (options)=>interpolatePath(\"{url_prefix}/\",");
        code = code.replace("        build: (options)=>interpolatePath(\"/", &to);

        let to: String = format!("    basename: \"{url_prefix}/\",");
        code = code.replace("    basename: \"/\",", &to);
    }

    code = code.replace(":src/index.tsx/", "");
    code = code.replace(":@vite/client/", "");
    code = code.replace(":node_modules/.vite/deps/react.js/", "");
    code = code.replace(":node_modules/.vite/deps/react_jsx-dev-runtime.js/", "");
    code = code.replace(":node_modules/.vite/deps/react-dom_client.js/", "");
    code = code.replace(":node_modules/.vite/deps/@tanstack_react-query.js/", "");
    code = code.replace(":src/queryClient.js/", "");
    code = code.replace(":src/router.tsx/", "");
    code = code.replace(":src/router/Link.tsx/", "");
    code = code.replace(":src/ext-src/MainPage.jsx/", "");
    code = code.replace(":node_modules/.vite/deps/react-router-dom.js/", "");

    code = code.replace(":src/ext-src/Main.css/", "");

    code = code.replace(":node_modules/", "");
    code = code.replace(":@react-refresh/", "");

    code = code.replace(".vite/deps/chunk-MMW4JUSU.js/", "");

    code
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
