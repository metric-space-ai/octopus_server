use crate::{error::AppError, context::Context, Result};
use axum::{
    body::Body,
    extract::Request,
    http::{header, HeaderValue, Method, StatusCode},
    response::{Html, IntoResponse, Json, Response},
};
use std::{str::FromStr, sync::Arc};
use tokio::time::{sleep, Duration};
use uuid::Uuid;

pub const BASE_WASP_APP_URL: &str = "http://127.0.0.1";
pub const BASE_WASP_APP_SERVER_URL: &str = "127.0.0.1";

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
tracing::info!("CONTAINS!");
        code = code.replace(server_url_to_replace, server_url);
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

#[allow(clippy::too_many_arguments)]
pub async fn request(
    context: Arc<Context>,
    chat_message_id: Uuid,
    pass: Option<String>,
    port: i32,
    proxy_url: &str,
    request: Request<Body>,
    server_port: i32,
    warmed_up: bool,
    wasp_app_id: Uuid,
) -> Result<Response> {
tracing::info!("warmed_up = {warmed_up}");
    let url = match pass {
        None => format!("{BASE_WASP_APP_URL}:{port}"),
        Some(ref pass) => format!("{BASE_WASP_APP_URL}:{port}/{pass}"),
    };

    let server_url_to_replace = format!("localhost:{server_port}/");
    let octopus_api_url = context.get_config().await?.get_parameter_octopus_api_url();
    let server_url = match octopus_api_url {
        None => String::new(),
        Some(server_url) => {
            let server_url = if server_url.contains("http://") {
                server_url
                    .strip_prefix("http://")
                    .ok_or(AppError::Parsing)?
                    .to_string()
            } else {
                server_url
                    .strip_prefix("https://")
                    .ok_or(AppError::Parsing)?
                    .to_string()
            };

            format!("{server_url}/api/v1/wasp-apps/{wasp_app_id}/{chat_message_id}/proxy-backend")
        }
    };

    tracing::info!("server_url_to_replace = {server_url_to_replace}");
tracing::info!("server_url = {server_url}");
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(30))
        .timeout(Duration::from_secs(30))
        .build()?;

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
