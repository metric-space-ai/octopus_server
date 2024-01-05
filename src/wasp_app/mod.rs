use crate::{error::AppError, Result};
use axum::{
    body::Body,
    extract::Request,
    http::{header, HeaderValue, Method, StatusCode},
    response::{Html, IntoResponse, Json, Response},
};
use std::str::FromStr;
use uuid::Uuid;

pub const BASE_WASP_APP_URL: &str = "http://127.0.0.1";

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

pub fn update_urls_in_javascript(code: &str, url: &str, url_prefix: &str) -> String {
    let mut code = code.to_string();
    let url = url.to_string();

    let to: String = format!("import \"{url_prefix}/");
    code = code.replace("import \"/", &to);
    let to: String = format!("from \"{url_prefix}/");
    code = code.replace("from \"/", &to);

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

pub async fn wasp_app_request(
    chat_message_id: Uuid,
    pass: Option<String>,
    port: i32,
    request: Request<Body>,
    wasp_app_id: Uuid,
) -> Result<Response> {
    let url = match pass {
        None => format!("{BASE_WASP_APP_URL}:{}", port),
        Some(ref pass) => format!("{BASE_WASP_APP_URL}:{}/{pass}", port),
    };

    let client = reqwest::Client::new();

    let request_builder = match *request.method() {
        Method::DELETE => client.delete(url.clone()),
        Method::GET => client.get(url.clone()),
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
        None => format!("/api/v1/wasp-apps/{wasp_app_id}/{chat_message_id}/proxy"),
        Some(pass) => format!("/api/v1/wasp-apps/{wasp_app_id}/{chat_message_id}/proxy/:{pass}"),
    };

    match content_type {
        "application/javascript" => {
            let text = response.text().await?;
            let text = update_urls_in_javascript(&text, &url, &url_prefix);
            tracing::info!("text = {:?}", text);

            Ok((status_code, JavaScript(text)).into_response())
        }
        "text/html" => {
            let text = response.text().await?;
            let text = update_urls_in_html(&text, &url_prefix);
            tracing::info!("text = {:?}", text);

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
