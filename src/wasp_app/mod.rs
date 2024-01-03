use axum::{
    body::Body,
    http::{header, HeaderValue},
    response::{IntoResponse, Response},
};

pub const BASE_WASP_APP_URL: &str = "http://127.0.0.1";

pub fn update_urls_in_html(code: &str, url_prefix: &str) -> String {
    let mut code = code.to_string();
    let to: String = format!("href=\"{url_prefix}/");
    code = code.replace("href=\"/", &to);
    let to: String = format!("src=\"{url_prefix}/");
    code = code.replace("src=\"/", &to);

    code
}

pub fn update_urls_in_javascript(code: &str, url_prefix: &str) -> String {
    let mut code = code.to_string();
    let to: String = format!("import \"{url_prefix}/");
    code = code.replace("import \"/", &to);
    let to: String = format!("from \"{url_prefix}/");
    code = code.replace("from \"/", &to);

    code = code.replace(":node_modules", "node_modules");
    code = code.replace(":::::src/index.tsx/", "");
    code = code.replace("::::src/index.tsx/", "");
    code = code.replace(":::src/index.tsx/", "");
    code = code.replace("::src/index.tsx/", "");
    code = code.replace(":src/index.tsx/", "");

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
