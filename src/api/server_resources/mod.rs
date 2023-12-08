use crate::{
    context::Context,
    entity::ROLE_COMPANY_ADMIN_USER,
    error::AppError,
    server_resources,
    session::{ensure_secured, ExtractedSession},
};
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use std::sync::Arc;

#[axum_macros::debug_handler]
#[utoipa::path(
    get,
    path = "/api/v1/server-resources",
    responses(
        (status = 200, description = "Server resources read.", body = ServerResources),
        (status = 403, description = "Forbidden.", body = ResponseError),
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn info(
    State(context): State<Arc<Context>>,
    extracted_session: ExtractedSession,
) -> Result<impl IntoResponse, AppError> {
    ensure_secured(context.clone(), extracted_session, ROLE_COMPANY_ADMIN_USER).await?;

    let server_resources = server_resources::get()?;

    Ok((StatusCode::OK, Json(server_resources)).into_response())
}

#[cfg(test)]
mod tests {
    use crate::{api, app, server_resources::ServerResources};
    use axum::{
        body::Body,
        http::{self, Request, StatusCode},
    };
    use fake::{
        faker::{
            internet::en::SafeEmail,
            lorem::en::{Paragraph, Word},
            name::en::Name,
        },
        Fake,
    };
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    #[tokio::test]
    async fn info_200() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri("/api/v1/server-resources")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
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
        let body: ServerResources = serde_json::from_slice(&body).unwrap();

        assert!(body.cpus > 0);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_user_by_id(&mut transaction, user_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_company_by_id(&mut transaction, company_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .transaction_commit(transaction)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn info_403() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let email = format!(
            "{}{}{}",
            Word().fake::<String>(),
            Word().fake::<String>(),
            SafeEmail().fake::<String>()
        );
        let job_title = Paragraph(1..2).fake::<String>();
        let name = Name().fake::<String>();
        let password = "password123";

        let user = api::auth::register::tests::register_with_company_id_post(
            router.clone(),
            company_id,
            &email,
            &job_title,
            &name,
            password,
        )
        .await;
        let second_user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, password, second_user_id)
                .await;
        let session_id = session_response.id;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri("/api/v1/server-resources")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_user_by_id(&mut transaction, user_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_user_by_id(&mut transaction, second_user_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_company_by_id(&mut transaction, company_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .transaction_commit(transaction)
            .await
            .unwrap();
    }
}
