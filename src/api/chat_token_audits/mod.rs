use crate::{
    context::Context,
    entity::ROLE_COMPANY_ADMIN_USER,
    error::AppError,
    session::{require_authenticated, ExtractedSession},
};
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use chrono::{DateTime, Datelike, NaiveDate, Utc};
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;

pub mod report;

#[axum_macros::debug_handler]
#[utoipa::path(
    get,
    path = "/api/v1/chat-token-audits",
    responses(
        (status = 200, description = "List of chat token audits.", body = [ChatTokenAudit]),
        (status = 401, description = "Unauthorized.", body = ResponseError),
        (status = 403, description = "Forbidden.", body = ResponseError)
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn list(
    State(context): State<Arc<Context>>,
    extracted_session: ExtractedSession,
) -> Result<impl IntoResponse, AppError> {
    let session = require_authenticated(extracted_session).await?;

    let session_user = context
        .octopus_database
        .try_get_user_by_id(session.user_id)
        .await?
        .ok_or(AppError::Forbidden)?;

    if !session_user
        .roles
        .contains(&ROLE_COMPANY_ADMIN_USER.to_string())
    {
        return Err(AppError::Forbidden);
    }

    let chat_token_audits = context
        .octopus_database
        .get_chat_token_audits_by_company_id(session_user.company_id)
        .await?;

    Ok((StatusCode::OK, Json(chat_token_audits)).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    get,
    path = "/api/v1/chat-token-audits/:chat_token_audit_id",
    responses(
        (status = 200, description = "Chat token audit read.", body = ChatTokenAudit),
        (status = 401, description = "Unauthorized.", body = ResponseError),
        (status = 403, description = "Forbidden.", body = ResponseError),
        (status = 404, description = "Chat token audit not found.", body = ResponseError),
    ),
    params(
        ("chat_token_audit_id" = String, Path, description = "Chat token audit id")
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn read(
    State(context): State<Arc<Context>>,
    extracted_session: ExtractedSession,
    Path(chat_token_audit_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let session = require_authenticated(extracted_session).await?;

    let session_user = context
        .octopus_database
        .try_get_user_by_id(session.user_id)
        .await?
        .ok_or(AppError::Forbidden)?;

    let chat_token_audit = context
        .octopus_database
        .try_get_chat_token_audit_by_id(chat_token_audit_id)
        .await?
        .ok_or(AppError::NotFound)?;

    if !session_user
        .roles
        .contains(&ROLE_COMPANY_ADMIN_USER.to_string())
        || session_user.company_id != chat_token_audit.company_id
    {
        return Err(AppError::Forbidden);
    }

    Ok((StatusCode::OK, Json(chat_token_audit)).into_response())
}

#[derive(Debug, Default, Deserialize)]
pub struct QueryParams {
    pub ends_at: Option<DateTime<Utc>>,
    pub starts_at: Option<DateTime<Utc>>,
}

#[axum_macros::debug_handler]
#[utoipa::path(
    get,
    path = "/api/v1/chat-token-audits/:company_id/report",
    responses(
        (status = 200, description = "Chat token audit report.", body = String),
        (status = 401, description = "Unauthorized.", body = ResponseError),
        (status = 403, description = "Forbidden.", body = ResponseError),
        (status = 404, description = "Company not found.", body = ResponseError)
    ),
    params(
        ("company_id" = String, Path, description = "Company id")
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn report(
    State(context): State<Arc<Context>>,
    extracted_session: ExtractedSession,
    Path(company_id): Path<Uuid>,
    query_params: Query<QueryParams>,
) -> Result<impl IntoResponse, AppError> {
    let ends_at = query_params.ends_at.unwrap_or_else(Utc::now);
    let now = Utc::now();
    let naive_date =
        NaiveDate::from_ymd_opt(now.year(), now.month(), 1).ok_or(AppError::Parsing)?;
    let starts_at = DateTime::from_naive_utc_and_offset(naive_date.into(), *now.offset());
    let starts_at = query_params.starts_at.unwrap_or(starts_at);

    let session = require_authenticated(extracted_session).await?;

    let session_user = context
        .octopus_database
        .try_get_user_by_id(session.user_id)
        .await?
        .ok_or(AppError::Forbidden)?;

    if !session_user
        .roles
        .contains(&ROLE_COMPANY_ADMIN_USER.to_string())
    {
        return Err(AppError::Forbidden);
    }

    context
        .octopus_database
        .try_get_company_by_id(company_id)
        .await?
        .ok_or(AppError::NotFound)?;

    let chat_token_audits = context
        .octopus_database
        .get_chat_token_audits_by_company_id_and_time(company_id, ends_at, starts_at)
        .await?;

    let report = report::generate(chat_token_audits, context, ends_at, starts_at).await?;

    Ok((StatusCode::OK, Json(report)).into_response())
}

#[cfg(test)]
mod tests {
    use crate::{
        api,
        api::chat_token_audits::report::ChatTokenAuditReport,
        app,
        entity::{
            ChatTokenAudit, ROLE_ADMIN, ROLE_COMPANY_ADMIN_USER, ROLE_PRIVATE_USER,
            ROLE_PUBLIC_USER,
        },
    };
    use axum::{
        body::Body,
        http::{self, Request, StatusCode},
    };
    use http_body_util::BodyExt;
    use tokio::time::{sleep, Duration};
    use tower::ServiceExt;

    #[tokio::test]
    async fn list_200() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        app.context
            .octopus_database
            .update_user_roles(
                user_id,
                &[
                    ROLE_ADMIN.to_string(),
                    ROLE_COMPANY_ADMIN_USER.to_string(),
                    ROLE_PRIVATE_USER.to_string(),
                    ROLE_PUBLIC_USER.to_string(),
                ],
            )
            .await
            .unwrap();

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let (name, r#type) = api::workspaces::tests::get_workspace_create_params_public();
        let message = api::chat_messages::tests::get_chat_message_create_params();
        let (chat_id, chat_message_id, workspace_id) =
            api::chat_messages::tests::chat_message_with_deps_create(
                router.clone(),
                session_id,
                user_id,
                &message,
                &name,
                &r#type,
            )
            .await;

        sleep(Duration::from_secs(2)).await;

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        app.context
            .octopus_database
            .insert_chat_token_audit(
                &mut transaction,
                chat_id,
                chat_message_id,
                company_id,
                user_id,
                100,
                "test_llm",
                "test_model",
                100,
            )
            .await
            .unwrap();

        api::tests::transaction_commit(app.context.clone(), transaction).await;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri("/api/v1/chat-token-audits")
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
        let body: Vec<ChatTokenAudit> = serde_json::from_slice(&body).unwrap();

        assert!(!body.is_empty());

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        api::chat_messages::tests::chat_message_with_deps_cleanup(
            app.context.clone(),
            &mut transaction,
            chat_id,
            chat_message_id,
            workspace_id,
        )
        .await;

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id],
            &[user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn list_401() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        app.context
            .octopus_database
            .update_user_roles(
                user_id,
                &[
                    ROLE_ADMIN.to_string(),
                    ROLE_COMPANY_ADMIN_USER.to_string(),
                    ROLE_PRIVATE_USER.to_string(),
                    ROLE_PUBLIC_USER.to_string(),
                ],
            )
            .await
            .unwrap();

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let (name, r#type) = api::workspaces::tests::get_workspace_create_params_public();
        let message = api::chat_messages::tests::get_chat_message_create_params();
        let (chat_id, chat_message_id, workspace_id) =
            api::chat_messages::tests::chat_message_with_deps_create(
                router.clone(),
                session_id,
                user_id,
                &message,
                &name,
                &r#type,
            )
            .await;

        sleep(Duration::from_secs(2)).await;

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        app.context
            .octopus_database
            .insert_chat_token_audit(
                &mut transaction,
                chat_id,
                chat_message_id,
                company_id,
                user_id,
                100,
                "test_llm",
                "test_model",
                100,
            )
            .await
            .unwrap();

        api::tests::transaction_commit(app.context.clone(), transaction).await;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri("/api/v1/chat-token-audits")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        api::chat_messages::tests::chat_message_with_deps_cleanup(
            app.context.clone(),
            &mut transaction,
            chat_id,
            chat_message_id,
            workspace_id,
        )
        .await;

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id],
            &[user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn list_403() {
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

        let (name, r#type) = api::workspaces::tests::get_workspace_create_params_public();
        let message = api::chat_messages::tests::get_chat_message_create_params();
        let (chat_id, chat_message_id, workspace_id) =
            api::chat_messages::tests::chat_message_with_deps_create(
                router.clone(),
                session_id,
                user_id,
                &message,
                &name,
                &r#type,
            )
            .await;

        sleep(Duration::from_secs(2)).await;

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        app.context
            .octopus_database
            .insert_chat_token_audit(
                &mut transaction,
                chat_id,
                chat_message_id,
                company_id,
                user_id,
                100,
                "test_llm",
                "test_model",
                100,
            )
            .await
            .unwrap();

        api::tests::transaction_commit(app.context.clone(), transaction).await;

        let (email, is_enabled, job_title, name, password, roles) =
            api::users::tests::get_user_create_params();
        let user = api::users::tests::user_create(
            router.clone(),
            session_id,
            &email,
            is_enabled,
            &job_title,
            &name,
            &password,
            &roles,
        )
        .await;
        let second_user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, second_user_id)
                .await;
        let session_id = session_response.id;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri("/api/v1/chat-token-audits")
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

        api::chat_messages::tests::chat_message_with_deps_cleanup(
            app.context.clone(),
            &mut transaction,
            chat_id,
            chat_message_id,
            workspace_id,
        )
        .await;

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id],
            &[user_id, second_user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn list_403_deleted_user() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        app.context
            .octopus_database
            .update_user_roles(
                user_id,
                &[
                    ROLE_ADMIN.to_string(),
                    ROLE_COMPANY_ADMIN_USER.to_string(),
                    ROLE_PRIVATE_USER.to_string(),
                    ROLE_PUBLIC_USER.to_string(),
                ],
            )
            .await
            .unwrap();

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let (name, r#type) = api::workspaces::tests::get_workspace_create_params_public();
        let message = api::chat_messages::tests::get_chat_message_create_params();
        let (chat_id, chat_message_id, workspace_id) =
            api::chat_messages::tests::chat_message_with_deps_create(
                router.clone(),
                session_id,
                user_id,
                &message,
                &name,
                &r#type,
            )
            .await;

        sleep(Duration::from_secs(2)).await;

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        app.context
            .octopus_database
            .insert_chat_token_audit(
                &mut transaction,
                chat_id,
                chat_message_id,
                company_id,
                user_id,
                100,
                "test_llm",
                "test_model",
                100,
            )
            .await
            .unwrap();

        api::tests::transaction_commit(app.context.clone(), transaction).await;

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(app.context.clone(), &mut transaction, &[], &[user_id])
            .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri("/api/v1/chat-token-audits")
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

        api::chat_messages::tests::chat_message_with_deps_cleanup(
            app.context.clone(),
            &mut transaction,
            chat_id,
            chat_message_id,
            workspace_id,
        )
        .await;

        api::setup::tests::setup_cleanup(app.context.clone(), &mut transaction, &[company_id], &[])
            .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn read_200() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        app.context
            .octopus_database
            .update_user_roles(
                user_id,
                &[
                    ROLE_ADMIN.to_string(),
                    ROLE_COMPANY_ADMIN_USER.to_string(),
                    ROLE_PRIVATE_USER.to_string(),
                    ROLE_PUBLIC_USER.to_string(),
                ],
            )
            .await
            .unwrap();

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let (name, r#type) = api::workspaces::tests::get_workspace_create_params_public();
        let message = api::chat_messages::tests::get_chat_message_create_params();
        let (chat_id, chat_message_id, workspace_id) =
            api::chat_messages::tests::chat_message_with_deps_create(
                router.clone(),
                session_id,
                user_id,
                &message,
                &name,
                &r#type,
            )
            .await;

        sleep(Duration::from_secs(3)).await;

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        let chat_token_audit = app
            .context
            .octopus_database
            .insert_chat_token_audit(
                &mut transaction,
                chat_id,
                chat_message_id,
                company_id,
                user_id,
                100,
                "test_llm",
                "test_model",
                100,
            )
            .await
            .unwrap();

        api::tests::transaction_commit(app.context.clone(), transaction).await;

        let chat_token_audit_id = chat_token_audit.id;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("/api/v1/chat-token-audits/{chat_token_audit_id}"))
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
        let body: ChatTokenAudit = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.chat_message_id, chat_message_id);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        api::chat_messages::tests::chat_message_with_deps_cleanup(
            app.context.clone(),
            &mut transaction,
            chat_id,
            chat_message_id,
            workspace_id,
        )
        .await;

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id],
            &[user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn read_401() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        app.context
            .octopus_database
            .update_user_roles(
                user_id,
                &[
                    ROLE_ADMIN.to_string(),
                    ROLE_COMPANY_ADMIN_USER.to_string(),
                    ROLE_PRIVATE_USER.to_string(),
                    ROLE_PUBLIC_USER.to_string(),
                ],
            )
            .await
            .unwrap();

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let (name, r#type) = api::workspaces::tests::get_workspace_create_params_public();
        let message = api::chat_messages::tests::get_chat_message_create_params();
        let (chat_id, chat_message_id, workspace_id) =
            api::chat_messages::tests::chat_message_with_deps_create(
                router.clone(),
                session_id,
                user_id,
                &message,
                &name,
                &r#type,
            )
            .await;

        sleep(Duration::from_secs(3)).await;

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        let chat_token_audit = app
            .context
            .octopus_database
            .insert_chat_token_audit(
                &mut transaction,
                chat_id,
                chat_message_id,
                company_id,
                user_id,
                100,
                "test_llm",
                "test_model",
                100,
            )
            .await
            .unwrap();

        api::tests::transaction_commit(app.context.clone(), transaction).await;

        let chat_token_audit_id = chat_token_audit.id;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("/api/v1/chat-token-audits/{chat_token_audit_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        api::chat_messages::tests::chat_message_with_deps_cleanup(
            app.context.clone(),
            &mut transaction,
            chat_id,
            chat_message_id,
            workspace_id,
        )
        .await;

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id],
            &[user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn read_403() {
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

        let (name, r#type) = api::workspaces::tests::get_workspace_create_params_public();
        let message = api::chat_messages::tests::get_chat_message_create_params();
        let (chat_id, chat_message_id, workspace_id) =
            api::chat_messages::tests::chat_message_with_deps_create(
                router.clone(),
                session_id,
                user_id,
                &message,
                &name,
                &r#type,
            )
            .await;

        sleep(Duration::from_secs(2)).await;

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        let chat_token_audit = app
            .context
            .octopus_database
            .insert_chat_token_audit(
                &mut transaction,
                chat_id,
                chat_message_id,
                company_id,
                user_id,
                100,
                "test_llm",
                "test_model",
                100,
            )
            .await
            .unwrap();

        api::tests::transaction_commit(app.context.clone(), transaction).await;

        let chat_token_audit_id = chat_token_audit.id;

        let (email, is_enabled, job_title, name, password, roles) =
            api::users::tests::get_user_create_params();
        let user = api::users::tests::user_create(
            router.clone(),
            session_id,
            &email,
            is_enabled,
            &job_title,
            &name,
            &password,
            &roles,
        )
        .await;
        let second_user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, second_user_id)
                .await;
        let session_id = session_response.id;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("/api/v1/chat-token-audits/{chat_token_audit_id}"))
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

        api::chat_messages::tests::chat_message_with_deps_cleanup(
            app.context.clone(),
            &mut transaction,
            chat_id,
            chat_message_id,
            workspace_id,
        )
        .await;

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id],
            &[user_id, second_user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn read_403_deleted_user() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        app.context
            .octopus_database
            .update_user_roles(
                user_id,
                &[
                    ROLE_ADMIN.to_string(),
                    ROLE_COMPANY_ADMIN_USER.to_string(),
                    ROLE_PRIVATE_USER.to_string(),
                    ROLE_PUBLIC_USER.to_string(),
                ],
            )
            .await
            .unwrap();

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let (name, r#type) = api::workspaces::tests::get_workspace_create_params_public();
        let message = api::chat_messages::tests::get_chat_message_create_params();
        let (chat_id, chat_message_id, workspace_id) =
            api::chat_messages::tests::chat_message_with_deps_create(
                router.clone(),
                session_id,
                user_id,
                &message,
                &name,
                &r#type,
            )
            .await;

        sleep(Duration::from_secs(3)).await;

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        let chat_token_audit = app
            .context
            .octopus_database
            .insert_chat_token_audit(
                &mut transaction,
                chat_id,
                chat_message_id,
                company_id,
                user_id,
                100,
                "test_llm",
                "test_model",
                100,
            )
            .await
            .unwrap();

        api::tests::transaction_commit(app.context.clone(), transaction).await;

        let chat_token_audit_id = chat_token_audit.id;

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(app.context.clone(), &mut transaction, &[], &[user_id])
            .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("/api/v1/chat-token-audits/{chat_token_audit_id}"))
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

        api::chat_messages::tests::chat_message_with_deps_cleanup(
            app.context.clone(),
            &mut transaction,
            chat_id,
            chat_message_id,
            workspace_id,
        )
        .await;

        api::setup::tests::setup_cleanup(app.context.clone(), &mut transaction, &[company_id], &[])
            .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn read_404() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        app.context
            .octopus_database
            .update_user_roles(
                user_id,
                &[
                    ROLE_ADMIN.to_string(),
                    ROLE_COMPANY_ADMIN_USER.to_string(),
                    ROLE_PRIVATE_USER.to_string(),
                    ROLE_PUBLIC_USER.to_string(),
                ],
            )
            .await
            .unwrap();

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let chat_token_audit_id = "33847746-0030-4964-a496-f75d04499160";

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("/api/v1/chat-token-audits/{chat_token_audit_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id],
            &[user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn report_200() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        app.context
            .octopus_database
            .update_user_roles(
                user_id,
                &[
                    ROLE_ADMIN.to_string(),
                    ROLE_COMPANY_ADMIN_USER.to_string(),
                    ROLE_PRIVATE_USER.to_string(),
                    ROLE_PUBLIC_USER.to_string(),
                ],
            )
            .await
            .unwrap();

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let (name, r#type) = api::workspaces::tests::get_workspace_create_params_public();
        let message = api::chat_messages::tests::get_chat_message_create_params();
        let (chat_id, chat_message_id, workspace_id) =
            api::chat_messages::tests::chat_message_with_deps_create(
                router.clone(),
                session_id,
                user_id,
                &message,
                &name,
                &r#type,
            )
            .await;

        sleep(Duration::from_secs(3)).await;

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        app.context
            .octopus_database
            .insert_chat_token_audit(
                &mut transaction,
                chat_id,
                chat_message_id,
                company_id,
                user_id,
                100,
                "test_llm",
                "test_model",
                100,
            )
            .await
            .unwrap();

        api::tests::transaction_commit(app.context.clone(), transaction).await;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("/api/v1/chat-token-audits/{company_id}/report"))
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
        let _body: ChatTokenAuditReport = serde_json::from_slice(&body).unwrap();

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        api::chat_messages::tests::chat_message_with_deps_cleanup(
            app.context.clone(),
            &mut transaction,
            chat_id,
            chat_message_id,
            workspace_id,
        )
        .await;

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id],
            &[user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn report_401() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        app.context
            .octopus_database
            .update_user_roles(
                user_id,
                &[
                    ROLE_ADMIN.to_string(),
                    ROLE_COMPANY_ADMIN_USER.to_string(),
                    ROLE_PRIVATE_USER.to_string(),
                    ROLE_PUBLIC_USER.to_string(),
                ],
            )
            .await
            .unwrap();

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let (name, r#type) = api::workspaces::tests::get_workspace_create_params_public();
        let message = api::chat_messages::tests::get_chat_message_create_params();
        let (chat_id, chat_message_id, workspace_id) =
            api::chat_messages::tests::chat_message_with_deps_create(
                router.clone(),
                session_id,
                user_id,
                &message,
                &name,
                &r#type,
            )
            .await;

        sleep(Duration::from_secs(3)).await;

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        app.context
            .octopus_database
            .insert_chat_token_audit(
                &mut transaction,
                chat_id,
                chat_message_id,
                company_id,
                user_id,
                100,
                "test_llm",
                "test_model",
                100,
            )
            .await
            .unwrap();

        api::tests::transaction_commit(app.context.clone(), transaction).await;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("/api/v1/chat-token-audits/{company_id}/report"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        api::chat_messages::tests::chat_message_with_deps_cleanup(
            app.context.clone(),
            &mut transaction,
            chat_id,
            chat_message_id,
            workspace_id,
        )
        .await;

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id],
            &[user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn report_403() {
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

        let (name, r#type) = api::workspaces::tests::get_workspace_create_params_public();
        let message = api::chat_messages::tests::get_chat_message_create_params();
        let (chat_id, chat_message_id, workspace_id) =
            api::chat_messages::tests::chat_message_with_deps_create(
                router.clone(),
                session_id,
                user_id,
                &message,
                &name,
                &r#type,
            )
            .await;

        sleep(Duration::from_secs(2)).await;

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        app.context
            .octopus_database
            .insert_chat_token_audit(
                &mut transaction,
                chat_id,
                chat_message_id,
                company_id,
                user_id,
                100,
                "test_llm",
                "test_model",
                100,
            )
            .await
            .unwrap();

        api::tests::transaction_commit(app.context.clone(), transaction).await;

        let (email, is_enabled, job_title, name, password, roles) =
            api::users::tests::get_user_create_params();
        let user = api::users::tests::user_create(
            router.clone(),
            session_id,
            &email,
            is_enabled,
            &job_title,
            &name,
            &password,
            &roles,
        )
        .await;
        let second_user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, second_user_id)
                .await;
        let session_id = session_response.id;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("/api/v1/chat-token-audits/{company_id}/report"))
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

        api::chat_messages::tests::chat_message_with_deps_cleanup(
            app.context.clone(),
            &mut transaction,
            chat_id,
            chat_message_id,
            workspace_id,
        )
        .await;

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id],
            &[user_id, second_user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn report_403_deleted_user() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        app.context
            .octopus_database
            .update_user_roles(
                user_id,
                &[
                    ROLE_ADMIN.to_string(),
                    ROLE_COMPANY_ADMIN_USER.to_string(),
                    ROLE_PRIVATE_USER.to_string(),
                    ROLE_PUBLIC_USER.to_string(),
                ],
            )
            .await
            .unwrap();

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let (name, r#type) = api::workspaces::tests::get_workspace_create_params_public();
        let message = api::chat_messages::tests::get_chat_message_create_params();
        let (chat_id, chat_message_id, workspace_id) =
            api::chat_messages::tests::chat_message_with_deps_create(
                router.clone(),
                session_id,
                user_id,
                &message,
                &name,
                &r#type,
            )
            .await;

        sleep(Duration::from_secs(3)).await;

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        app.context
            .octopus_database
            .insert_chat_token_audit(
                &mut transaction,
                chat_id,
                chat_message_id,
                company_id,
                user_id,
                100,
                "test_llm",
                "test_model",
                100,
            )
            .await
            .unwrap();

        api::tests::transaction_commit(app.context.clone(), transaction).await;

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(app.context.clone(), &mut transaction, &[], &[user_id])
            .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("/api/v1/chat-token-audits/{company_id}/report"))
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

        api::chat_messages::tests::chat_message_with_deps_cleanup(
            app.context.clone(),
            &mut transaction,
            chat_id,
            chat_message_id,
            workspace_id,
        )
        .await;

        api::setup::tests::setup_cleanup(app.context.clone(), &mut transaction, &[company_id], &[])
            .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn report_404() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        app.context
            .octopus_database
            .update_user_roles(
                user_id,
                &[
                    ROLE_ADMIN.to_string(),
                    ROLE_COMPANY_ADMIN_USER.to_string(),
                    ROLE_PRIVATE_USER.to_string(),
                    ROLE_PUBLIC_USER.to_string(),
                ],
            )
            .await
            .unwrap();

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let wrong_company_id = "33847746-0030-4964-a496-f75d04499160";

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!(
                        "/api/v1/chat-token-audits/{wrong_company_id}/report"
                    ))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id],
            &[user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }
}
