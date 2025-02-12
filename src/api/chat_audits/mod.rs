use crate::{
    context::Context,
    entity::{ChatAudit, ROLE_ADMIN},
    error::{AppError, ResponseError},
    session::{require_authenticated, ExtractedSession},
};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use std::sync::Arc;
use uuid::Uuid;

#[axum_macros::debug_handler]
#[utoipa::path(
    get,
    path = "/api/v1/chat-audits",
    responses(
        (status = 200, description = "List of chat audits.", body = [ChatAudit]),
        (status = 401, description = "Unauthorized request.", body = ResponseError),
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

    if !session_user.roles.contains(&ROLE_ADMIN.to_string()) {
        return Err(AppError::Forbidden);
    }

    let chat_audits = context.octopus_database.get_chat_audits().await?;

    Ok((StatusCode::OK, Json(chat_audits)).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    get,
    path = "/api/v1/chat-audits/:chat_audit_id",
    responses(
        (status = 200, description = "Chat audit read.", body = ChatAudit),
        (status = 403, description = "Forbidden.", body = ResponseError),
        (status = 401, description = "Unauthorized request.", body = ResponseError),
        (status = 404, description = "Chat audit not found.", body = ResponseError),
    ),
    params(
        ("chat_audit_id" = String, Path, description = "Chat audit id")
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn read(
    State(context): State<Arc<Context>>,
    extracted_session: ExtractedSession,
    Path(chat_audit_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let session = require_authenticated(extracted_session).await?;

    let session_user = context
        .octopus_database
        .try_get_user_by_id(session.user_id)
        .await?
        .ok_or(AppError::Forbidden)?;

    if !session_user.roles.contains(&ROLE_ADMIN.to_string()) {
        return Err(AppError::Forbidden);
    }

    let chat_audit = context
        .octopus_database
        .try_get_chat_audit_by_id(chat_audit_id)
        .await?
        .ok_or(AppError::NotFound)?;

    Ok((StatusCode::OK, Json(chat_audit)).into_response())
}

#[cfg(test)]
mod tests {
    use crate::{
        api, app,
        entity::{
            ChatAudit, ROLE_ADMIN, ROLE_COMPANY_ADMIN_USER, ROLE_PRIVATE_USER, ROLE_PUBLIC_USER,
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

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        app.context
            .octopus_database
            .insert_chat_audit(
                &mut transaction,
                chat_id,
                chat_message_id,
                user_id,
                serde_json::Value::Null,
            )
            .await
            .unwrap();

        api::tests::transaction_commit(app.context.clone(), transaction).await;

        sleep(Duration::from_secs(2)).await;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri("/api/v1/chat-audits")
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
        let body: Vec<ChatAudit> = serde_json::from_slice(&body).unwrap();

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

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri("/api/v1/chat-audits")
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

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let second_company_id = user.company_id;
        let second_user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, second_user_id)
                .await;
        let session_id = session_response.id;

        sleep(Duration::from_secs(2)).await;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri("/api/v1/chat-audits")
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
            &[company_id, second_company_id],
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

        api::setup::tests::setup_cleanup(app.context.clone(), &mut transaction, &[], &[user_id])
            .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri("/api/v1/chat-audits")
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

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        app.context
            .octopus_database
            .insert_chat_audit(
                &mut transaction,
                chat_id,
                chat_message_id,
                user_id,
                serde_json::Value::Null,
            )
            .await
            .unwrap();

        api::tests::transaction_commit(app.context.clone(), transaction).await;

        sleep(Duration::from_secs(3)).await;

        let chat_audit = app
            .context
            .octopus_database
            .try_get_chat_audit_by_chat_message_id(chat_message_id)
            .await
            .unwrap()
            .unwrap();

        let chat_audit_id = chat_audit.id;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("/api/v1/chat-audits/{chat_audit_id}"))
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
        let body: ChatAudit = serde_json::from_slice(&body).unwrap();

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

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        app.context
            .octopus_database
            .insert_chat_audit(
                &mut transaction,
                chat_id,
                chat_message_id,
                user_id,
                serde_json::Value::Null,
            )
            .await
            .unwrap();

        api::tests::transaction_commit(app.context.clone(), transaction).await;

        sleep(Duration::from_secs(3)).await;

        let chat_audit = app
            .context
            .octopus_database
            .try_get_chat_audit_by_chat_message_id(chat_message_id)
            .await
            .unwrap()
            .unwrap();

        let chat_audit_id = chat_audit.id;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("/api/v1/chat-audits/{chat_audit_id}"))
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

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let second_company_id = user.company_id;
        let second_user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, second_user_id)
                .await;
        let session_id = session_response.id;

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        app.context
            .octopus_database
            .insert_chat_audit(
                &mut transaction,
                chat_id,
                chat_message_id,
                user_id,
                serde_json::Value::Null,
            )
            .await
            .unwrap();

        api::tests::transaction_commit(app.context.clone(), transaction).await;

        sleep(Duration::from_secs(2)).await;

        let chat_audit = app
            .context
            .octopus_database
            .try_get_chat_audit_by_chat_message_id(chat_message_id)
            .await
            .unwrap()
            .unwrap();

        let chat_audit_id = chat_audit.id;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("/api/v1/chat-audits/{chat_audit_id}"))
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
            &[company_id, second_company_id],
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

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        app.context
            .octopus_database
            .insert_chat_audit(
                &mut transaction,
                chat_id,
                chat_message_id,
                user_id,
                serde_json::Value::Null,
            )
            .await
            .unwrap();

        api::tests::transaction_commit(app.context.clone(), transaction).await;

        sleep(Duration::from_secs(3)).await;

        let chat_audit = app
            .context
            .octopus_database
            .try_get_chat_audit_by_chat_message_id(chat_message_id)
            .await
            .unwrap()
            .unwrap();

        let chat_audit_id = chat_audit.id;

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
                    .uri(format!("/api/v1/chat-audits/{chat_audit_id}"))
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

        let chat_audit_id = "33847746-0030-4964-a496-f75d04499160";

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("/api/v1/chat-audits/{chat_audit_id}"))
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
