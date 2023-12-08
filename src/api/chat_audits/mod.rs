use crate::{
    context::Context,
    entity::ROLE_ADMIN,
    error::AppError,
    session::{ensure_secured, ExtractedSession},
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
    ensure_secured(context.clone(), extracted_session, ROLE_ADMIN).await?;

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
    ensure_secured(context.clone(), extracted_session, ROLE_ADMIN).await?;

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
    use fake::{faker::lorem::en::Word, Fake};
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

        let name = format!("workspace {}", Word().fake::<String>());
        let r#type = "Public";

        let workspace = api::workspaces::tests::workspace_create(
            router.clone(),
            session_id,
            user_id,
            &name,
            r#type,
        )
        .await;
        let workspace_id = workspace.id;

        let chat =
            api::chats::tests::chat_create(router.clone(), session_id, user_id, workspace_id).await;
        let chat_id = chat.id;

        let message = "test message";

        let chat_message = api::chat_messages::tests::chat_message_create(
            router.clone(),
            session_id,
            chat_id,
            user_id,
            message,
        )
        .await;
        let chat_message_id = chat_message.id;

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
            .try_delete_chat_by_id(&mut transaction, chat_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_chat_message_by_id(&mut transaction, chat_message_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_workspace_by_id(&mut transaction, workspace_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .transaction_commit(transaction)
            .await
            .unwrap();
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

        let name = format!("workspace {}", Word().fake::<String>());
        let r#type = "Public";

        let workspace = api::workspaces::tests::workspace_create(
            router.clone(),
            session_id,
            user_id,
            &name,
            r#type,
        )
        .await;
        let workspace_id = workspace.id;

        let chat =
            api::chats::tests::chat_create(router.clone(), session_id, user_id, workspace_id).await;
        let chat_id = chat.id;

        let message = "test message";

        let chat_message = api::chat_messages::tests::chat_message_create(
            router.clone(),
            session_id,
            chat_id,
            user_id,
            message,
        )
        .await;
        let chat_message_id = chat_message.id;

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
            .try_delete_company_by_id(&mut transaction, second_company_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_chat_by_id(&mut transaction, chat_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_chat_message_by_id(&mut transaction, chat_message_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_workspace_by_id(&mut transaction, workspace_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .transaction_commit(transaction)
            .await
            .unwrap();
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

        let name = format!("workspace {}", Word().fake::<String>());
        let r#type = "Public";

        let workspace = api::workspaces::tests::workspace_create(
            router.clone(),
            session_id,
            user_id,
            &name,
            r#type,
        )
        .await;
        let workspace_id = workspace.id;

        let chat =
            api::chats::tests::chat_create(router.clone(), session_id, user_id, workspace_id).await;
        let chat_id = chat.id;

        let message = "test message";

        let chat_message = api::chat_messages::tests::chat_message_create(
            router.clone(),
            session_id,
            chat_id,
            user_id,
            message,
        )
        .await;
        let chat_message_id = chat_message.id;

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
            .try_delete_chat_by_id(&mut transaction, chat_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_chat_message_by_id(&mut transaction, chat_message_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_workspace_by_id(&mut transaction, workspace_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .transaction_commit(transaction)
            .await
            .unwrap();
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

        let name = format!("workspace {}", Word().fake::<String>());
        let r#type = "Public";

        let workspace = api::workspaces::tests::workspace_create(
            router.clone(),
            session_id,
            user_id,
            &name,
            r#type,
        )
        .await;
        let workspace_id = workspace.id;

        let chat =
            api::chats::tests::chat_create(router.clone(), session_id, user_id, workspace_id).await;
        let chat_id = chat.id;

        let message = "test message";

        let chat_message = api::chat_messages::tests::chat_message_create(
            router.clone(),
            session_id,
            chat_id,
            user_id,
            message,
        )
        .await;
        let chat_message_id = chat_message.id;

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
            .try_delete_company_by_id(&mut transaction, second_company_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_chat_by_id(&mut transaction, chat_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_chat_message_by_id(&mut transaction, chat_message_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_workspace_by_id(&mut transaction, workspace_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .transaction_commit(transaction)
            .await
            .unwrap();
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
}
