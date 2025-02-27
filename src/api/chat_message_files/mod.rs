use crate::{
    PUBLIC_DIR,
    context::Context,
    entity::ChatMessageFile,
    error::{AppError, ResponseError},
    session::{ExtractedSession, require_authenticated},
};
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::{Html, IntoResponse},
};
use serde::Deserialize;
use std::{
    fs::{read_to_string, remove_file},
    sync::Arc,
};
use utoipa::IntoParams;
use uuid::Uuid;

#[derive(Deserialize, IntoParams)]
pub struct Params {
    chat_message_id: Uuid,
    chat_message_file_id: Uuid,
}

#[axum_macros::debug_handler]
#[utoipa::path(
    delete,
    path = "/api/v1/chat-message-files/:chat_message_id/:chat_message_file_id",
    responses(
        (status = 204, description = "Chat message file deleted."),
        (status = 401, description = "Unauthorized.", body = ResponseError),
        (status = 403, description = "Forbidden.", body = ResponseError),
        (status = 404, description = "Chat message file not found.", body = ResponseError),
    ),
    params(
        ("chat_message_id" = String, Path, description = "Chat message id"),
        ("chat_message_file_id" = String, Path, description = "Chat message file id")
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn delete(
    State(context): State<Arc<Context>>,
    extracted_session: ExtractedSession,
    Path(Params {
        chat_message_id,
        chat_message_file_id,
    }): Path<Params>,
) -> Result<impl IntoResponse, AppError> {
    let session = require_authenticated(extracted_session).await?;

    context
        .octopus_database
        .try_get_user_by_id(session.user_id)
        .await?
        .ok_or(AppError::Forbidden)?;

    let chat_message_file = context
        .octopus_database
        .try_get_chat_message_file_by_id(chat_message_file_id)
        .await?
        .ok_or(AppError::NotFound)?;

    if chat_message_id != chat_message_file.chat_message_id {
        return Err(AppError::Forbidden);
    }

    let chat_message = context
        .octopus_database
        .try_get_chat_message_by_id(chat_message_file.chat_message_id)
        .await?
        .ok_or(AppError::NotFound)?;

    if chat_message.user_id != session.user_id {
        return Err(AppError::Forbidden);
    }

    let path = format!("{PUBLIC_DIR}/{}", chat_message_file.file_name);

    let mut transaction = context.octopus_database.transaction_begin().await?;

    context
        .octopus_database
        .try_delete_chat_message_file_by_id(&mut transaction, chat_message_file.id)
        .await?
        .ok_or(AppError::NotFound)?;

    let file_exists = std::path::Path::new(&path).is_file();

    if file_exists {
        remove_file(path)?;
    }

    context
        .octopus_database
        .transaction_commit(transaction)
        .await?;

    Ok((StatusCode::NO_CONTENT, ()).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    get,
    path = "/api/v1/chat-message-files/:chat_message_id",
    responses(
        (status = 200, description = "List of chat message files.", body = [ChatMessageFile]),
        (status = 401, description = "Unauthorized.", body = ResponseError),
        (status = 403, description = "Forbidden.", body = ResponseError),
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn list(
    State(context): State<Arc<Context>>,
    extracted_session: ExtractedSession,
    Path(chat_message_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let session = require_authenticated(extracted_session).await?;

    context
        .octopus_database
        .try_get_user_by_id(session.user_id)
        .await?
        .ok_or(AppError::Forbidden)?;

    let chat_message = context
        .octopus_database
        .try_get_chat_message_by_id(chat_message_id)
        .await?;

    if let Some(chat_message) = chat_message {
        if chat_message.user_id != session.user_id {
            return Err(AppError::Forbidden);
        }

        let mut chat_message_files = vec![];
        let chat_message_files_tmp = context
            .octopus_database
            .get_chat_message_files_by_chat_message_id(chat_message.id)
            .await?;

        for mut chat_message_file in chat_message_files_tmp {
            chat_message_file.file_name = format!("{PUBLIC_DIR}/{}", chat_message_file.file_name);
            chat_message_files.push(chat_message_file);
        }

        return Ok((StatusCode::OK, Json(chat_message_files)).into_response());
    }

    Ok((StatusCode::OK, Json(())).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    get,
    path = "/api/v1/chat-message-files/:chat_message_id/:chat_message_file_id",
    responses(
        (status = 200, description = "Chat message file read.", body = ChatMessageFile),
        (status = 401, description = "Unauthorized.", body = ResponseError),
        (status = 403, description = "Forbidden.", body = ResponseError),
        (status = 404, description = "Chat message file not found.", body = ResponseError),
    ),
    params(
        ("chat_message_id" = String, Path, description = "Chat message id"),
        ("chat_message_file_id" = String, Path, description = "Chat message file id")
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn read(
    State(context): State<Arc<Context>>,
    extracted_session: ExtractedSession,
    Path(Params {
        chat_message_id,
        chat_message_file_id,
    }): Path<Params>,
) -> Result<impl IntoResponse, AppError> {
    let session = require_authenticated(extracted_session).await?;

    context
        .octopus_database
        .try_get_user_by_id(session.user_id)
        .await?
        .ok_or(AppError::Forbidden)?;

    let mut chat_message_file = context
        .octopus_database
        .try_get_chat_message_file_by_id(chat_message_file_id)
        .await?
        .ok_or(AppError::NotFound)?;

    chat_message_file.file_name = format!("{PUBLIC_DIR}/{}", chat_message_file.file_name);

    if chat_message_id != chat_message_file.chat_message_id {
        return Err(AppError::Forbidden);
    }

    let chat_message = context
        .octopus_database
        .try_get_chat_message_by_id(chat_message_file.chat_message_id)
        .await?
        .ok_or(AppError::NotFound)?;

    if chat_message.user_id != session.user_id {
        return Err(AppError::Forbidden);
    }

    Ok((StatusCode::OK, Json(chat_message_file)).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    get,
    path = "/api/v1/chat-message-files/:chat_message_id/:chat_message_file_id/render-html",
    responses(
        (status = 200, description = "Chat message file read render html.", body = String),
        (status = 404, description = "Chat message file not found.", body = ResponseError),
    ),
    params(
        ("chat_message_id" = String, Path, description = "Chat message id"),
        ("chat_message_file_id" = String, Path, description = "Chat message file id")
    ),
    security()
)]
pub async fn read_render_html(
    State(context): State<Arc<Context>>,
    Path(Params {
        chat_message_id,
        chat_message_file_id,
    }): Path<Params>,
) -> Result<impl IntoResponse, AppError> {
    let chat_message_file = context
        .octopus_database
        .try_get_chat_message_file_by_id(chat_message_file_id)
        .await?
        .ok_or(AppError::NotFound)?;

    if chat_message_id != chat_message_file.chat_message_id {
        return Err(AppError::Forbidden);
    }

    let chat_message = context
        .octopus_database
        .try_get_chat_message_by_id(chat_message_file.chat_message_id)
        .await?
        .ok_or(AppError::NotFound)?;

    let chat_message_files = context
        .octopus_database
        .get_chat_message_files_by_chat_message_id(chat_message.id)
        .await?;

    let file_name = format!("{PUBLIC_DIR}/{}", chat_message_file.file_name);
    let mut content = read_to_string(file_name)?;

    for chat_message_file in chat_message_files {
        if let Some(original_file_name) = chat_message_file.original_file_name {
            if content.contains(&original_file_name) {
                let new_file_name = format!("/{PUBLIC_DIR}/{}", chat_message_file.file_name);
                content = content.replace(&original_file_name, &new_file_name);
            }
        }
    }

    Ok((StatusCode::OK, Html(content)).into_response())
}

#[cfg(test)]
mod tests {
    use crate::{api, app, entity::ChatMessageFile};
    use axum::{
        body::Body,
        http::{self, Request, StatusCode},
    };
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    #[tokio::test]
    async fn delete_204() {
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

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        let file_name = "33847746-0030-4964-a496-f75d04499160.png";
        let chat_message_file = app
            .context
            .octopus_database
            .insert_chat_message_file(
                &mut transaction,
                chat_message_id,
                file_name,
                "image/png",
                None,
            )
            .await
            .unwrap();

        api::tests::transaction_commit(app.context.clone(), transaction).await;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::DELETE)
                    .uri(format!(
                        "/api/v1/chat-message-files/{}/{}",
                        chat_message_id, chat_message_file.id
                    ))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NO_CONTENT);

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
    async fn delete_401() {
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

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        let file_name = "33847746-0030-4964-a496-f75d04499160.png";
        let chat_message_file = app
            .context
            .octopus_database
            .insert_chat_message_file(
                &mut transaction,
                chat_message_id,
                file_name,
                "image/png",
                None,
            )
            .await
            .unwrap();

        api::tests::transaction_commit(app.context.clone(), transaction).await;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::DELETE)
                    .uri(format!(
                        "/api/v1/chat-message-files/{}/{}",
                        chat_message_id, chat_message_file.id
                    ))
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
    async fn delete_403() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let admin_session_id = session_response.id;

        let (email, is_enabled, job_title, name, password, roles) =
            api::users::tests::get_user_create_params();
        let user = api::users::tests::user_create(
            router.clone(),
            admin_session_id,
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

        let (name, r#type) = api::workspaces::tests::get_workspace_create_params_public();
        let message = api::chat_messages::tests::get_chat_message_create_params();
        let (chat_id, chat_message_id, workspace_id) =
            api::chat_messages::tests::chat_message_with_deps_create(
                router.clone(),
                admin_session_id,
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

        let file_name = "33847746-0030-4964-a496-f75d04499160.png";
        let chat_message_file = app
            .context
            .octopus_database
            .insert_chat_message_file(
                &mut transaction,
                chat_message_id,
                file_name,
                "image/png",
                None,
            )
            .await
            .unwrap();

        api::tests::transaction_commit(app.context.clone(), transaction).await;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::DELETE)
                    .uri(format!(
                        "/api/v1/chat-message-files/{}/{}",
                        chat_message_id, chat_message_file.id
                    ))
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
            .try_delete_chat_message_file_by_id(&mut transaction, chat_message_file.id)
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
    async fn delete_403_wrong_id() {
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

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        let file_name = "33847746-0030-4964-a496-f75d04499160.png";
        let chat_message_file = app
            .context
            .octopus_database
            .insert_chat_message_file(
                &mut transaction,
                chat_message_id,
                file_name,
                "image/png",
                None,
            )
            .await
            .unwrap();

        api::tests::transaction_commit(app.context.clone(), transaction).await;

        let wrong_chat_message_id = "33847746-0030-4964-a496-f75d04499160";

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::DELETE)
                    .uri(format!(
                        "/api/v1/chat-message-files/{}/{}",
                        wrong_chat_message_id, chat_message_file.id
                    ))
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
            &[user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn delete_403_different_company_admin() {
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

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        let file_name = "33847746-0030-4964-a496-f75d04499160.png";
        let chat_message_file = app
            .context
            .octopus_database
            .insert_chat_message_file(
                &mut transaction,
                chat_message_id,
                file_name,
                "image/png",
                None,
            )
            .await
            .unwrap();

        api::tests::transaction_commit(app.context.clone(), transaction).await;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let second_company_id = user.company_id;
        let second_user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, second_user_id)
                .await;
        let session_id = session_response.id;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::DELETE)
                    .uri(format!(
                        "/api/v1/chat-message-files/{}/{}",
                        chat_message_id, chat_message_file.id
                    ))
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
            .try_delete_chat_message_file_by_id(&mut transaction, chat_message_file.id)
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
    async fn delete_403_deleted_user() {
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

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        let file_name = "33847746-0030-4964-a496-f75d04499160.png";
        let chat_message_file = app
            .context
            .octopus_database
            .insert_chat_message_file(
                &mut transaction,
                chat_message_id,
                file_name,
                "image/png",
                None,
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
                    .method(http::Method::DELETE)
                    .uri(format!(
                        "/api/v1/chat-message-files/{}/{}",
                        chat_message_id, chat_message_file.id
                    ))
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
    async fn delete_404() {
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

        let chat_message_file_id = "33847746-0030-4964-a496-f75d04499160";

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::DELETE)
                    .uri(format!(
                        "/api/v1/chat-message-files/{chat_message_id}/{chat_message_file_id}"
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
    async fn list_200() {
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

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        let file_name = "33847746-0030-4964-a496-f75d04499160.png";
        let chat_message_file = app
            .context
            .octopus_database
            .insert_chat_message_file(
                &mut transaction,
                chat_message_id,
                file_name,
                "image/png",
                None,
            )
            .await
            .unwrap();

        api::tests::transaction_commit(app.context.clone(), transaction).await;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("/api/v1/chat-message-files/{chat_message_id}"))
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
        let body: Vec<ChatMessageFile> = serde_json::from_slice(&body).unwrap();

        assert!(!body.is_empty());

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_chat_message_file_by_id(&mut transaction, chat_message_file.id)
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

        let file_name = "33847746-0030-4964-a496-f75d04499160.png";
        let chat_message_file = app
            .context
            .octopus_database
            .insert_chat_message_file(
                &mut transaction,
                chat_message_id,
                file_name,
                "image/png",
                None,
            )
            .await
            .unwrap();

        api::tests::transaction_commit(app.context.clone(), transaction).await;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("/api/v1/chat-message-files/{chat_message_id}"))
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

        app.context
            .octopus_database
            .try_delete_chat_message_file_by_id(&mut transaction, chat_message_file.id)
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

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        let file_name = "33847746-0030-4964-a496-f75d04499160.png";
        let chat_message_file = app
            .context
            .octopus_database
            .insert_chat_message_file(
                &mut transaction,
                chat_message_id,
                file_name,
                "image/png",
                None,
            )
            .await
            .unwrap();

        api::tests::transaction_commit(app.context.clone(), transaction).await;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let second_company_id = user.company_id;
        let second_user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, second_user_id)
                .await;
        let session_id = session_response.id;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!(
                        "/api/v1/chat-message-files/{}/{}",
                        chat_message_id, chat_message_file.id
                    ))
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
            .try_delete_chat_message_file_by_id(&mut transaction, chat_message_file.id)
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

        let file_name = "33847746-0030-4964-a496-f75d04499160.png";
        let chat_message_file = app
            .context
            .octopus_database
            .insert_chat_message_file(
                &mut transaction,
                chat_message_id,
                file_name,
                "image/png",
                None,
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
                    .uri(format!("/api/v1/chat-message-files/{chat_message_id}"))
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
            .try_delete_chat_message_file_by_id(&mut transaction, chat_message_file.id)
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

        let file_name = "33847746-0030-4964-a496-f75d04499160.png";
        let chat_message_file = app
            .context
            .octopus_database
            .insert_chat_message_file(
                &mut transaction,
                chat_message_id,
                file_name,
                "image/png",
                None,
            )
            .await
            .unwrap();

        api::tests::transaction_commit(app.context.clone(), transaction).await;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!(
                        "/api/v1/chat-message-files/{}/{}",
                        chat_message_id, chat_message_file.id
                    ))
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
        let body: ChatMessageFile = serde_json::from_slice(&body).unwrap();

        assert!(body.file_name.contains(file_name));

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_chat_message_file_by_id(&mut transaction, chat_message_file.id)
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

        let file_name = "33847746-0030-4964-a496-f75d04499160.png";
        let chat_message_file = app
            .context
            .octopus_database
            .insert_chat_message_file(
                &mut transaction,
                chat_message_id,
                file_name,
                "image/png",
                None,
            )
            .await
            .unwrap();

        api::tests::transaction_commit(app.context.clone(), transaction).await;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!(
                        "/api/v1/chat-message-files/{}/{}",
                        chat_message_id, chat_message_file.id
                    ))
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

        app.context
            .octopus_database
            .try_delete_chat_message_file_by_id(&mut transaction, chat_message_file.id)
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

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        let file_name = "33847746-0030-4964-a496-f75d04499160.png";
        let chat_message_file = app
            .context
            .octopus_database
            .insert_chat_message_file(
                &mut transaction,
                chat_message_id,
                file_name,
                "image/png",
                None,
            )
            .await
            .unwrap();

        api::tests::transaction_commit(app.context.clone(), transaction).await;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let second_company_id = user.company_id;
        let second_user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, second_user_id)
                .await;
        let session_id = session_response.id;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!(
                        "/api/v1/chat-message-files/{}/{}",
                        chat_message_id, chat_message_file.id
                    ))
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
            .try_delete_chat_message_file_by_id(&mut transaction, chat_message_file.id)
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
    async fn read_403_wrong_id() {
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

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        let file_name = "33847746-0030-4964-a496-f75d04499160.png";
        let chat_message_file = app
            .context
            .octopus_database
            .insert_chat_message_file(
                &mut transaction,
                chat_message_id,
                file_name,
                "image/png",
                None,
            )
            .await
            .unwrap();

        api::tests::transaction_commit(app.context.clone(), transaction).await;

        let wrong_chat_message_id = "33847746-0030-4964-a496-f75d04499160";

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!(
                        "/api/v1/chat-message-files/{}/{}",
                        wrong_chat_message_id, chat_message_file.id
                    ))
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
            .try_delete_chat_message_file_by_id(&mut transaction, chat_message_file.id)
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
    async fn read_403_deleted_user() {
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

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        let file_name = "33847746-0030-4964-a496-f75d04499160.png";
        let chat_message_file = app
            .context
            .octopus_database
            .insert_chat_message_file(
                &mut transaction,
                chat_message_id,
                file_name,
                "image/png",
                None,
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
                    .uri(format!(
                        "/api/v1/chat-message-files/{}/{}",
                        chat_message_id, chat_message_file.id
                    ))
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
            .try_delete_chat_message_file_by_id(&mut transaction, chat_message_file.id)
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

        let chat_message_file_id = "33847746-0030-4964-a496-f75d04499160";

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!(
                        "/api/v1/chat-message-files/{chat_message_id}/{chat_message_file_id}"
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
}
