use crate::{
    context::Context,
    entity::{WorkspacesType, ROLE_COMPANY_ADMIN_USER, ROLE_PRIVATE_USER},
    error::AppError,
    session::{require_authenticated, ExtractedSession},
    PUBLIC_DIR,
};
use axum::{
    extract::{Multipart, Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use std::{
    fs::{remove_file, File},
    io::Write,
    sync::Arc,
};
use utoipa::IntoParams;
use uuid::Uuid;

#[derive(Deserialize, IntoParams)]
pub struct Params {
    chat_message_id: Uuid,
    chat_message_picture_id: Uuid,
}

#[axum_macros::debug_handler]
#[utoipa::path(
    post,
    path = "/api/v1/chat-message-pictures/:chat_message_id",
    responses(
        (status = 201, description = "Chat message picture created.", body = ChatMessagePicture),
        (status = 401, description = "Unauthorized.", body = ResponseError),
        (status = 403, description = "Forbidden.", body = ResponseError),
        (status = 404, description = "Chat not found.", body = ResponseError),
    ),
    params(
        ("chat_message_id" = String, Path, description = "Chat message id"),
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn create(
    State(context): State<Arc<Context>>,
    extracted_session: ExtractedSession,
    Path(chat_message_id): Path<Uuid>,
    mut multipart: Multipart,
) -> Result<impl IntoResponse, AppError> {
    let session = require_authenticated(extracted_session).await?;

    let session_user = context
        .octopus_database
        .try_get_user_by_id(session.user_id)
        .await?
        .ok_or(AppError::Forbidden)?;

    let chat_message = context
        .octopus_database
        .try_get_chat_message_by_id(chat_message_id)
        .await?
        .ok_or(AppError::NotFound)?;

    let chat = context
        .octopus_database
        .try_get_chat_by_id(chat_message.chat_id)
        .await?
        .ok_or(AppError::NotFound)?;

    let user = context
        .octopus_database
        .try_get_user_by_id(chat.user_id)
        .await?
        .ok_or(AppError::NotFound)?;

    let workspace = context
        .octopus_database
        .try_get_workspace_by_id(chat.workspace_id)
        .await?
        .ok_or(AppError::NotFound)?;

    match workspace.r#type {
        WorkspacesType::Private => {
            if session_user.id != chat_message.user_id
                && !session_user.roles.contains(&ROLE_PRIVATE_USER.to_string())
            {
                return Err(AppError::Forbidden);
            }
        }
        WorkspacesType::Public => {
            if session_user.id != chat_message.user_id || session_user.company_id != user.company_id
            {
                return Err(AppError::Forbidden);
            }
        }
    }

    while let Some(field) = multipart.next_field().await? {
        let extension = (*field
            .file_name()
            .ok_or(AppError::File)?
            .to_string()
            .split('.')
            .collect::<Vec<&str>>()
            .last()
            .ok_or(AppError::File)?)
        .to_string();
        let content_image = (*field
            .content_type()
            .ok_or(AppError::File)?
            .to_string()
            .split('/')
            .collect::<Vec<&str>>()
            .first()
            .ok_or(AppError::File)?)
        .to_string();

        if content_image == "image" {
            let data = field.bytes().await?;

            let file_name = format!("{}.{}", Uuid::new_v4(), extension);
            let path = format!("{PUBLIC_DIR}/{file_name}");

            let mut file = File::create(path)?;
            file.write_all(&data)?;

            let mut transaction = context.octopus_database.transaction_begin().await?;

            let mut chat_message_picture = context
                .octopus_database
                .insert_chat_message_picture(&mut transaction, chat_message.id, &file_name)
                .await?;

            context
                .octopus_database
                .transaction_commit(transaction)
                .await?;

            chat_message_picture.file_name =
                format!("{PUBLIC_DIR}/{}", chat_message_picture.file_name);

            return Ok((StatusCode::CREATED, Json(chat_message_picture)).into_response());
        }
    }

    Err(AppError::BadRequest)
}

#[axum_macros::debug_handler]
#[utoipa::path(
    delete,
    path = "/api/v1/chat-message-pictures/:chat_message_id/:chat_message_picture_id",
    responses(
        (status = 204, description = "Chat message picture deleted."),
        (status = 401, description = "Unauthorized.", body = ResponseError),
        (status = 403, description = "Forbidden.", body = ResponseError),
        (status = 404, description = "Chat message picture not found.", body = ResponseError),
    ),
    params(
        ("chat_message_id" = String, Path, description = "Chat message id"),
        ("chat_message_picture_id" = String, Path, description = "Chat message picture id")
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
        chat_message_picture_id,
    }): Path<Params>,
) -> Result<impl IntoResponse, AppError> {
    let session = require_authenticated(extracted_session).await?;

    let session_user = context
        .octopus_database
        .try_get_user_by_id(session.user_id)
        .await?
        .ok_or(AppError::Forbidden)?;

    let chat_message_picture = context
        .octopus_database
        .try_get_chat_message_picture_by_id(chat_message_picture_id)
        .await?
        .ok_or(AppError::NotFound)?;

    if chat_message_id != chat_message_picture.chat_message_id {
        return Err(AppError::Forbidden);
    }

    let chat_message = context
        .octopus_database
        .try_get_chat_message_by_id(chat_message_picture.chat_message_id)
        .await?
        .ok_or(AppError::NotFound)?;

    let user = context
        .octopus_database
        .try_get_user_by_id(chat_message.user_id)
        .await?
        .ok_or(AppError::NotFound)?;

    if session_user.id != chat_message.user_id
        && (!session_user
            .roles
            .contains(&ROLE_COMPANY_ADMIN_USER.to_string())
            || session_user.company_id != user.company_id)
    {
        return Err(AppError::Forbidden);
    }

    let mut transaction = context.octopus_database.transaction_begin().await?;

    context
        .octopus_database
        .try_delete_chat_message_picture_by_id(&mut transaction, chat_message_picture.id)
        .await?
        .ok_or(AppError::NotFound)?;

    let path = format!("{PUBLIC_DIR}/{}", chat_message_picture.file_name);
    remove_file(path)?;

    context
        .octopus_database
        .transaction_commit(transaction)
        .await?;

    Ok((StatusCode::NO_CONTENT, ()).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    get,
    path = "/api/v1/chat-message-pictures/:chat_message_id/:chat_message_picture_id",
    responses(
        (status = 200, description = "Chat message picture read.", body = ChatMessagePicture),
        (status = 401, description = "Unauthorized.", body = ResponseError),
        (status = 403, description = "Forbidden.", body = ResponseError),
        (status = 404, description = "Chat message picture not found.", body = ResponseError),
    ),
    params(
        ("chat_message_id" = String, Path, description = "Chat message id"),
        ("chat_message_picture_id" = String, Path, description = "Chat message picture id")
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
        chat_message_picture_id,
    }): Path<Params>,
) -> Result<impl IntoResponse, AppError> {
    let session = require_authenticated(extracted_session).await?;

    let session_user = context
        .octopus_database
        .try_get_user_by_id(session.user_id)
        .await?
        .ok_or(AppError::Forbidden)?;

    let mut chat_message_picture = context
        .octopus_database
        .try_get_chat_message_picture_by_id(chat_message_picture_id)
        .await?
        .ok_or(AppError::NotFound)?;

    chat_message_picture.file_name = format!("{PUBLIC_DIR}/{}", chat_message_picture.file_name);

    if chat_message_id != chat_message_picture.chat_message_id {
        return Err(AppError::Forbidden);
    }

    let chat_message = context
        .octopus_database
        .try_get_chat_message_by_id(chat_message_picture.chat_message_id)
        .await?
        .ok_or(AppError::NotFound)?;

    let user = context
        .octopus_database
        .try_get_user_by_id(chat_message.user_id)
        .await?
        .ok_or(AppError::NotFound)?;

    if session_user.id != chat_message.user_id || session_user.company_id != user.company_id {
        return Err(AppError::Forbidden);
    }

    Ok((StatusCode::OK, Json(chat_message_picture)).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    put,
    path = "/api/v1/chat-message-pictures/:chat_message_id/:chat_message_picture_id",
    responses(
        (status = 200, description = "Chat message picture updated.", body = ChatMessagePicture),
        (status = 401, description = "Unauthorized.", body = ResponseError),
        (status = 403, description = "Forbidden.", body = ResponseError),
        (status = 404, description = "Chat message picture not found.", body = ResponseError),
    ),
    params(
        ("chat_message_id" = String, Path, description = "Chat message id"),
        ("chat_message_picture_id" = String, Path, description = "Chat message picture id")
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn update(
    State(context): State<Arc<Context>>,
    extracted_session: ExtractedSession,
    Path(Params {
        chat_message_id,
        chat_message_picture_id,
    }): Path<Params>,
    mut multipart: Multipart,
) -> Result<impl IntoResponse, AppError> {
    let session = require_authenticated(extracted_session).await?;

    let session_user = context
        .octopus_database
        .try_get_user_by_id(session.user_id)
        .await?
        .ok_or(AppError::Forbidden)?;

    let chat_message_picture = context
        .octopus_database
        .try_get_chat_message_picture_by_id(chat_message_picture_id)
        .await?
        .ok_or(AppError::NotFound)?;

    if chat_message_id != chat_message_picture.chat_message_id {
        return Err(AppError::Forbidden);
    }

    let chat_message = context
        .octopus_database
        .try_get_chat_message_by_id(chat_message_picture.chat_message_id)
        .await?
        .ok_or(AppError::NotFound)?;

    let user = context
        .octopus_database
        .try_get_user_by_id(chat_message.user_id)
        .await?
        .ok_or(AppError::NotFound)?;

    if session_user.id != chat_message.user_id
        && (!session_user
            .roles
            .contains(&ROLE_COMPANY_ADMIN_USER.to_string())
            || session_user.company_id != user.company_id)
    {
        return Err(AppError::Forbidden);
    }

    while let Some(field) = multipart.next_field().await? {
        let extension = (*field
            .file_name()
            .ok_or(AppError::File)?
            .to_string()
            .split('.')
            .collect::<Vec<&str>>()
            .last()
            .ok_or(AppError::File)?)
        .to_string();
        let content_image = (*field
            .content_type()
            .ok_or(AppError::File)?
            .to_string()
            .split('/')
            .collect::<Vec<&str>>()
            .first()
            .ok_or(AppError::File)?)
        .to_string();

        if content_image == "image" {
            let data = field.bytes().await?;

            let old_file = format!("{PUBLIC_DIR}/{}", chat_message_picture.file_name);

            let file_name = format!("{}.{}", Uuid::new_v4(), extension);
            let path = format!("{PUBLIC_DIR}/{file_name}");

            let mut file = File::create(path)?;
            file.write_all(&data)?;

            let mut transaction = context.octopus_database.transaction_begin().await?;

            let mut chat_message_picture = context
                .octopus_database
                .update_chat_message_picture(&mut transaction, chat_message_picture.id, &file_name)
                .await?;

            context
                .octopus_database
                .transaction_commit(transaction)
                .await?;

            chat_message_picture.file_name =
                format!("{PUBLIC_DIR}/{}", chat_message_picture.file_name);

            remove_file(old_file)?;

            return Ok((StatusCode::OK, Json(chat_message_picture)).into_response());
        }
    }

    Err(AppError::BadRequest)
}

#[cfg(test)]
mod tests {
    use crate::{api, app, entity::ChatMessagePicture, multipart};
    use axum::{
        body::Body,
        http::{self, Request, StatusCode},
        Router,
    };
    use http_body_util::BodyExt;
    use tokio::time::{sleep, Duration};
    use tower::ServiceExt;
    use uuid::Uuid;

    pub async fn chat_message_picture_create(
        router: Router,
        session_id: Uuid,
        chat_message_id: Uuid,
    ) -> ChatMessagePicture {
        let body =
            multipart::tests::file_data("image/png", "test.png", "data/test/test.png").unwrap();

        let value = format!(
            "{}; boundary={}",
            mime::MULTIPART_FORM_DATA,
            multipart::tests::BOUNDARY
        );

        let request = Request::builder()
            .method(http::Method::POST)
            .uri(format!("/api/v1/chat-message-pictures/{chat_message_id}"))
            .header(http::header::CONTENT_TYPE, value)
            .header("X-Auth-Token".to_string(), session_id.to_string())
            .body(body)
            .unwrap();

        let response = router.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = BodyExt::collect(response.into_body())
            .await
            .unwrap()
            .to_bytes()
            .to_vec();
        let body: ChatMessagePicture = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.chat_message_id, chat_message_id);

        body
    }

    #[tokio::test]
    async fn create_201() {
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

        let chat_message_picture: ChatMessagePicture =
            chat_message_picture_create(router, session_id, chat_message_id).await;
        let chat_message_picture_id = chat_message_picture.id;

        sleep(Duration::from_secs(1)).await;

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_chat_message_picture_by_id(&mut transaction, chat_message_picture_id)
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
    async fn create_401() {
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

        let body =
            multipart::tests::file_data("image/png", "test.png", "data/test/test.png").unwrap();

        let value = format!(
            "{}; boundary={}",
            mime::MULTIPART_FORM_DATA,
            multipart::tests::BOUNDARY
        );

        let request = Request::builder()
            .method(http::Method::POST)
            .uri(format!("/api/v1/chat-message-pictures/{chat_message_id}"))
            .header(http::header::CONTENT_TYPE, value)
            .body(body)
            .unwrap();

        let response = router.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        sleep(Duration::from_secs(1)).await;

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
    async fn create_403() {
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

        let body =
            multipart::tests::file_data("image/png", "test.png", "data/test/test.png").unwrap();

        let value = format!(
            "{}; boundary={}",
            mime::MULTIPART_FORM_DATA,
            multipart::tests::BOUNDARY
        );

        let request = Request::builder()
            .method(http::Method::POST)
            .uri(format!("/api/v1/chat-message-pictures/{chat_message_id}"))
            .header(http::header::CONTENT_TYPE, value)
            .header("X-Auth-Token".to_string(), session_id.to_string())
            .body(body)
            .unwrap();

        let response = router.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        sleep(Duration::from_secs(1)).await;

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
    async fn create_404() {
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

        let chat_message_id = "33847746-0030-4964-a496-f75d04499160";

        let body =
            multipart::tests::file_data("image/png", "test.png", "data/test/test.png").unwrap();

        let value = format!(
            "{}; boundary={}",
            mime::MULTIPART_FORM_DATA,
            multipart::tests::BOUNDARY
        );

        let request = Request::builder()
            .method(http::Method::POST)
            .uri(format!("/api/v1/chat-message-pictures/{chat_message_id}"))
            .header(http::header::CONTENT_TYPE, value)
            .header("X-Auth-Token".to_string(), session_id.to_string())
            .body(body)
            .unwrap();

        let response = router.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        sleep(Duration::from_secs(1)).await;

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

        let chat_message_picture =
            chat_message_picture_create(router.clone(), session_id, chat_message_id).await;
        let chat_message_picture_id = chat_message_picture.id;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::DELETE)
                    .uri(format!(
                        "/api/v1/chat-message-pictures/{chat_message_id}/{chat_message_picture_id}"
                    ))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        sleep(Duration::from_secs(1)).await;

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

        let chat_message_picture =
            chat_message_picture_create(router.clone(), session_id, chat_message_id).await;
        let chat_message_picture_id = chat_message_picture.id;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::DELETE)
                    .uri(format!(
                        "/api/v1/chat-message-pictures/{chat_message_id}/{chat_message_picture_id}"
                    ))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        sleep(Duration::from_secs(1)).await;

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_chat_message_picture_by_id(&mut transaction, chat_message_picture_id)
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

        let chat_message_picture =
            chat_message_picture_create(router.clone(), session_id, chat_message_id).await;
        let chat_message_picture_id = chat_message_picture.id;

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
                    .method(http::Method::DELETE)
                    .uri(format!(
                        "/api/v1/chat-message-pictures/{chat_message_id}/{chat_message_picture_id}"
                    ))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        sleep(Duration::from_secs(1)).await;

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_chat_message_picture_by_id(&mut transaction, chat_message_picture_id)
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
        let (chat_id, workspace_id) = api::chats::tests::chat_with_deps_create(
            router.clone(),
            session_id,
            user_id,
            &name,
            &r#type,
        )
        .await;

        let chat_message_id = "33847746-0030-4964-a496-f75d04499160";
        let chat_message_picture_id = "33847746-0030-4964-a496-f75d04499160";

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::DELETE)
                    .uri(format!(
                        "/api/v1/chat-message-pictures/{chat_message_id}/{chat_message_picture_id}"
                    ))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        sleep(Duration::from_secs(1)).await;

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        api::chats::tests::chat_with_deps_cleanup(
            app.context.clone(),
            &mut transaction,
            chat_id,
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

        let chat_message_picture =
            chat_message_picture_create(router.clone(), session_id, chat_message_id).await;
        let chat_message_picture_id = chat_message_picture.id;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!(
                        "/api/v1/chat-message-pictures/{chat_message_id}/{chat_message_picture_id}"
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
        let body: ChatMessagePicture = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.chat_message_id, chat_message_id);

        sleep(Duration::from_secs(1)).await;

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_chat_message_picture_by_id(&mut transaction, chat_message_picture_id)
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

        let chat_message_picture =
            chat_message_picture_create(router.clone(), session_id, chat_message_id).await;
        let chat_message_picture_id = chat_message_picture.id;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!(
                        "/api/v1/chat-message-pictures/{chat_message_id}/{chat_message_picture_id}"
                    ))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        sleep(Duration::from_secs(1)).await;

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_chat_message_picture_by_id(&mut transaction, chat_message_picture_id)
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

        let chat_message_picture =
            chat_message_picture_create(router.clone(), session_id, chat_message_id).await;
        let chat_message_picture_id = chat_message_picture.id;

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
                    .uri(format!(
                        "/api/v1/chat-message-pictures/{chat_message_id}/{chat_message_picture_id}"
                    ))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        sleep(Duration::from_secs(1)).await;

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_chat_message_picture_by_id(&mut transaction, chat_message_picture_id)
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
        let (chat_id, workspace_id) = api::chats::tests::chat_with_deps_create(
            router.clone(),
            session_id,
            user_id,
            &name,
            &r#type,
        )
        .await;

        let chat_message_id = "33847746-0030-4964-a496-f75d04499160";
        let chat_message_picture_id = "33847746-0030-4964-a496-f75d04499160";

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!(
                        "/api/v1/chat-message-pictures/{chat_message_id}/{chat_message_picture_id}"
                    ))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        sleep(Duration::from_secs(1)).await;

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        api::chats::tests::chat_with_deps_cleanup(
            app.context.clone(),
            &mut transaction,
            chat_id,
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
    async fn update_200() {
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

        let chat_message_picture =
            chat_message_picture_create(router.clone(), session_id, chat_message_id).await;
        let chat_message_picture_id = chat_message_picture.id;

        let body =
            multipart::tests::file_data("image/png", "test.png", "data/test/test.png").unwrap();

        let value = format!(
            "{}; boundary={}",
            mime::MULTIPART_FORM_DATA,
            multipart::tests::BOUNDARY
        );

        let request = Request::builder()
            .method(http::Method::PUT)
            .uri(format!(
                "/api/v1/chat-message-pictures/{chat_message_id}/{chat_message_picture_id}"
            ))
            .header(http::header::CONTENT_TYPE, value)
            .header("X-Auth-Token".to_string(), session_id.to_string())
            .body(body)
            .unwrap();

        let response = router.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = BodyExt::collect(response.into_body())
            .await
            .unwrap()
            .to_bytes()
            .to_vec();
        let body: ChatMessagePicture = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.chat_message_id, chat_message_id);

        sleep(Duration::from_secs(1)).await;

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_chat_message_picture_by_id(&mut transaction, chat_message_picture_id)
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
    async fn update_401() {
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

        let chat_message_picture =
            chat_message_picture_create(router.clone(), session_id, chat_message_id).await;
        let chat_message_picture_id = chat_message_picture.id;

        let body =
            multipart::tests::file_data("image/png", "test.png", "data/test/test.png").unwrap();

        let value = format!(
            "{}; boundary={}",
            mime::MULTIPART_FORM_DATA,
            multipart::tests::BOUNDARY
        );

        let request = Request::builder()
            .method(http::Method::PUT)
            .uri(format!(
                "/api/v1/chat-message-pictures/{chat_message_id}/{chat_message_picture_id}"
            ))
            .header(http::header::CONTENT_TYPE, value)
            .body(body)
            .unwrap();

        let response = router.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        sleep(Duration::from_secs(1)).await;

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_chat_message_picture_by_id(&mut transaction, chat_message_picture_id)
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
    async fn update_403() {
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

        let chat_message_picture =
            chat_message_picture_create(router.clone(), session_id, chat_message_id).await;
        let chat_message_picture_id = chat_message_picture.id;

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

        let body =
            multipart::tests::file_data("image/png", "test.png", "data/test/test.png").unwrap();

        let value = format!(
            "{}; boundary={}",
            mime::MULTIPART_FORM_DATA,
            multipart::tests::BOUNDARY
        );

        let request = Request::builder()
            .method(http::Method::PUT)
            .uri(format!(
                "/api/v1/chat-message-pictures/{chat_message_id}/{chat_message_picture_id}"
            ))
            .header(http::header::CONTENT_TYPE, value)
            .header("X-Auth-Token".to_string(), session_id.to_string())
            .body(body)
            .unwrap();

        let response = router.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        sleep(Duration::from_secs(1)).await;

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_chat_message_picture_by_id(&mut transaction, chat_message_picture_id)
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
    async fn update_404() {
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
        let (chat_id, workspace_id) = api::chats::tests::chat_with_deps_create(
            router.clone(),
            session_id,
            user_id,
            &name,
            &r#type,
        )
        .await;

        let chat_message_id = "33847746-0030-4964-a496-f75d04499160";
        let chat_message_picture_id = "33847746-0030-4964-a496-f75d04499160";

        let body =
            multipart::tests::file_data("image/png", "test.png", "data/test/test.png").unwrap();

        let value = format!(
            "{}; boundary={}",
            mime::MULTIPART_FORM_DATA,
            multipart::tests::BOUNDARY
        );

        let request = Request::builder()
            .method(http::Method::PUT)
            .uri(format!(
                "/api/v1/chat-message-pictures/{chat_message_id}/{chat_message_picture_id}"
            ))
            .header(http::header::CONTENT_TYPE, value)
            .header("X-Auth-Token".to_string(), session_id.to_string())
            .body(body)
            .unwrap();

        let response = router.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        sleep(Duration::from_secs(1)).await;

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        api::chats::tests::chat_with_deps_cleanup(
            app.context.clone(),
            &mut transaction,
            chat_id,
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
