use crate::{
    PUBLIC_DIR,
    context::Context,
    entity::{ChatPicture, ROLE_COMPANY_ADMIN_USER},
    error::{AppError, ResponseError},
    session::{ExtractedSession, require_authenticated},
};
use axum::{
    Json,
    extract::{Multipart, Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::Deserialize;
use std::{
    fs::{File, remove_file},
    io::Write,
    sync::Arc,
};
use utoipa::IntoParams;
use uuid::Uuid;

#[derive(Deserialize, IntoParams)]
pub struct Params {
    chat_id: Uuid,
    chat_picture_id: Uuid,
}

#[axum_macros::debug_handler]
#[utoipa::path(
    post,
    path = "/api/v1/chat-pictures/:chat_id",
    responses(
        (status = 201, description = "Chat picture created.", body = ChatPicture),
        (status = 400, description = "Bad request.", body = ResponseError),
        (status = 401, description = "Unauthorized.", body = ResponseError),
        (status = 403, description = "Forbidden.", body = ResponseError),
        (status = 404, description = "Chat not found.", body = ResponseError),
        (status = 409, description = "Conflicting request.", body = ResponseError),
    ),
    params(
        ("chat_id" = String, Path, description = "Chat id"),
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn create(
    State(context): State<Arc<Context>>,
    extracted_session: ExtractedSession,
    Path(chat_id): Path<Uuid>,
    mut multipart: Multipart,
) -> Result<impl IntoResponse, AppError> {
    let session = require_authenticated(extracted_session).await?;

    context
        .octopus_database
        .try_get_user_by_id(session.user_id)
        .await?
        .ok_or(AppError::Forbidden)?;

    let chat = context
        .octopus_database
        .try_get_chat_by_id(chat_id)
        .await?
        .ok_or(AppError::NotFound)?;

    if chat.user_id != session.user_id {
        return Err(AppError::Forbidden);
    }

    let chat_picture_exists = context
        .octopus_database
        .try_get_chat_picture_by_chat_id(chat_id)
        .await?;

    match chat_picture_exists {
        None => {
            while let Some(field) = multipart.next_field().await? {
                if !field.file_name().ok_or(AppError::File)?.contains('.') {
                    return Err(AppError::BadRequest);
                }

                let extension = (*field
                    .file_name()
                    .ok_or(AppError::File)?
                    .split('.')
                    .collect::<Vec<&str>>()
                    .last()
                    .ok_or(AppError::File)?)
                .to_string();

                if extension.contains(' ') {
                    return Err(AppError::BadRequest);
                }

                let content_image = (*field
                    .content_type()
                    .ok_or(AppError::File)?
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

                    let mut chat_picture = context
                        .octopus_database
                        .insert_chat_picture(&mut transaction, chat_id, &file_name)
                        .await?;

                    context
                        .octopus_database
                        .transaction_commit(transaction)
                        .await?;

                    chat_picture.file_name = format!("{PUBLIC_DIR}/{}", chat_picture.file_name);

                    return Ok((StatusCode::CREATED, Json(chat_picture)).into_response());
                }
            }
        }
        Some(_chat_picture) => return Err(AppError::Conflict),
    }

    Err(AppError::BadRequest)
}

#[axum_macros::debug_handler]
#[utoipa::path(
    delete,
    path = "/api/v1/chat-pictures/:chat_id/:chat_picture_id",
    responses(
        (status = 204, description = "Chat picture deleted."),
        (status = 401, description = "Unauthorized.", body = ResponseError),
        (status = 403, description = "Forbidden.", body = ResponseError),
        (status = 404, description = "Chat picture not found.", body = ResponseError),
    ),
    params(
        ("chat_id" = String, Path, description = "Chat id"),
        ("chat_picture_id" = String, Path, description = "Chat picture id")
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn delete(
    State(context): State<Arc<Context>>,
    extracted_session: ExtractedSession,
    Path(Params {
        chat_id,
        chat_picture_id,
    }): Path<Params>,
) -> Result<impl IntoResponse, AppError> {
    let session = require_authenticated(extracted_session).await?;

    let session_user = context
        .octopus_database
        .try_get_user_by_id(session.user_id)
        .await?
        .ok_or(AppError::Forbidden)?;

    let chat_picture = context
        .octopus_database
        .try_get_chat_picture_by_id(chat_picture_id)
        .await?
        .ok_or(AppError::NotFound)?;

    if chat_id != chat_picture.chat_id {
        return Err(AppError::Forbidden);
    }

    let chat = context
        .octopus_database
        .try_get_chat_by_id(chat_picture.chat_id)
        .await?
        .ok_or(AppError::NotFound)?;

    let user = context
        .octopus_database
        .try_get_user_by_id(chat.user_id)
        .await?
        .ok_or(AppError::NotFound)?;

    if session_user.id != chat.user_id
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
        .try_delete_chat_picture_by_id(&mut transaction, chat_picture_id)
        .await?
        .ok_or(AppError::NotFound)?;

    let path = format!("{PUBLIC_DIR}/{}", chat_picture.file_name);
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
    path = "/api/v1/chat-pictures/:chat_id/:chat_picture_id",
    responses(
        (status = 200, description = "Chat picture read.", body = ChatPicture),
        (status = 401, description = "Unauthorized.", body = ResponseError),
        (status = 403, description = "Forbidden.", body = ResponseError),
        (status = 404, description = "Chat picture not found.", body = ResponseError),
    ),
    params(
        ("chat_id" = String, Path, description = "Chat id"),
        ("chat_picture_id" = String, Path, description = "Chat picture id")
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn read(
    State(context): State<Arc<Context>>,
    extracted_session: ExtractedSession,
    Path(Params {
        chat_id,
        chat_picture_id,
    }): Path<Params>,
) -> Result<impl IntoResponse, AppError> {
    let session = require_authenticated(extracted_session).await?;

    let session_user = context
        .octopus_database
        .try_get_user_by_id(session.user_id)
        .await?
        .ok_or(AppError::Forbidden)?;

    let mut chat_picture = context
        .octopus_database
        .try_get_chat_picture_by_id(chat_picture_id)
        .await?
        .ok_or(AppError::NotFound)?;

    chat_picture.file_name = format!("{PUBLIC_DIR}/{}", chat_picture.file_name);

    if chat_id != chat_picture.chat_id {
        return Err(AppError::Forbidden);
    }

    let chat = context
        .octopus_database
        .try_get_chat_by_id(chat_picture.chat_id)
        .await?
        .ok_or(AppError::NotFound)?;

    let user = context
        .octopus_database
        .try_get_user_by_id(chat.user_id)
        .await?
        .ok_or(AppError::NotFound)?;

    if session_user.company_id != user.company_id {
        return Err(AppError::Forbidden);
    }

    Ok((StatusCode::OK, Json(chat_picture)).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    put,
    path = "/api/v1/chat-pictures/:chat_id/:chat_picture_id",
    responses(
        (status = 200, description = "Chat picture updated.", body = ChatPicture),
        (status = 400, description = "Bad request.", body = ResponseError),
        (status = 401, description = "Unauthorized.", body = ResponseError),
        (status = 403, description = "Forbidden.", body = ResponseError),
        (status = 404, description = "Chat picture not found.", body = ResponseError),
    ),
    params(
        ("chat_id" = String, Path, description = "Chat id"),
        ("chat_picture_id" = String, Path, description = "Chat picture id")
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn update(
    State(context): State<Arc<Context>>,
    extracted_session: ExtractedSession,
    Path(Params {
        chat_id,
        chat_picture_id,
    }): Path<Params>,
    mut multipart: Multipart,
) -> Result<impl IntoResponse, AppError> {
    let session = require_authenticated(extracted_session).await?;

    let session_user = context
        .octopus_database
        .try_get_user_by_id(session.user_id)
        .await?
        .ok_or(AppError::Forbidden)?;

    let chat_picture = context
        .octopus_database
        .try_get_chat_picture_by_id(chat_picture_id)
        .await?
        .ok_or(AppError::NotFound)?;

    if chat_id != chat_picture.chat_id {
        return Err(AppError::Forbidden);
    }

    let chat = context
        .octopus_database
        .try_get_chat_by_id(chat_picture.chat_id)
        .await?
        .ok_or(AppError::NotFound)?;

    let user = context
        .octopus_database
        .try_get_user_by_id(chat.user_id)
        .await?
        .ok_or(AppError::NotFound)?;

    if session_user.id != chat.user_id
        && (!session_user
            .roles
            .contains(&ROLE_COMPANY_ADMIN_USER.to_string())
            || session_user.company_id != user.company_id)
    {
        return Err(AppError::Forbidden);
    }

    while let Some(field) = multipart.next_field().await? {
        if !field.file_name().ok_or(AppError::File)?.contains('.') {
            return Err(AppError::BadRequest);
        }

        let extension = (*field
            .file_name()
            .ok_or(AppError::File)?
            .split('.')
            .collect::<Vec<&str>>()
            .last()
            .ok_or(AppError::File)?)
        .to_string();

        if extension.contains(' ') {
            return Err(AppError::BadRequest);
        }

        let content_image = (*field
            .content_type()
            .ok_or(AppError::File)?
            .split('/')
            .collect::<Vec<&str>>()
            .first()
            .ok_or(AppError::File)?)
        .to_string();

        if content_image == "image" {
            let data = field.bytes().await?;

            let old_file = format!("{PUBLIC_DIR}/{}", chat_picture.file_name);

            let file_name = format!("{}.{}", Uuid::new_v4(), extension);
            let path = format!("{PUBLIC_DIR}/{file_name}");

            let mut file = File::create(path)?;
            file.write_all(&data)?;

            let mut transaction = context.octopus_database.transaction_begin().await?;

            let mut chat_picture = context
                .octopus_database
                .update_chat_picture(&mut transaction, chat_picture_id, &file_name)
                .await?;

            chat_picture.file_name = format!("{PUBLIC_DIR}/{}", chat_picture.file_name);

            remove_file(old_file)?;

            context
                .octopus_database
                .transaction_commit(transaction)
                .await?;

            return Ok((StatusCode::OK, Json(chat_picture)).into_response());
        }
    }

    Err(AppError::BadRequest)
}

#[cfg(test)]
mod tests {
    use crate::{api, app, entity::ChatPicture, multipart};
    use axum::{
        Router,
        body::Body,
        http::{self, Request, StatusCode},
    };
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    use uuid::Uuid;

    pub async fn chat_picture_create(
        router: Router,
        session_id: Uuid,
        chat_id: Uuid,
    ) -> ChatPicture {
        let body = multipart::tests::file_data("image/png", "test.png", "data/test/test.png", true)
            .unwrap();

        let value = format!(
            "{}; boundary={}",
            mime::MULTIPART_FORM_DATA,
            multipart::tests::BOUNDARY
        );

        let request = Request::builder()
            .method(http::Method::POST)
            .uri(format!("/api/v1/chat-pictures/{chat_id}"))
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
        let body: ChatPicture = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.chat_id, chat_id);

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
        let (chat_id, workspace_id) = api::chats::tests::chat_with_deps_create(
            router.clone(),
            session_id,
            user_id,
            &name,
            &r#type,
            "Chat",
        )
        .await;

        let chat_picture = chat_picture_create(router, session_id, chat_id).await;
        let chat_picture_id = chat_picture.id;

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_chat_picture_by_id(&mut transaction, chat_picture_id)
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
    async fn create_400_file1() {
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
            "Chat",
        )
        .await;

        let body = multipart::tests::file_data("image/png", "testpng", "data/test/test.png", true)
            .unwrap();

        let value = format!(
            "{}; boundary={}",
            mime::MULTIPART_FORM_DATA,
            multipart::tests::BOUNDARY
        );

        let request = Request::builder()
            .method(http::Method::POST)
            .uri(format!("/api/v1/chat-pictures/{chat_id}"))
            .header(http::header::CONTENT_TYPE, value)
            .header("X-Auth-Token".to_string(), session_id.to_string())
            .body(body)
            .unwrap();

        let response = router.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

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
    async fn create_400_file2() {
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
            "Chat",
        )
        .await;

        let body =
            multipart::tests::file_data("image/png", "test.p ng", "data/test/test.png", true)
                .unwrap();

        let value = format!(
            "{}; boundary={}",
            mime::MULTIPART_FORM_DATA,
            multipart::tests::BOUNDARY
        );

        let request = Request::builder()
            .method(http::Method::POST)
            .uri(format!("/api/v1/chat-pictures/{chat_id}"))
            .header(http::header::CONTENT_TYPE, value)
            .header("X-Auth-Token".to_string(), session_id.to_string())
            .body(body)
            .unwrap();

        let response = router.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

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
        let (chat_id, workspace_id) = api::chats::tests::chat_with_deps_create(
            router.clone(),
            session_id,
            user_id,
            &name,
            &r#type,
            "Chat",
        )
        .await;

        let body = multipart::tests::file_data("image/png", "test.png", "data/test/test.png", true)
            .unwrap();

        let value = format!(
            "{}; boundary={}",
            mime::MULTIPART_FORM_DATA,
            multipart::tests::BOUNDARY
        );

        let request = Request::builder()
            .method(http::Method::POST)
            .uri(format!("/api/v1/chat-pictures/{chat_id}"))
            .header(http::header::CONTENT_TYPE, value)
            .body(body)
            .unwrap();

        let response = router.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

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
        let (chat_id, workspace_id) = api::chats::tests::chat_with_deps_create(
            router.clone(),
            session_id,
            user_id,
            &name,
            &r#type,
            "Chat",
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

        let body = multipart::tests::file_data("image/png", "test.png", "data/test/test.png", true)
            .unwrap();

        let value = format!(
            "{}; boundary={}",
            mime::MULTIPART_FORM_DATA,
            multipart::tests::BOUNDARY
        );

        let request = Request::builder()
            .method(http::Method::POST)
            .uri(format!("/api/v1/chat-pictures/{chat_id}"))
            .header(http::header::CONTENT_TYPE, value)
            .header("X-Auth-Token".to_string(), session_id.to_string())
            .body(body)
            .unwrap();

        let response = router.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);

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
            &[user_id, second_user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn create_403_deleted_user() {
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
            "Chat",
        )
        .await;

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(app.context.clone(), &mut transaction, &[], &[user_id])
            .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;

        let body = multipart::tests::file_data("image/png", "test.png", "data/test/test.png", true)
            .unwrap();

        let value = format!(
            "{}; boundary={}",
            mime::MULTIPART_FORM_DATA,
            multipart::tests::BOUNDARY
        );

        let request = Request::builder()
            .method(http::Method::POST)
            .uri(format!("/api/v1/chat-pictures/{chat_id}"))
            .header(http::header::CONTENT_TYPE, value)
            .header("X-Auth-Token".to_string(), session_id.to_string())
            .body(body)
            .unwrap();

        let response = router.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);

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

        api::setup::tests::setup_cleanup(app.context.clone(), &mut transaction, &[company_id], &[])
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

        let chat_id = "33847746-0030-4964-a496-f75d04499160";

        let body = multipart::tests::file_data("image/png", "test.png", "data/test/test.png", true)
            .unwrap();

        let value = format!(
            "{}; boundary={}",
            mime::MULTIPART_FORM_DATA,
            multipart::tests::BOUNDARY
        );

        let request = Request::builder()
            .method(http::Method::POST)
            .uri(format!("/api/v1/chat-pictures/{chat_id}"))
            .header(http::header::CONTENT_TYPE, value)
            .header("X-Auth-Token".to_string(), session_id.to_string())
            .body(body)
            .unwrap();

        let response = router.oneshot(request).await.unwrap();

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
    async fn create_409() {
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
            "Chat",
        )
        .await;

        let chat_picture = chat_picture_create(router.clone(), session_id, chat_id).await;
        let chat_picture_id = chat_picture.id;

        let body = multipart::tests::file_data("image/png", "test.png", "data/test/test.png", true)
            .unwrap();

        let value = format!(
            "{}; boundary={}",
            mime::MULTIPART_FORM_DATA,
            multipart::tests::BOUNDARY
        );

        let request = Request::builder()
            .method(http::Method::POST)
            .uri(format!("/api/v1/chat-pictures/{chat_id}"))
            .header(http::header::CONTENT_TYPE, value)
            .header("X-Auth-Token".to_string(), session_id.to_string())
            .body(body)
            .unwrap();

        let response = router.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::CONFLICT);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_chat_picture_by_id(&mut transaction, chat_picture_id)
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
        let (chat_id, workspace_id) = api::chats::tests::chat_with_deps_create(
            router.clone(),
            session_id,
            user_id,
            &name,
            &r#type,
            "Chat",
        )
        .await;

        let chat_picture = chat_picture_create(router.clone(), session_id, chat_id).await;
        let chat_picture_id = chat_picture.id;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::DELETE)
                    .uri(format!("/api/v1/chat-pictures/{chat_id}/{chat_picture_id}"))
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
        let (chat_id, workspace_id) = api::chats::tests::chat_with_deps_create(
            router.clone(),
            session_id,
            user_id,
            &name,
            &r#type,
            "Chat",
        )
        .await;

        let chat_picture = chat_picture_create(router.clone(), session_id, chat_id).await;
        let chat_picture_id = chat_picture.id;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::DELETE)
                    .uri(format!("/api/v1/chat-pictures/{chat_id}/{chat_picture_id}"))
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
            .try_delete_chat_picture_by_id(&mut transaction, chat_picture_id)
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
        let (chat_id, workspace_id) = api::chats::tests::chat_with_deps_create(
            router.clone(),
            session_id,
            user_id,
            &name,
            &r#type,
            "Chat",
        )
        .await;

        let chat_picture = chat_picture_create(router.clone(), session_id, chat_id).await;
        let chat_picture_id = chat_picture.id;

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
                    .uri(format!("/api/v1/chat-pictures/{chat_id}/{chat_picture_id}"))
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
            .try_delete_chat_picture_by_id(&mut transaction, chat_picture_id)
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
        let (chat_id, workspace_id) = api::chats::tests::chat_with_deps_create(
            router.clone(),
            session_id,
            user_id,
            &name,
            &r#type,
            "Chat",
        )
        .await;

        let chat_picture = chat_picture_create(router.clone(), session_id, chat_id).await;
        let chat_picture_id = chat_picture.id;

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
                    .uri(format!("/api/v1/chat-pictures/{chat_id}/{chat_picture_id}"))
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

        api::chats::tests::chat_with_deps_cleanup(
            app.context.clone(),
            &mut transaction,
            chat_id,
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
        let (chat_id, workspace_id) = api::chats::tests::chat_with_deps_create(
            router.clone(),
            session_id,
            user_id,
            &name,
            &r#type,
            "Chat",
        )
        .await;

        let chat_picture_id = "33847746-0030-4964-a496-f75d04499160";

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::DELETE)
                    .uri(format!("/api/v1/chat-pictures/{chat_id}/{chat_picture_id}"))
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
        let (chat_id, workspace_id) = api::chats::tests::chat_with_deps_create(
            router.clone(),
            session_id,
            user_id,
            &name,
            &r#type,
            "Chat",
        )
        .await;

        let chat_picture = chat_picture_create(router.clone(), session_id, chat_id).await;
        let chat_picture_id = chat_picture.id;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("/api/v1/chat-pictures/{chat_id}/{chat_picture_id}"))
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
        let body: ChatPicture = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.chat_id, chat_id);

        let chat_picture_id = body.id;

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_chat_picture_by_id(&mut transaction, chat_picture_id)
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
        let (chat_id, workspace_id) = api::chats::tests::chat_with_deps_create(
            router.clone(),
            session_id,
            user_id,
            &name,
            &r#type,
            "Chat",
        )
        .await;

        let chat_picture = chat_picture_create(router.clone(), session_id, chat_id).await;
        let chat_picture_id = chat_picture.id;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("/api/v1/chat-pictures/{chat_id}/{chat_picture_id}"))
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
            .try_delete_chat_picture_by_id(&mut transaction, chat_picture_id)
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
        let (chat_id, workspace_id) = api::chats::tests::chat_with_deps_create(
            router.clone(),
            session_id,
            user_id,
            &name,
            &r#type,
            "Chat",
        )
        .await;

        let chat_picture = chat_picture_create(router.clone(), session_id, chat_id).await;
        let chat_picture_id = chat_picture.id;

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

        let second_chat_id = "33847746-0030-4964-a496-f75d04499160";

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!(
                        "/api/v1/chat-pictures/{second_chat_id}/{chat_picture_id}"
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
            .try_delete_chat_picture_by_id(&mut transaction, chat_picture_id)
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
            "Chat",
        )
        .await;

        let chat_picture = chat_picture_create(router.clone(), session_id, chat_id).await;
        let chat_picture_id = chat_picture.id;

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
                    .uri(format!("/api/v1/chat-pictures/{chat_id}/{chat_picture_id}"))
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
            .try_delete_chat_picture_by_id(&mut transaction, chat_picture_id)
            .await
            .unwrap();

        api::chats::tests::chat_with_deps_cleanup(
            app.context.clone(),
            &mut transaction,
            chat_id,
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
        let (chat_id, workspace_id) = api::chats::tests::chat_with_deps_create(
            router.clone(),
            session_id,
            user_id,
            &name,
            &r#type,
            "Chat",
        )
        .await;

        let chat_picture_id = "33847746-0030-4964-a496-f75d04499160";

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("/api/v1/chat-pictures/{chat_id}/{chat_picture_id}"))
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
        let (chat_id, workspace_id) = api::chats::tests::chat_with_deps_create(
            router.clone(),
            session_id,
            user_id,
            &name,
            &r#type,
            "Chat",
        )
        .await;

        let chat_picture = chat_picture_create(router.clone(), session_id, chat_id).await;
        let chat_picture_id = chat_picture.id;

        let body = multipart::tests::file_data("image/png", "test.png", "data/test/test.png", true)
            .unwrap();

        let value = format!(
            "{}; boundary={}",
            mime::MULTIPART_FORM_DATA,
            multipart::tests::BOUNDARY
        );

        let request = Request::builder()
            .method(http::Method::PUT)
            .uri(format!("/api/v1/chat-pictures/{chat_id}/{chat_picture_id}"))
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
        let body: ChatPicture = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.chat_id, chat_id);

        let chat_picture_id = body.id;

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_chat_picture_by_id(&mut transaction, chat_picture_id)
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
    async fn update_400_file1() {
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
            "Chat",
        )
        .await;

        let chat_picture = chat_picture_create(router.clone(), session_id, chat_id).await;
        let chat_picture_id = chat_picture.id;

        let body = multipart::tests::file_data("image/png", "testpng", "data/test/test.png", true)
            .unwrap();

        let value = format!(
            "{}; boundary={}",
            mime::MULTIPART_FORM_DATA,
            multipart::tests::BOUNDARY
        );

        let request = Request::builder()
            .method(http::Method::PUT)
            .uri(format!("/api/v1/chat-pictures/{chat_id}/{chat_picture_id}"))
            .header(http::header::CONTENT_TYPE, value)
            .header("X-Auth-Token".to_string(), session_id.to_string())
            .body(body)
            .unwrap();

        let response = router.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_chat_picture_by_id(&mut transaction, chat_picture_id)
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
    async fn update_400_file2() {
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
            "Chat",
        )
        .await;

        let chat_picture = chat_picture_create(router.clone(), session_id, chat_id).await;
        let chat_picture_id = chat_picture.id;

        let body =
            multipart::tests::file_data("image/png", "test.p ng", "data/test/test.png", true)
                .unwrap();

        let value = format!(
            "{}; boundary={}",
            mime::MULTIPART_FORM_DATA,
            multipart::tests::BOUNDARY
        );

        let request = Request::builder()
            .method(http::Method::PUT)
            .uri(format!("/api/v1/chat-pictures/{chat_id}/{chat_picture_id}"))
            .header(http::header::CONTENT_TYPE, value)
            .header("X-Auth-Token".to_string(), session_id.to_string())
            .body(body)
            .unwrap();

        let response = router.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_chat_picture_by_id(&mut transaction, chat_picture_id)
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
        let (chat_id, workspace_id) = api::chats::tests::chat_with_deps_create(
            router.clone(),
            session_id,
            user_id,
            &name,
            &r#type,
            "Chat",
        )
        .await;

        let chat_picture = chat_picture_create(router.clone(), session_id, chat_id).await;
        let chat_picture_id = chat_picture.id;

        let body = multipart::tests::file_data("image/png", "test.png", "data/test/test.png", true)
            .unwrap();

        let value = format!(
            "{}; boundary={}",
            mime::MULTIPART_FORM_DATA,
            multipart::tests::BOUNDARY
        );

        let request = Request::builder()
            .method(http::Method::PUT)
            .uri(format!("/api/v1/chat-pictures/{chat_id}/{chat_picture_id}"))
            .header(http::header::CONTENT_TYPE, value)
            .body(body)
            .unwrap();

        let response = router.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_chat_picture_by_id(&mut transaction, chat_picture_id)
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
        let (chat_id, workspace_id) = api::chats::tests::chat_with_deps_create(
            router.clone(),
            session_id,
            user_id,
            &name,
            &r#type,
            "Chat",
        )
        .await;

        let chat_picture = chat_picture_create(router.clone(), session_id, chat_id).await;
        let chat_picture_id = chat_picture.id;

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

        let second_chat_id = "33847746-0030-4964-a496-f75d04499160";

        let body = multipart::tests::file_data("image/png", "test.png", "data/test/test.png", true)
            .unwrap();

        let value = format!(
            "{}; boundary={}",
            mime::MULTIPART_FORM_DATA,
            multipart::tests::BOUNDARY
        );

        let request = Request::builder()
            .method(http::Method::PUT)
            .uri(format!(
                "/api/v1/chat-pictures/{second_chat_id}/{chat_picture_id}"
            ))
            .header(http::header::CONTENT_TYPE, value)
            .header("X-Auth-Token".to_string(), session_id.to_string())
            .body(body)
            .unwrap();

        let response = router.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_chat_picture_by_id(&mut transaction, chat_picture_id)
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
    async fn update_403_deleted_user() {
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
            "Chat",
        )
        .await;

        let chat_picture = chat_picture_create(router.clone(), session_id, chat_id).await;
        let chat_picture_id = chat_picture.id;

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(app.context.clone(), &mut transaction, &[], &[user_id])
            .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;

        let body = multipart::tests::file_data("image/png", "test.png", "data/test/test.png", true)
            .unwrap();

        let value = format!(
            "{}; boundary={}",
            mime::MULTIPART_FORM_DATA,
            multipart::tests::BOUNDARY
        );

        let request = Request::builder()
            .method(http::Method::PUT)
            .uri(format!("/api/v1/chat-pictures/{chat_id}/{chat_picture_id}"))
            .header(http::header::CONTENT_TYPE, value)
            .header("X-Auth-Token".to_string(), session_id.to_string())
            .body(body)
            .unwrap();

        let response = router.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_chat_picture_by_id(&mut transaction, chat_picture_id)
            .await
            .unwrap();

        api::chats::tests::chat_with_deps_cleanup(
            app.context.clone(),
            &mut transaction,
            chat_id,
            workspace_id,
        )
        .await;

        api::setup::tests::setup_cleanup(app.context.clone(), &mut transaction, &[company_id], &[])
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
            "Chat",
        )
        .await;

        let chat_picture_id = "33847746-0030-4964-a496-f75d04499160";

        let body = multipart::tests::file_data("image/png", "test.png", "data/test/test.png", true)
            .unwrap();

        let value = format!(
            "{}; boundary={}",
            mime::MULTIPART_FORM_DATA,
            multipart::tests::BOUNDARY
        );

        let request = Request::builder()
            .method(http::Method::PUT)
            .uri(format!("/api/v1/chat-pictures/{chat_id}/{chat_picture_id}"))
            .header(http::header::CONTENT_TYPE, value)
            .header("X-Auth-Token".to_string(), session_id.to_string())
            .body(body)
            .unwrap();

        let response = router.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);

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
