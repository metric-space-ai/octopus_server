use crate::{
    context::Context,
    entity::{WorkspacesType, ROLE_COMPANY_ADMIN_USER, ROLE_PRIVATE_USER},
    error::AppError,
    session::{require_authenticated_session, ExtractedSession},
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
    let session = require_authenticated_session(extracted_session).await?;

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

            let mut chat_message_picture = context
                .octopus_database
                .insert_chat_message_picture(chat_message.id, &file_name)
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
    let session = require_authenticated_session(extracted_session).await?;

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

    context
        .octopus_database
        .try_delete_chat_message_picture_by_id(chat_message_picture.id)
        .await?
        .ok_or(AppError::NotFound)?;

    let path = format!("{PUBLIC_DIR}/{}", chat_message_picture.file_name);
    remove_file(path)?;

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
    let session = require_authenticated_session(extracted_session).await?;

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
    let session = require_authenticated_session(extracted_session).await?;

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

            let mut chat_message_picture = context
                .octopus_database
                .update_chat_message_picture(chat_message_picture.id, &file_name)
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
    use crate::{
        api, app,
        entity::{Chat, ChatMessage, ChatMessagePicture, User, Workspace},
        session::SessionResponse,
        Args,
    };
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
    extern crate hyper_multipart_rfc7578 as hyper_multipart;
    use hyper_multipart::client::multipart;
    use tower::ServiceExt;

    #[tokio::test]
    async fn create_201() {
        let args = Args {
            azure_openai_api_key: None,
            azure_openai_deployment_id: None,
            azure_openai_enabled: Some(true),
            database_url: Some(String::from(
                "postgres://admin:admin@db/octopus_server_test",
            )),
            openai_api_key: None,
            port: None,
        };
        let app = app::get_app(args).await.unwrap();
        let router = app.router;
        let second_router = router.clone();
        let third_router = router.clone();
        let fourth_router = router.clone();
        let fifth_router = router.clone();
        let sixth_router = router.clone();

        let company_name = Paragraph(1..2).fake::<String>();
        let email = format!(
            "{}{}{}",
            Word().fake::<String>(),
            Word().fake::<String>(),
            SafeEmail().fake::<String>()
        );
        let password = "password123";

        let user = api::setup::tests::setup_post(router, &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let response = second_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/auth")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "email": &email,
                            "password": &password,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: SessionResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);

        let session_id = body.id;

        let name = format!("workspace {}", Word().fake::<String>());
        let r#type = "Public";

        let response = third_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/workspaces")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "name": &name,
                            "type": r#type,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: Workspace = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);
        assert_eq!(body.name, name);

        let workspace_id = body.id;

        let response = fourth_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri(format!("/api/v1/chats/{workspace_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: Chat = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);

        let chat_id = body.id;

        let message = "test message";

        let response = fifth_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri(format!("/api/v1/chat-messages/{chat_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "message": &message,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: ChatMessage = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.message, message);

        let chat_message_id = body.id;

        let mut form = multipart::Form::default();
        form.add_file_with_mime("test.png", "data/test/test.png", mime::IMAGE_PNG)
            .unwrap();
        let req_builder = Request::builder()
            .method(http::Method::POST)
            .uri(format!("/api/v1/chat-message-pictures/{chat_message_id}"))
            .header("X-Auth-Token".to_string(), session_id.to_string());
        let request = form
            .set_body_convert::<hyper::Body, multipart::Body>(req_builder)
            .unwrap();

        let response = sixth_router.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: ChatMessagePicture = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.chat_message_id, chat_message_id);

        let chat_message_picture_id = body.id;

        app.context
            .octopus_database
            .try_delete_chat_message_picture_by_id(chat_message_picture_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_chat_message_by_id(chat_message_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_user_by_id(user_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_company_by_id(company_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_chat_by_id(chat_id)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn create_401() {
        let args = Args {
            azure_openai_api_key: None,
            azure_openai_deployment_id: None,
            azure_openai_enabled: Some(true),
            database_url: Some(String::from(
                "postgres://admin:admin@db/octopus_server_test",
            )),
            openai_api_key: None,
            port: None,
        };
        let app = app::get_app(args).await.unwrap();
        let router = app.router;
        let second_router = router.clone();
        let third_router = router.clone();
        let fourth_router = router.clone();
        let fifth_router = router.clone();
        let sixth_router = router.clone();

        let company_name = Paragraph(1..2).fake::<String>();
        let email = format!(
            "{}{}{}",
            Word().fake::<String>(),
            Word().fake::<String>(),
            SafeEmail().fake::<String>()
        );
        let password = "password123";

        let user = api::setup::tests::setup_post(router, &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;
        let response = second_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/auth")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "email": &email,
                            "password": &password,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: SessionResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);

        let session_id = body.id;

        let name = format!("workspace {}", Word().fake::<String>());
        let r#type = "Public";

        let response = third_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/workspaces")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "name": &name,
                            "type": r#type,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: Workspace = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);
        assert_eq!(body.name, name);

        let workspace_id = body.id;

        let response = fourth_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri(format!("/api/v1/chats/{workspace_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: Chat = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);

        let chat_id = body.id;

        let message = "test message";

        let response = fifth_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri(format!("/api/v1/chat-messages/{chat_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "message": &message,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: ChatMessage = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.message, message);

        let chat_message_id = body.id;

        let mut form = multipart::Form::default();
        form.add_file_with_mime("test.png", "data/test/test.png", mime::IMAGE_PNG)
            .unwrap();
        let req_builder = Request::builder()
            .method(http::Method::POST)
            .uri(format!("/api/v1/chat-message-pictures/{chat_message_id}"));
        let request = form
            .set_body_convert::<hyper::Body, multipart::Body>(req_builder)
            .unwrap();

        let response = sixth_router.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        app.context
            .octopus_database
            .try_delete_chat_message_by_id(chat_message_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_user_by_id(user_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_company_by_id(company_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_chat_by_id(chat_id)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn create_403() {
        let args = Args {
            azure_openai_api_key: None,
            azure_openai_deployment_id: None,
            azure_openai_enabled: Some(true),
            database_url: Some(String::from(
                "postgres://admin:admin@db/octopus_server_test",
            )),
            openai_api_key: None,
            port: None,
        };
        let app = app::get_app(args).await.unwrap();
        let router = app.router;
        let second_router = router.clone();
        let third_router = router.clone();
        let fourth_router = router.clone();
        let fifth_router = router.clone();
        let sixth_router = router.clone();
        let seventh_router = router.clone();
        let eighth_router = router.clone();

        let company_name = Paragraph(1..2).fake::<String>();
        let email = format!(
            "{}{}{}",
            Word().fake::<String>(),
            Word().fake::<String>(),
            SafeEmail().fake::<String>()
        );
        let password = "password123";

        let user = api::setup::tests::setup_post(router, &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let response = second_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/auth")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "email": &email,
                            "password": &password,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: SessionResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);

        let session_id = body.id;

        let name = format!("workspace {}", Word().fake::<String>());
        let r#type = "Public";

        let response = third_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/workspaces")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "name": &name,
                            "type": r#type,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: Workspace = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);
        assert_eq!(body.name, name);

        let workspace_id = body.id;

        let response = fourth_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri(format!("/api/v1/chats/{workspace_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: Chat = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);

        let chat_id = body.id;

        let message = "test message";

        let response = fifth_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri(format!("/api/v1/chat-messages/{chat_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "message": &message,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: ChatMessage = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.message, message);

        let chat_message_id = body.id;

        let email = format!(
            "{}{}{}",
            Word().fake::<String>(),
            Word().fake::<String>(),
            SafeEmail().fake::<String>()
        );
        let job_title = Paragraph(1..2).fake::<String>();
        let name = Name().fake::<String>();
        let password = "password123";

        let response = sixth_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri(format!("/api/v1/auth/register/{company_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "email": &email,
                            "job_title": &job_title,
                            "name": &name,
                            "password": &password,
                            "repeat_password": &password,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: User = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.email, email);

        let user2_id = body.id;

        let response = seventh_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/auth")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "email": &email,
                            "password": &password,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: SessionResponse = serde_json::from_slice(&body).unwrap();

        let session_id = body.id;

        let mut form = multipart::Form::default();
        form.add_file_with_mime("test.png", "data/test/test.png", mime::IMAGE_PNG)
            .unwrap();
        let req_builder = Request::builder()
            .method(http::Method::POST)
            .uri(format!("/api/v1/chat-message-pictures/{chat_message_id}"))
            .header("X-Auth-Token".to_string(), session_id.to_string());
        let request = form
            .set_body_convert::<hyper::Body, multipart::Body>(req_builder)
            .unwrap();

        let response = eighth_router.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        app.context
            .octopus_database
            .try_delete_chat_message_by_id(chat_message_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_user_by_id(user_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_user_by_id(user2_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_company_by_id(company_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_chat_by_id(chat_id)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn create_404() {
        let args = Args {
            azure_openai_api_key: None,
            azure_openai_deployment_id: None,
            azure_openai_enabled: Some(true),
            database_url: Some(String::from(
                "postgres://admin:admin@db/octopus_server_test",
            )),
            openai_api_key: None,
            port: None,
        };
        let app = app::get_app(args).await.unwrap();
        let router = app.router;
        let second_router = router.clone();
        let third_router = router.clone();

        let company_name = Paragraph(1..2).fake::<String>();
        let email = format!(
            "{}{}{}",
            Word().fake::<String>(),
            Word().fake::<String>(),
            SafeEmail().fake::<String>()
        );
        let password = "password123";

        let user = api::setup::tests::setup_post(router, &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;
        let response = second_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/auth")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "email": &email,
                            "password": &password,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: SessionResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);

        let session_id = body.id;

        let chat_message_id = "33847746-0030-4964-a496-f75d04499160";

        let mut form = multipart::Form::default();
        form.add_file_with_mime("test.png", "data/test/test.png", mime::IMAGE_PNG)
            .unwrap();
        let req_builder = Request::builder()
            .method(http::Method::POST)
            .uri(format!("/api/v1/chat-message-pictures/{chat_message_id}"))
            .header("X-Auth-Token".to_string(), session_id.to_string());
        let request = form
            .set_body_convert::<hyper::Body, multipart::Body>(req_builder)
            .unwrap();

        let response = third_router.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        app.context
            .octopus_database
            .try_delete_user_by_id(user_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_company_by_id(company_id)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn delete_204() {
        let args = Args {
            azure_openai_api_key: None,
            azure_openai_deployment_id: None,
            azure_openai_enabled: Some(true),
            database_url: Some(String::from(
                "postgres://admin:admin@db/octopus_server_test",
            )),
            openai_api_key: None,
            port: None,
        };
        let app = app::get_app(args).await.unwrap();
        let router = app.router;
        let second_router = router.clone();
        let third_router = router.clone();
        let fourth_router = router.clone();
        let fifth_router = router.clone();
        let sixth_router = router.clone();
        let seventh_router = router.clone();

        let company_name = Paragraph(1..2).fake::<String>();
        let email = format!(
            "{}{}{}",
            Word().fake::<String>(),
            Word().fake::<String>(),
            SafeEmail().fake::<String>()
        );
        let password = "password123";

        let user = api::setup::tests::setup_post(router, &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;
        let response = second_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/auth")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "email": &email,
                            "password": &password,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: SessionResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);

        let session_id = body.id;

        let name = format!("workspace {}", Word().fake::<String>());
        let r#type = "Public";

        let response = third_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/workspaces")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "name": &name,
                            "type": r#type,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: Workspace = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);
        assert_eq!(body.name, name);

        let workspace_id = body.id;

        let response = fourth_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri(format!("/api/v1/chats/{workspace_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: Chat = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);

        let chat_id = body.id;

        let message = "test message";

        let response = fifth_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri(format!("/api/v1/chat-messages/{chat_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "message": &message,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: ChatMessage = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.message, message);

        let chat_message_id = body.id;

        let mut form = multipart::Form::default();
        form.add_file_with_mime("test.png", "data/test/test.png", mime::IMAGE_PNG)
            .unwrap();
        let req_builder = Request::builder()
            .method(http::Method::POST)
            .uri(format!("/api/v1/chat-message-pictures/{chat_message_id}"))
            .header("X-Auth-Token".to_string(), session_id.to_string());
        let request = form
            .set_body_convert::<hyper::Body, multipart::Body>(req_builder)
            .unwrap();

        let response = sixth_router.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: ChatMessagePicture = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.chat_message_id, chat_message_id);

        let chat_message_picture_id = body.id;

        let response = seventh_router
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

        app.context
            .octopus_database
            .try_delete_chat_message_by_id(chat_message_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_user_by_id(user_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_company_by_id(company_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_chat_by_id(chat_id)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn delete_401() {
        let args = Args {
            azure_openai_api_key: None,
            azure_openai_deployment_id: None,
            azure_openai_enabled: Some(true),
            database_url: Some(String::from(
                "postgres://admin:admin@db/octopus_server_test",
            )),
            openai_api_key: None,
            port: None,
        };
        let app = app::get_app(args).await.unwrap();
        let router = app.router;
        let second_router = router.clone();
        let third_router = router.clone();
        let fourth_router = router.clone();
        let fifth_router = router.clone();
        let sixth_router = router.clone();
        let seventh_router = router.clone();

        let company_name = Paragraph(1..2).fake::<String>();
        let email = format!(
            "{}{}{}",
            Word().fake::<String>(),
            Word().fake::<String>(),
            SafeEmail().fake::<String>()
        );
        let password = "password123";

        let user = api::setup::tests::setup_post(router, &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;
        let response = second_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/auth")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "email": &email,
                            "password": &password,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: SessionResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);

        let session_id = body.id;

        let name = format!("workspace {}", Word().fake::<String>());
        let r#type = "Public";

        let response = third_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/workspaces")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "name": &name,
                            "type": r#type,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: Workspace = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);
        assert_eq!(body.name, name);

        let workspace_id = body.id;

        let response = fourth_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri(format!("/api/v1/chats/{workspace_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: Chat = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);

        let chat_id = body.id;

        let message = "test message";

        let response = fifth_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri(format!("/api/v1/chat-messages/{chat_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "message": &message,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: ChatMessage = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.message, message);

        let chat_message_id = body.id;

        let mut form = multipart::Form::default();
        form.add_file_with_mime("test.png", "data/test/test.png", mime::IMAGE_PNG)
            .unwrap();
        let req_builder = Request::builder()
            .method(http::Method::POST)
            .uri(format!("/api/v1/chat-message-pictures/{chat_message_id}"))
            .header("X-Auth-Token".to_string(), session_id.to_string());
        let request = form
            .set_body_convert::<hyper::Body, multipart::Body>(req_builder)
            .unwrap();

        let response = sixth_router.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: ChatMessagePicture = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.chat_message_id, chat_message_id);

        let chat_message_picture_id = body.id;

        let response = seventh_router
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

        app.context
            .octopus_database
            .try_delete_chat_message_picture_by_id(chat_message_picture_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_chat_message_by_id(chat_message_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_user_by_id(user_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_company_by_id(company_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_chat_by_id(chat_id)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn delete_403() {
        let args = Args {
            azure_openai_api_key: None,
            azure_openai_deployment_id: None,
            azure_openai_enabled: Some(true),
            database_url: Some(String::from(
                "postgres://admin:admin@db/octopus_server_test",
            )),
            openai_api_key: None,
            port: None,
        };
        let app = app::get_app(args).await.unwrap();
        let router = app.router;
        let second_router = router.clone();
        let third_router = router.clone();
        let fourth_router = router.clone();
        let fifth_router = router.clone();
        let sixth_router = router.clone();
        let seventh_router = router.clone();
        let eighth_router = router.clone();
        let ninth_router = router.clone();

        let company_name = Paragraph(1..2).fake::<String>();
        let email = format!(
            "{}{}{}",
            Word().fake::<String>(),
            Word().fake::<String>(),
            SafeEmail().fake::<String>()
        );
        let password = "password123";

        let user = api::setup::tests::setup_post(router, &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;
        let response = second_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/auth")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "email": &email,
                            "password": &password,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: SessionResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);

        let session_id = body.id;

        let name = format!("workspace {}", Word().fake::<String>());
        let r#type = "Public";

        let response = third_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/workspaces")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "name": &name,
                            "type": r#type,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: Workspace = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);
        assert_eq!(body.name, name);

        let workspace_id = body.id;

        let response = fourth_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri(format!("/api/v1/chats/{workspace_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: Chat = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);

        let chat_id = body.id;

        let message = "test message";

        let response = fifth_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri(format!("/api/v1/chat-messages/{chat_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "message": &message,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: ChatMessage = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.message, message);

        let chat_message_id = body.id;

        let mut form = multipart::Form::default();
        form.add_file_with_mime("test.png", "data/test/test.png", mime::IMAGE_PNG)
            .unwrap();
        let req_builder = Request::builder()
            .method(http::Method::POST)
            .uri(format!("/api/v1/chat-message-pictures/{chat_message_id}"))
            .header("X-Auth-Token".to_string(), session_id.to_string());
        let request = form
            .set_body_convert::<hyper::Body, multipart::Body>(req_builder)
            .unwrap();

        let response = sixth_router.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: ChatMessagePicture = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.chat_message_id, chat_message_id);

        let chat_message_picture_id = body.id;

        let email = format!(
            "{}{}{}",
            Word().fake::<String>(),
            Word().fake::<String>(),
            SafeEmail().fake::<String>()
        );
        let job_title = Paragraph(1..2).fake::<String>();
        let name = Name().fake::<String>();
        let password = "password123";

        let response = seventh_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri(format!("/api/v1/auth/register/{company_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "email": &email,
                            "job_title": &job_title,
                            "name": &name,
                            "password": &password,
                            "repeat_password": &password,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: User = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.email, email);

        let user2_id = body.id;

        let response = eighth_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/auth")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "email": &email,
                            "password": &password,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: SessionResponse = serde_json::from_slice(&body).unwrap();

        let session_id = body.id;

        let response = ninth_router
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

        app.context
            .octopus_database
            .try_delete_chat_message_picture_by_id(chat_message_picture_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_chat_message_by_id(chat_message_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_user_by_id(user_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_user_by_id(user2_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_company_by_id(company_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_chat_by_id(chat_id)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn delete_404() {
        let args = Args {
            azure_openai_api_key: None,
            azure_openai_deployment_id: None,
            azure_openai_enabled: Some(true),
            database_url: Some(String::from(
                "postgres://admin:admin@db/octopus_server_test",
            )),
            openai_api_key: None,
            port: None,
        };
        let app = app::get_app(args).await.unwrap();
        let router = app.router;
        let second_router = router.clone();
        let third_router = router.clone();
        let fourth_router = router.clone();
        let fifth_router = router.clone();

        let company_name = Paragraph(1..2).fake::<String>();
        let email = format!(
            "{}{}{}",
            Word().fake::<String>(),
            Word().fake::<String>(),
            SafeEmail().fake::<String>()
        );
        let password = "password123";

        let user = api::setup::tests::setup_post(router, &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;
        let response = second_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/auth")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "email": &email,
                            "password": &password,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: SessionResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);

        let session_id = body.id;

        let name = format!("workspace {}", Word().fake::<String>());
        let r#type = "Public";

        let response = third_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/workspaces")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "name": &name,
                            "type": r#type,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: Workspace = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);
        assert_eq!(body.name, name);

        let workspace_id = body.id;

        let response = fourth_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri(format!("/api/v1/chats/{workspace_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: Chat = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);

        let chat_id = body.id;

        let chat_message_id = "33847746-0030-4964-a496-f75d04499160";
        let chat_message_picture_id = "33847746-0030-4964-a496-f75d04499160";

        let response = fifth_router
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

        app.context
            .octopus_database
            .try_delete_user_by_id(user_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_company_by_id(company_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_chat_by_id(chat_id)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn read_200() {
        let args = Args {
            azure_openai_api_key: None,
            azure_openai_deployment_id: None,
            azure_openai_enabled: Some(true),
            database_url: Some(String::from(
                "postgres://admin:admin@db/octopus_server_test",
            )),
            openai_api_key: None,
            port: None,
        };
        let app = app::get_app(args).await.unwrap();
        let router = app.router;
        let second_router = router.clone();
        let third_router = router.clone();
        let fourth_router = router.clone();
        let fifth_router = router.clone();
        let sixth_router = router.clone();
        let seventh_router = router.clone();

        let company_name = Paragraph(1..2).fake::<String>();
        let email = format!(
            "{}{}{}",
            Word().fake::<String>(),
            Word().fake::<String>(),
            SafeEmail().fake::<String>()
        );
        let password = "password123";

        let user = api::setup::tests::setup_post(router, &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;
        let response = second_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/auth")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "email": &email,
                            "password": &password,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: SessionResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);

        let session_id = body.id;

        let name = format!("workspace {}", Word().fake::<String>());
        let r#type = "Public";

        let response = third_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/workspaces")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "name": &name,
                            "type": r#type,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: Workspace = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);
        assert_eq!(body.name, name);

        let workspace_id = body.id;

        let response = fourth_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri(format!("/api/v1/chats/{workspace_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: Chat = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);

        let chat_id = body.id;

        let message = "test message";

        let response = fifth_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri(format!("/api/v1/chat-messages/{chat_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "message": &message,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: ChatMessage = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.message, message);

        let chat_message_id = body.id;

        let mut form = multipart::Form::default();
        form.add_file_with_mime("test.png", "data/test/test.png", mime::IMAGE_PNG)
            .unwrap();
        let req_builder = Request::builder()
            .method(http::Method::POST)
            .uri(format!("/api/v1/chat-message-pictures/{chat_message_id}"))
            .header("X-Auth-Token".to_string(), session_id.to_string());
        let request = form
            .set_body_convert::<hyper::Body, multipart::Body>(req_builder)
            .unwrap();

        let response = sixth_router.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: ChatMessagePicture = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.chat_message_id, chat_message_id);

        let chat_message_picture_id = body.id;

        let response = seventh_router
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

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: ChatMessagePicture = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.chat_message_id, chat_message_id);

        app.context
            .octopus_database
            .try_delete_chat_message_picture_by_id(chat_message_picture_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_chat_message_by_id(chat_message_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_user_by_id(user_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_company_by_id(company_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_chat_by_id(chat_id)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn read_401() {
        let args = Args {
            azure_openai_api_key: None,
            azure_openai_deployment_id: None,
            azure_openai_enabled: Some(true),
            database_url: Some(String::from(
                "postgres://admin:admin@db/octopus_server_test",
            )),
            openai_api_key: None,
            port: None,
        };
        let app = app::get_app(args).await.unwrap();
        let router = app.router;
        let second_router = router.clone();
        let third_router = router.clone();
        let fourth_router = router.clone();
        let fifth_router = router.clone();
        let sixth_router = router.clone();
        let seventh_router = router.clone();

        let company_name = Paragraph(1..2).fake::<String>();
        let email = format!(
            "{}{}{}",
            Word().fake::<String>(),
            Word().fake::<String>(),
            SafeEmail().fake::<String>()
        );
        let password = "password123";

        let user = api::setup::tests::setup_post(router, &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;
        let response = second_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/auth")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "email": &email,
                            "password": &password,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: SessionResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);

        let session_id = body.id;

        let name = format!("workspace {}", Word().fake::<String>());
        let r#type = "Public";

        let response = third_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/workspaces")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "name": &name,
                            "type": r#type,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: Workspace = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);
        assert_eq!(body.name, name);

        let workspace_id = body.id;

        let response = fourth_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri(format!("/api/v1/chats/{workspace_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: Chat = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);

        let chat_id = body.id;

        let message = "test message";

        let response = fifth_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri(format!("/api/v1/chat-messages/{chat_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "message": &message,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: ChatMessage = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.message, message);

        let chat_message_id = body.id;

        let mut form = multipart::Form::default();
        form.add_file_with_mime("test.png", "data/test/test.png", mime::IMAGE_PNG)
            .unwrap();
        let req_builder = Request::builder()
            .method(http::Method::POST)
            .uri(format!("/api/v1/chat-message-pictures/{chat_message_id}"))
            .header("X-Auth-Token".to_string(), session_id.to_string());
        let request = form
            .set_body_convert::<hyper::Body, multipart::Body>(req_builder)
            .unwrap();

        let response = sixth_router.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: ChatMessagePicture = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.chat_message_id, chat_message_id);

        let chat_message_picture_id = body.id;

        let response = seventh_router
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

        app.context
            .octopus_database
            .try_delete_chat_message_picture_by_id(chat_message_picture_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_chat_message_by_id(chat_message_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_user_by_id(user_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_company_by_id(company_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_chat_by_id(chat_id)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn read_403() {
        let args = Args {
            azure_openai_api_key: None,
            azure_openai_deployment_id: None,
            azure_openai_enabled: Some(true),
            database_url: Some(String::from(
                "postgres://admin:admin@db/octopus_server_test",
            )),
            openai_api_key: None,
            port: None,
        };
        let app = app::get_app(args).await.unwrap();
        let router = app.router;
        let second_router = router.clone();
        let third_router = router.clone();
        let fourth_router = router.clone();
        let fifth_router = router.clone();
        let sixth_router = router.clone();
        let seventh_router = router.clone();
        let eighth_router = router.clone();
        let ninth_router = router.clone();

        let company_name = Paragraph(1..2).fake::<String>();
        let email = format!(
            "{}{}{}",
            Word().fake::<String>(),
            Word().fake::<String>(),
            SafeEmail().fake::<String>()
        );
        let password = "password123";

        let user = api::setup::tests::setup_post(router, &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;
        let response = second_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/auth")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "email": &email,
                            "password": &password,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: SessionResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);

        let session_id = body.id;

        let name = format!("workspace {}", Word().fake::<String>());
        let r#type = "Public";

        let response = third_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/workspaces")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "name": &name,
                            "type": r#type,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: Workspace = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);
        assert_eq!(body.name, name);

        let workspace_id = body.id;

        let response = fourth_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri(format!("/api/v1/chats/{workspace_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: Chat = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);

        let chat_id = body.id;

        let message = "test message";

        let response = fifth_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri(format!("/api/v1/chat-messages/{chat_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "message": &message,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: ChatMessage = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.message, message);

        let chat_message_id = body.id;

        let mut form = multipart::Form::default();
        form.add_file_with_mime("test.png", "data/test/test.png", mime::IMAGE_PNG)
            .unwrap();
        let req_builder = Request::builder()
            .method(http::Method::POST)
            .uri(format!("/api/v1/chat-message-pictures/{chat_message_id}"))
            .header("X-Auth-Token".to_string(), session_id.to_string());
        let request = form
            .set_body_convert::<hyper::Body, multipart::Body>(req_builder)
            .unwrap();

        let response = sixth_router.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: ChatMessagePicture = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.chat_message_id, chat_message_id);

        let chat_message_picture_id = body.id;

        let email = format!(
            "{}{}{}",
            Word().fake::<String>(),
            Word().fake::<String>(),
            SafeEmail().fake::<String>()
        );
        let job_title = Paragraph(1..2).fake::<String>();
        let name = Name().fake::<String>();
        let password = "password123";

        let response = seventh_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri(format!("/api/v1/auth/register/{company_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "email": &email,
                            "job_title": &job_title,
                            "name": &name,
                            "password": &password,
                            "repeat_password": &password,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: User = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.email, email);

        let user2_id = body.id;

        let response = eighth_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/auth")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "email": &email,
                            "password": &password,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: SessionResponse = serde_json::from_slice(&body).unwrap();

        let session_id = body.id;

        let response = ninth_router
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

        app.context
            .octopus_database
            .try_delete_chat_message_picture_by_id(chat_message_picture_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_chat_message_by_id(chat_message_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_user_by_id(user_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_user_by_id(user2_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_company_by_id(company_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_chat_by_id(chat_id)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn read_404() {
        let args = Args {
            azure_openai_api_key: None,
            azure_openai_deployment_id: None,
            azure_openai_enabled: Some(true),
            database_url: Some(String::from(
                "postgres://admin:admin@db/octopus_server_test",
            )),
            openai_api_key: None,
            port: None,
        };
        let app = app::get_app(args).await.unwrap();
        let router = app.router;
        let second_router = router.clone();
        let third_router = router.clone();
        let fourth_router = router.clone();
        let fifth_router = router.clone();

        let company_name = Paragraph(1..2).fake::<String>();
        let email = format!(
            "{}{}{}",
            Word().fake::<String>(),
            Word().fake::<String>(),
            SafeEmail().fake::<String>()
        );
        let password = "password123";

        let user = api::setup::tests::setup_post(router, &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;
        let response = second_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/auth")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "email": &email,
                            "password": &password,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: SessionResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);

        let session_id = body.id;

        let name = format!("workspace {}", Word().fake::<String>());
        let r#type = "Public";

        let response = third_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/workspaces")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "name": &name,
                            "type": r#type,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: Workspace = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);
        assert_eq!(body.name, name);

        let workspace_id = body.id;

        let response = fourth_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri(format!("/api/v1/chats/{workspace_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: Chat = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);

        let chat_id = body.id;

        let chat_message_id = "33847746-0030-4964-a496-f75d04499160";
        let chat_message_picture_id = "33847746-0030-4964-a496-f75d04499160";

        let response = fifth_router
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

        app.context
            .octopus_database
            .try_delete_user_by_id(user_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_company_by_id(company_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_chat_by_id(chat_id)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn update_200() {
        let args = Args {
            azure_openai_api_key: None,
            azure_openai_deployment_id: None,
            azure_openai_enabled: Some(true),
            database_url: Some(String::from(
                "postgres://admin:admin@db/octopus_server_test",
            )),
            openai_api_key: None,
            port: None,
        };
        let app = app::get_app(args).await.unwrap();
        let router = app.router;
        let second_router = router.clone();
        let third_router = router.clone();
        let fourth_router = router.clone();
        let fifth_router = router.clone();
        let sixth_router = router.clone();
        let seventh_router = router.clone();

        let company_name = Paragraph(1..2).fake::<String>();
        let email = format!(
            "{}{}{}",
            Word().fake::<String>(),
            Word().fake::<String>(),
            SafeEmail().fake::<String>()
        );
        let password = "password123";

        let user = api::setup::tests::setup_post(router, &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;
        let response = second_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/auth")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "email": &email,
                            "password": &password,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: SessionResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);

        let session_id = body.id;

        let name = format!("workspace {}", Word().fake::<String>());
        let r#type = "Public";

        let response = third_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/workspaces")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "name": &name,
                            "type": r#type,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: Workspace = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);
        assert_eq!(body.name, name);

        let workspace_id = body.id;

        let response = fourth_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri(format!("/api/v1/chats/{workspace_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: Chat = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);

        let chat_id = body.id;

        let message = "test message";

        let response = fifth_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri(format!("/api/v1/chat-messages/{chat_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "message": &message,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: ChatMessage = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.message, message);

        let chat_message_id = body.id;

        let mut form = multipart::Form::default();
        form.add_file_with_mime("test.png", "data/test/test.png", mime::IMAGE_PNG)
            .unwrap();
        let req_builder = Request::builder()
            .method(http::Method::POST)
            .uri(format!("/api/v1/chat-message-pictures/{chat_message_id}"))
            .header("X-Auth-Token".to_string(), session_id.to_string());
        let request = form
            .set_body_convert::<hyper::Body, multipart::Body>(req_builder)
            .unwrap();

        let response = sixth_router.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: ChatMessagePicture = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.chat_message_id, chat_message_id);

        let chat_message_picture_id = body.id;

        let mut form = multipart::Form::default();
        form.add_file_with_mime("test.png", "data/test/test.png", mime::IMAGE_PNG)
            .unwrap();
        let req_builder = Request::builder()
            .method(http::Method::PUT)
            .uri(format!(
                "/api/v1/chat-message-pictures/{chat_message_id}/{chat_message_picture_id}"
            ))
            .header("X-Auth-Token".to_string(), session_id.to_string());
        let request = form
            .set_body_convert::<hyper::Body, multipart::Body>(req_builder)
            .unwrap();

        let response = seventh_router.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: ChatMessagePicture = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.chat_message_id, chat_message_id);

        app.context
            .octopus_database
            .try_delete_chat_message_picture_by_id(chat_message_picture_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_chat_message_by_id(chat_message_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_user_by_id(user_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_company_by_id(company_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_chat_by_id(chat_id)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn update_401() {
        let args = Args {
            azure_openai_api_key: None,
            azure_openai_deployment_id: None,
            azure_openai_enabled: Some(true),
            database_url: Some(String::from(
                "postgres://admin:admin@db/octopus_server_test",
            )),
            openai_api_key: None,
            port: None,
        };
        let app = app::get_app(args).await.unwrap();
        let router = app.router;
        let second_router = router.clone();
        let third_router = router.clone();
        let fourth_router = router.clone();
        let fifth_router = router.clone();
        let sixth_router = router.clone();
        let seventh_router = router.clone();

        let company_name = Paragraph(1..2).fake::<String>();
        let email = format!(
            "{}{}{}",
            Word().fake::<String>(),
            Word().fake::<String>(),
            SafeEmail().fake::<String>()
        );
        let password = "password123";

        let user = api::setup::tests::setup_post(router, &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;
        let response = second_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/auth")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "email": &email,
                            "password": &password,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: SessionResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);

        let session_id = body.id;

        let name = format!("workspace {}", Word().fake::<String>());
        let r#type = "Public";

        let response = third_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/workspaces")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "name": &name,
                            "type": r#type,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: Workspace = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);
        assert_eq!(body.name, name);

        let workspace_id = body.id;

        let response = fourth_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri(format!("/api/v1/chats/{workspace_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: Chat = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);

        let chat_id = body.id;

        let message = "test message";

        let response = fifth_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri(format!("/api/v1/chat-messages/{chat_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "message": &message,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: ChatMessage = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.message, message);

        let chat_message_id = body.id;

        let mut form = multipart::Form::default();
        form.add_file_with_mime("test.png", "data/test/test.png", mime::IMAGE_PNG)
            .unwrap();
        let req_builder = Request::builder()
            .method(http::Method::POST)
            .uri(format!("/api/v1/chat-message-pictures/{chat_message_id}"))
            .header("X-Auth-Token".to_string(), session_id.to_string());
        let request = form
            .set_body_convert::<hyper::Body, multipart::Body>(req_builder)
            .unwrap();

        let response = sixth_router.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: ChatMessagePicture = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.chat_message_id, chat_message_id);

        let chat_message_picture_id = body.id;

        let mut form = multipart::Form::default();
        form.add_file_with_mime("test.png", "data/test/test.png", mime::IMAGE_PNG)
            .unwrap();
        let req_builder = Request::builder().method(http::Method::PUT).uri(format!(
            "/api/v1/chat-message-pictures/{chat_message_id}/{chat_message_picture_id}"
        ));
        let request = form
            .set_body_convert::<hyper::Body, multipart::Body>(req_builder)
            .unwrap();

        let response = seventh_router.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        app.context
            .octopus_database
            .try_delete_chat_message_picture_by_id(chat_message_picture_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_chat_message_by_id(chat_message_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_user_by_id(user_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_company_by_id(company_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_chat_by_id(chat_id)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn update_403() {
        let args = Args {
            azure_openai_api_key: None,
            azure_openai_deployment_id: None,
            azure_openai_enabled: Some(true),
            database_url: Some(String::from(
                "postgres://admin:admin@db/octopus_server_test",
            )),
            openai_api_key: None,
            port: None,
        };
        let app = app::get_app(args).await.unwrap();
        let router = app.router;
        let second_router = router.clone();
        let third_router = router.clone();
        let fourth_router = router.clone();
        let fifth_router = router.clone();
        let sixth_router = router.clone();
        let seventh_router = router.clone();
        let eighth_router = router.clone();
        let ninth_router = router.clone();

        let company_name = Paragraph(1..2).fake::<String>();
        let email = format!(
            "{}{}{}",
            Word().fake::<String>(),
            Word().fake::<String>(),
            SafeEmail().fake::<String>()
        );
        let password = "password123";

        let user = api::setup::tests::setup_post(router, &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;
        let response = second_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/auth")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "email": &email,
                            "password": &password,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: SessionResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);

        let session_id = body.id;

        let name = format!("workspace {}", Word().fake::<String>());
        let r#type = "Public";

        let response = third_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/workspaces")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "name": &name,
                            "type": r#type,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: Workspace = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);
        assert_eq!(body.name, name);

        let workspace_id = body.id;

        let response = fourth_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri(format!("/api/v1/chats/{workspace_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: Chat = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);

        let chat_id = body.id;

        let message = "test message";

        let response = fifth_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri(format!("/api/v1/chat-messages/{chat_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "message": &message,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: ChatMessage = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.message, message);

        let chat_message_id = body.id;

        let mut form = multipart::Form::default();
        form.add_file_with_mime("test.png", "data/test/test.png", mime::IMAGE_PNG)
            .unwrap();
        let req_builder = Request::builder()
            .method(http::Method::POST)
            .uri(format!("/api/v1/chat-message-pictures/{chat_message_id}"))
            .header("X-Auth-Token".to_string(), session_id.to_string());
        let request = form
            .set_body_convert::<hyper::Body, multipart::Body>(req_builder)
            .unwrap();

        let response = sixth_router.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: ChatMessagePicture = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.chat_message_id, chat_message_id);

        let chat_message_picture_id = body.id;

        let email = format!(
            "{}{}{}",
            Word().fake::<String>(),
            Word().fake::<String>(),
            SafeEmail().fake::<String>()
        );
        let job_title = Paragraph(1..2).fake::<String>();
        let name = Name().fake::<String>();
        let password = "password123";

        let response = seventh_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri(format!("/api/v1/auth/register/{company_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "email": &email,
                            "job_title": &job_title,
                            "name": &name,
                            "password": &password,
                            "repeat_password": &password,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: User = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.email, email);

        let user2_id = body.id;

        let response = eighth_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/auth")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "email": &email,
                            "password": &password,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: SessionResponse = serde_json::from_slice(&body).unwrap();

        let session_id = body.id;

        let mut form = multipart::Form::default();
        form.add_file_with_mime("test.png", "data/test/test.png", mime::IMAGE_PNG)
            .unwrap();
        let req_builder = Request::builder()
            .method(http::Method::PUT)
            .uri(format!(
                "/api/v1/chat-message-pictures/{chat_message_id}/{chat_message_picture_id}"
            ))
            .header("X-Auth-Token".to_string(), session_id.to_string());
        let request = form
            .set_body_convert::<hyper::Body, multipart::Body>(req_builder)
            .unwrap();

        let response = ninth_router.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        app.context
            .octopus_database
            .try_delete_chat_message_picture_by_id(chat_message_picture_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_chat_message_by_id(chat_message_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_user_by_id(user_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_user_by_id(user2_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_company_by_id(company_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_chat_by_id(chat_id)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn update_404() {
        let args = Args {
            azure_openai_api_key: None,
            azure_openai_deployment_id: None,
            azure_openai_enabled: Some(true),
            database_url: Some(String::from(
                "postgres://admin:admin@db/octopus_server_test",
            )),
            openai_api_key: None,
            port: None,
        };
        let app = app::get_app(args).await.unwrap();
        let router = app.router;
        let second_router = router.clone();
        let third_router = router.clone();
        let fourth_router = router.clone();
        let fifth_router = router.clone();

        let company_name = Paragraph(1..2).fake::<String>();
        let email = format!(
            "{}{}{}",
            Word().fake::<String>(),
            Word().fake::<String>(),
            SafeEmail().fake::<String>()
        );
        let password = "password123";

        let user = api::setup::tests::setup_post(router, &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;
        let response = second_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/auth")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "email": &email,
                            "password": &password,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: SessionResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);

        let session_id = body.id;

        let name = format!("workspace {}", Word().fake::<String>());
        let r#type = "Public";

        let response = third_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/workspaces")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "name": &name,
                            "type": r#type,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: Workspace = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);
        assert_eq!(body.name, name);

        let workspace_id = body.id;

        let response = fourth_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri(format!("/api/v1/chats/{workspace_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: Chat = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);

        let chat_id = body.id;

        let chat_message_id = "33847746-0030-4964-a496-f75d04499160";
        let chat_message_picture_id = "33847746-0030-4964-a496-f75d04499160";

        let mut form = multipart::Form::default();
        form.add_file_with_mime("test.png", "data/test/test.png", mime::IMAGE_PNG)
            .unwrap();
        let req_builder = Request::builder()
            .method(http::Method::PUT)
            .uri(format!(
                "/api/v1/chat-message-pictures/{chat_message_id}/{chat_message_picture_id}"
            ))
            .header("X-Auth-Token".to_string(), session_id.to_string());
        let request = form
            .set_body_convert::<hyper::Body, multipart::Body>(req_builder)
            .unwrap();

        let response = fifth_router.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        app.context
            .octopus_database
            .try_delete_user_by_id(user_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_company_by_id(company_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_chat_by_id(chat_id)
            .await
            .unwrap();
    }
}
