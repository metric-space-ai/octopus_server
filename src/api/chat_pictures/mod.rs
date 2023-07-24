use crate::{
    context::Context,
    entity::ROLE_COMPANY_ADMIN_USER,
    error::AppError,
    session::{require_authenticated_session, ExtractedSession},
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

pub const PUBLIC_DIR: &str = "public";

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
        (status = 401, description = "Unauthorized request.", body = ResponseError),
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
    let session = require_authenticated_session(extracted_session).await?;

    let chat = context
        .octopus_database
        .try_get_chat_by_id(chat_id)
        .await?
        .ok_or(AppError::NotFound)?;

    if chat.user_id != session.user_id {
        return Err(AppError::Unauthorized);
    }

    let chat_picture_exists = context
        .octopus_database
        .try_get_chat_picture_by_chat_id(chat_id)
        .await?;

    match chat_picture_exists {
        None => {
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

                    let chat_picture = context
                        .octopus_database
                        .insert_chat_picture(chat_id, &file_name)
                        .await?;

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
        (status = 401, description = "Unauthorized request.", body = ResponseError),
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
    let session = require_authenticated_session(extracted_session).await?;

    let session_user = context
        .octopus_database
        .try_get_user_by_id(session.user_id)
        .await?
        .ok_or(AppError::Unauthorized)?;

    let chat_picture = context
        .octopus_database
        .try_get_chat_picture_by_id(chat_picture_id)
        .await?
        .ok_or(AppError::NotFound)?;

    if chat_id != chat_picture.chat_id {
        return Err(AppError::Unauthorized);
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
        return Err(AppError::Unauthorized);
    }

    context
        .octopus_database
        .try_delete_chat_picture_by_id(chat_picture_id)
        .await?
        .ok_or(AppError::NotFound)?;

    let path = format!("{PUBLIC_DIR}/{}", chat_picture.file_name);
    remove_file(path)?;

    Ok((StatusCode::NO_CONTENT, ()).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    get,
    path = "/api/v1/chat-pictures/:chat_id/:chat_picture_id",
    responses(
        (status = 200, description = "Chat picture read.", body = ChatPicture),
        (status = 401, description = "Unauthorized request.", body = ResponseError),
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
    let session = require_authenticated_session(extracted_session).await?;

    let session_user = context
        .octopus_database
        .try_get_user_by_id(session.user_id)
        .await?
        .ok_or(AppError::Unauthorized)?;

    let chat_picture = context
        .octopus_database
        .try_get_chat_picture_by_id(chat_picture_id)
        .await?
        .ok_or(AppError::NotFound)?;

    if chat_id != chat_picture.chat_id {
        return Err(AppError::Unauthorized);
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

    if session_user.id != chat.user_id && session_user.company_id != user.company_id {
        return Err(AppError::Unauthorized);
    }

    Ok((StatusCode::OK, Json(chat_picture)).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    put,
    path = "/api/v1/chat-pictures/:chat_id/:chat_picture_id",
    responses(
        (status = 200, description = "Chat picture updated.", body = ChatPicture),
        (status = 401, description = "Unauthorized request.", body = ResponseError),
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
    let session = require_authenticated_session(extracted_session).await?;

    let session_user = context
        .octopus_database
        .try_get_user_by_id(session.user_id)
        .await?
        .ok_or(AppError::Unauthorized)?;

    let chat_picture = context
        .octopus_database
        .try_get_chat_picture_by_id(chat_picture_id)
        .await?
        .ok_or(AppError::NotFound)?;

    if chat_id != chat_picture.chat_id {
        return Err(AppError::Unauthorized);
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
        return Err(AppError::Unauthorized);
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

            let old_file = format!("{PUBLIC_DIR}/{}", chat_picture.file_name);

            let file_name = format!("{}.{}", Uuid::new_v4(), extension);
            let path = format!("{PUBLIC_DIR}/{file_name}");

            let mut file = File::create(path)?;
            file.write_all(&data)?;

            let chat_picture = context
                .octopus_database
                .update_chat_picture(chat_picture_id, &file_name)
                .await?;

            remove_file(old_file)?;

            return Ok((StatusCode::CREATED, Json(chat_picture)).into_response());
        }
    }

    Err(AppError::BadRequest)
}
/*
#[cfg(test)]
mod tests {
    use crate::{app, entity::Chat, entity::User, session::SessionResponse, Args};
    use axum::{
        body::Body,
        http::{self, Request, StatusCode},
    };
    use fake::{
        faker::{internet::en::SafeEmail, lorem::en::{Paragraph, Word}},
        Fake,
    };
    use mime::BOUNDARY;
    extern crate hyper_multipart_rfc7578 as hyper_multipart;
    use hyper::Client;
    use hyper_multipart::client::{self, multipart};
    use rand::{distributions::Alphanumeric, thread_rng, Rng};
    use std::{fs::File, io, io::{Read, Write}};
    use tower::ServiceExt;

    #[tokio::test]
    async fn create_201() {
        let args = Args {
            database_url: Some(String::from("postgres://admin:admin@db/octopus_server_test")),
            openai_api_key: None,
            port: None,
        };
        let app = app::get_app(args).await.unwrap();
        let router = app.router;
        let second_router = router.clone();
        let third_router = router.clone();
        let fourth_router = router.clone();

        let company_name = Paragraph(1..2).fake::<String>();
        let email = format!("{}{}{}", Word().fake::<String>(), Word().fake::<String>(), SafeEmail().fake::<String>());
        let password = "password123";

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/auth/register-company")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "company_name": &company_name,
                            "email": &email,
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

        let company_id = body.company_id;
        let user_id = body.id;

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

        let response = third_router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/chats")
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

        let data = image_data().unwrap();
        let client = Client::new();
        let mut form = multipart::Form::default();
        form.add_file("test.png", "test.png").unwrap();
        let mut req_builder = Request::builder()
                    .method(http::Method::POST)
                    .uri(format!("/api/v1/chat-pictures/{}", chat_id))
                    .header(http::header::CONTENT_TYPE, mime::MULTIPART_FORM_DATA.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string());
        let form = form.set_body_convert::<hyper::Body, multipart::Body>(req_builder).unwrap();

println!("form = {:?}", form.body());

        let response = fourth_router
            .oneshot(
                form
            )
            .await
            .unwrap();

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        assert_eq!(vec![0], body.to_vec());

        //assert_eq!(response.status(), StatusCode::CREATED);

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

    fn image_data() -> io::Result<Vec<u8>> {
        let mut data = Vec::new();
        let boundary = generate_boundary();

        write!(data, "--{}\r\n", boundary)?;
        write!(
            data,
            "Content-Disposition: form-data; name=\"file\"; filename=\"test.png\"\r\n"
        )?;
        write!(data, "Content-Type: image/png\r\n")?;
        write!(data, "\r\n")?;

        let mut f = File::open("test.png")?;
        f.read_to_end(&mut data)?;

        write!(data, "\r\n")?;
        write!(data, "--{}--\r\n", boundary)?;

        Ok(data)
    }

    fn generate_boundary() -> String {
        let boundary =  rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(20)
            .map(char::from)
            .collect();
        boundary
    }
}
*/
