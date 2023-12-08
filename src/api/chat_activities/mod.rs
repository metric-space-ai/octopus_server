use crate::{
    context::Context,
    error::AppError,
    session::{require_authenticated_session, ExtractedSession},
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
    post,
    path = "/api/v1/chat-activities/:chat_id",
    responses(
        (status = 201, description = "Chat activity created.", body = ChatActivity),
        (status = 401, description = "Unauthorized.", body = ResponseError),
        (status = 403, description = "Forbidden.", body = ResponseError),
        (status = 404, description = "Chat not found.", body = ResponseError),
    ),
    params(
        ("chat_id" = String, Path, description = "Chat id")
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn create(
    State(context): State<Arc<Context>>,
    extracted_session: ExtractedSession,
    Path(chat_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let session = require_authenticated_session(extracted_session).await?;

    let session_user = context
        .octopus_database
        .try_get_user_by_id(session.user_id)
        .await?
        .ok_or(AppError::Forbidden)?;

    let chat = context
        .octopus_database
        .try_get_chat_by_id(chat_id)
        .await?
        .ok_or(AppError::NotFound)?;

    let user = context
        .octopus_database
        .try_get_user_by_id(chat.user_id)
        .await?
        .ok_or(AppError::NotFound)?;

    if session_user.id != chat.user_id && session_user.company_id != user.company_id {
        return Err(AppError::Forbidden);
    }

    let mut transaction = context.octopus_database.transaction_begin().await?;

    let chat_activity = context
        .octopus_database
        .insert_chat_activity(&mut transaction, chat.id, session.id, session_user.id)
        .await?;

    context
        .octopus_database
        .transaction_commit(transaction)
        .await?;

    Ok((StatusCode::CREATED, Json(chat_activity)).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    get,
    path = "/api/v1/chat-activities/:chat_id",
    responses(
        (status = 200, description = "List of the latest chat activities.", body = [ChatActivity]),
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
    Path(chat_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let session = require_authenticated_session(extracted_session).await?;

    let session_user = context
        .octopus_database
        .try_get_user_by_id(session.user_id)
        .await?
        .ok_or(AppError::Forbidden)?;

    let chat = context.octopus_database.try_get_chat_by_id(chat_id).await?;

    if let Some(chat) = chat {
        let user = context
            .octopus_database
            .try_get_user_by_id(chat.user_id)
            .await?
            .ok_or(AppError::NotFound)?;

        if session_user.id != chat.user_id && session_user.company_id != user.company_id {
            return Err(AppError::Forbidden);
        }

        let chat_activities = context
            .octopus_database
            .get_chat_activities_latest_by_chat_id_and_session_id(chat.id, session.id)
            .await?;

        return Ok((StatusCode::OK, Json(chat_activities)).into_response());
    }

    Ok((StatusCode::OK, Json(())).into_response())
}

#[cfg(test)]
mod tests {
    use crate::{api, app, entity::ChatActivity};
    use axum::{
        body::Body,
        http::{self, Request, StatusCode},
        Router,
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
    use uuid::Uuid;

    pub async fn chat_activity_create(
        router: Router,
        session_id: Uuid,
        chat_id: Uuid,
        user_id: Uuid,
    ) -> ChatActivity {
        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri(format!("/api/v1/chat-activities/{chat_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = BodyExt::collect(response.into_body())
            .await
            .unwrap()
            .to_bytes()
            .to_vec();
        let body: ChatActivity = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);

        body
    }

    #[tokio::test]
    async fn create_201() {
        let app = app::tests::get_test_app().await;
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

        let user = api::setup::tests::setup_post(router, &company_name, &email, password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(second_router, &email, password, user_id).await;
        let session_id = session_response.id;

        let name = format!("workspace {}", Word().fake::<String>());
        let r#type = "Public";

        let workspace = api::workspaces::tests::workspace_create(
            third_router,
            session_id,
            user_id,
            &name,
            r#type,
        )
        .await;
        let workspace_id = workspace.id;

        let chat =
            api::chats::tests::chat_create(fourth_router, session_id, user_id, workspace_id).await;
        let chat_id = chat.id;

        chat_activity_create(fifth_router, session_id, chat_id, user_id).await;

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
    async fn create_401() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let company_name = Paragraph(1..2).fake::<String>();
        let email = format!(
            "{}{}{}",
            Word().fake::<String>(),
            Word().fake::<String>(),
            SafeEmail().fake::<String>()
        );
        let password = "password123";

        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, password, user_id).await;
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

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri(format!("/api/v1/chat-activities/{chat_id}"))
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
    async fn create_403() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let company_name = Paragraph(1..2).fake::<String>();
        let email = format!(
            "{}{}{}",
            Word().fake::<String>(),
            Word().fake::<String>(),
            SafeEmail().fake::<String>()
        );
        let password = "password123";

        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, password, user_id).await;
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

        let company_name = Paragraph(1..2).fake::<String>();
        let email = format!(
            "{}{}{}",
            Word().fake::<String>(),
            Word().fake::<String>(),
            SafeEmail().fake::<String>()
        );
        let password = "password123";

        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, password).await;
        let second_company_id = user.company_id;
        let second_user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, password, second_user_id)
                .await;
        let session_id = session_response.id;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri(format!("/api/v1/chat-activities/{chat_id}"))
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
    async fn create_404() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let company_name = Paragraph(1..2).fake::<String>();
        let email = format!(
            "{}{}{}",
            Word().fake::<String>(),
            Word().fake::<String>(),
            SafeEmail().fake::<String>()
        );
        let password = "password123";

        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, password, user_id).await;
        let session_id = session_response.id;

        let chat_id = "33847746-0030-4964-a496-f75d04499160";

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri(format!("/api/v1/chat-activities/{chat_id}"))
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

    #[tokio::test]
    async fn list_200() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let company_name = Paragraph(1..2).fake::<String>();
        let email = format!(
            "{}{}{}",
            Word().fake::<String>(),
            Word().fake::<String>(),
            SafeEmail().fake::<String>()
        );
        let password = "password123";

        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, password, user_id).await;
        let admin_session_id = session_response.id;

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

        let name = format!("workspace {}", Word().fake::<String>());
        let r#type = "Public";

        let workspace = api::workspaces::tests::workspace_create(
            router.clone(),
            admin_session_id,
            user_id,
            &name,
            r#type,
        )
        .await;
        let workspace_id = workspace.id;

        let chat =
            api::chats::tests::chat_create(router.clone(), admin_session_id, user_id, workspace_id)
                .await;
        let chat_id = chat.id;

        chat_activity_create(router.clone(), admin_session_id, chat_id, user_id).await;

        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("/api/v1/chat-activities/{chat_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), admin_session_id.to_string())
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
        let body: Vec<ChatActivity> = serde_json::from_slice(&body).unwrap();

        assert!(body.is_empty());

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("/api/v1/chat-activities/{chat_id}"))
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
        let body: Vec<ChatActivity> = serde_json::from_slice(&body).unwrap();

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
    async fn list_401() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let company_name = Paragraph(1..2).fake::<String>();
        let email = format!(
            "{}{}{}",
            Word().fake::<String>(),
            Word().fake::<String>(),
            SafeEmail().fake::<String>()
        );
        let password = "password123";

        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, password, user_id).await;
        let admin_session_id = session_response.id;

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

        api::auth::login::tests::login_post(router.clone(), &email, password, second_user_id).await;

        let name = format!("workspace {}", Word().fake::<String>());
        let r#type = "Public";

        let workspace = api::workspaces::tests::workspace_create(
            router.clone(),
            admin_session_id,
            user_id,
            &name,
            r#type,
        )
        .await;
        let workspace_id = workspace.id;

        let chat =
            api::chats::tests::chat_create(router.clone(), admin_session_id, user_id, workspace_id)
                .await;
        let chat_id = chat.id;

        chat_activity_create(router.clone(), admin_session_id, chat_id, user_id).await;

        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("/api/v1/chat-activities/{chat_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), admin_session_id.to_string())
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
        let body: Vec<ChatActivity> = serde_json::from_slice(&body).unwrap();

        assert!(body.is_empty());

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("/api/v1/chat-activities/{chat_id}"))
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

        let company_name = Paragraph(1..2).fake::<String>();
        let email = format!(
            "{}{}{}",
            Word().fake::<String>(),
            Word().fake::<String>(),
            SafeEmail().fake::<String>()
        );
        let password = "password123";

        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, password, user_id).await;
        let admin_session_id = session_response.id;

        let name = format!("workspace {}", Word().fake::<String>());
        let r#type = "Public";

        let workspace = api::workspaces::tests::workspace_create(
            router.clone(),
            admin_session_id,
            user_id,
            &name,
            r#type,
        )
        .await;
        let workspace_id = workspace.id;

        let chat =
            api::chats::tests::chat_create(router.clone(), admin_session_id, user_id, workspace_id)
                .await;
        let chat_id = chat.id;

        chat_activity_create(router.clone(), admin_session_id, chat_id, user_id).await;

        let company_name = Paragraph(1..2).fake::<String>();
        let email = format!(
            "{}{}{}",
            Word().fake::<String>(),
            Word().fake::<String>(),
            SafeEmail().fake::<String>()
        );
        let password = "password123";

        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, password).await;
        let second_company_id = user.company_id;
        let second_user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, password, second_user_id)
                .await;
        let session_id = session_response.id;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("/api/v1/chat-activities/{chat_id}"))
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
            .try_delete_workspace_by_id(&mut transaction, workspace_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .transaction_commit(transaction)
            .await
            .unwrap();
    }
}
