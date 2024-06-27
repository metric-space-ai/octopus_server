use crate::{
    context::Context,
    entity::ROLE_COMPANY_ADMIN_USER,
    error::AppError,
    session::{ensure_secured, require_authenticated, ExtractedSession},
    NEXTCLOUD_FILES_DIR,
};
use axum::{
    extract::{Multipart, Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use std::{
    fs::{remove_file, File},
    io::Write,
    sync::Arc,
};
use uuid::Uuid;

#[axum_macros::debug_handler]
#[utoipa::path(
    post,
    path = "/api/v1/nextcloud-files",
    responses(
        (status = 201, description = "Nextcloud file created.", body = NextcloudFile),
        (status = 400, description = "Bad request.", body = ResponseError),
        (status = 403, description = "Forbidden.", body = ResponseError),
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn create(
    State(context): State<Arc<Context>>,
    extracted_session: ExtractedSession,
    mut multipart: Multipart,
) -> Result<impl IntoResponse, AppError> {
    ensure_secured(context.clone(), extracted_session, ROLE_COMPANY_ADMIN_USER).await?;

    let mut content_type = None;
    let mut data = None;
    let mut original_file_name = None;

    while let Some(field) = multipart.next_field().await? {
        original_file_name = Some((field.file_name().ok_or(AppError::File)?).to_string());
        content_type = Some((field.content_type().ok_or(AppError::File)?).to_string());
        data = Some(field.bytes().await?.clone().to_vec());
    }

    if let (Some(content_type), Some(data), Some(original_file_name)) =
        (content_type, data, original_file_name)
    {
        let extension = (*original_file_name
            .split('.')
            .collect::<Vec<&str>>()
            .last()
            .ok_or(AppError::File)?).to_string();

        let file_name = format!("{}.{}", Uuid::new_v4(), extension);
        let nextcloud_subdir = context.get_config().await?.nextcloud_subdir;
        let path = format!("{NEXTCLOUD_FILES_DIR}/{nextcloud_subdir}{file_name}");

        let mut file = File::create(path)?;
        file.write_all(&data)?;

        let mut transaction = context.octopus_database.transaction_begin().await?;

        let nextcloud_file = context
            .octopus_database
            .insert_nextcloud_file(
                &mut transaction,
                &file_name,
                &content_type,
                &original_file_name,
            )
            .await?;

        context
            .octopus_database
            .transaction_commit(transaction)
            .await?;

        return Ok((StatusCode::CREATED, Json(nextcloud_file)).into_response());
    }

    Err(AppError::BadRequest)
}

#[axum_macros::debug_handler]
#[utoipa::path(
    delete,
    path = "/api/v1/nextcloud-files/:id",
    responses(
        (status = 204, description = "Nextcloud file deleted."),
        (status = 403, description = "Forbidden.", body = ResponseError),
        (status = 404, description = "Nextcloud file not found.", body = ResponseError),
    ),
    params(
        ("id" = String, Path, description = "Nextcloud file id")
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn delete(
    State(context): State<Arc<Context>>,
    extracted_session: ExtractedSession,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    ensure_secured(context.clone(), extracted_session, ROLE_COMPANY_ADMIN_USER).await?;

    let nextcloud_file = context
        .octopus_database
        .try_get_nextcloud_file_by_id(id)
        .await?
        .ok_or(AppError::NotFound)?;

    let nextcloud_subdir = context.get_config().await?.nextcloud_subdir;
    let old_path = format!(
        "{NEXTCLOUD_FILES_DIR}/{nextcloud_subdir}{}",
        nextcloud_file.file_name
    );

    let mut transaction = context.octopus_database.transaction_begin().await?;

    context
        .octopus_database
        .try_delete_nextcloud_file_by_id(&mut transaction, id)
        .await?
        .ok_or(AppError::NotFound)?;

    let file_exists = std::path::Path::new(&old_path).is_file();

    if file_exists {
        remove_file(old_path)?;
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
    path = "/api/v1/nextcloud-files",
    responses(
        (status = 200, description = "List of Nextcloud files.", body = [NextcloudFile]),
        (status = 401, description = "Unauthorized request.", body = ResponseError),
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn list(
    State(context): State<Arc<Context>>,
    extracted_session: ExtractedSession,
) -> Result<impl IntoResponse, AppError> {
    require_authenticated(extracted_session).await?;

    let nextcloud_files = context.octopus_database.get_nextcloud_files().await?;

    Ok((StatusCode::OK, Json(nextcloud_files)).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    get,
    path = "/api/v1/nextcloud-files/:id",
    responses(
        (status = 200, description = "Nextcloud file read.", body = NextcloudFile),
        (status = 401, description = "Unauthorized request.", body = ResponseError),
        (status = 404, description = "Nextcloud file not found.", body = ResponseError),
    ),
    params(
        ("id" = String, Path, description = "Nextcloud file id")
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn read(
    State(context): State<Arc<Context>>,
    extracted_session: ExtractedSession,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    require_authenticated(extracted_session).await?;

    let nextcloud_file = context
        .octopus_database
        .try_get_nextcloud_file_by_id(id)
        .await?
        .ok_or(AppError::NotFound)?;

    Ok((StatusCode::OK, Json(nextcloud_file)).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    put,
    path = "/api/v1/nextcloud-files/:id",
    responses(
        (status = 200, description = "Nextcloud file updated.", body = NextcloudFile),
        (status = 400, description = "Bad request.", body = ResponseError),
        (status = 403, description = "Forbidden.", body = ResponseError),
        (status = 404, description = "Nextcloud file not found.", body = ResponseError),
    ),
    params(
        ("id" = String, Path, description = "Nextcloud file id")
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn update(
    State(context): State<Arc<Context>>,
    extracted_session: ExtractedSession,
    Path(id): Path<Uuid>,
    mut multipart: Multipart,
) -> Result<impl IntoResponse, AppError> {
    ensure_secured(context.clone(), extracted_session, ROLE_COMPANY_ADMIN_USER).await?;

    let nextcloud_file = context
        .octopus_database
        .try_get_nextcloud_file_by_id(id)
        .await?
        .ok_or(AppError::NotFound)?;

    let mut content_type = None;
    let mut data = None;
    let mut original_file_name = None;

    while let Some(field) = multipart.next_field().await? {
        original_file_name = Some((field.file_name().ok_or(AppError::File)?).to_string());
        content_type = Some((field.content_type().ok_or(AppError::File)?).to_string());
        data = Some(field.bytes().await?.clone().to_vec());
    }

    if let (Some(content_type), Some(data), Some(original_file_name)) =
        (content_type, data, original_file_name)
    {
        let nextcloud_subdir = context.get_config().await?.nextcloud_subdir;
        let old_path = format!(
            "{NEXTCLOUD_FILES_DIR}/{nextcloud_subdir}{}",
            nextcloud_file.file_name
        );

        let extension = (*original_file_name
            .split('.')
            .collect::<Vec<&str>>()
            .last()
            .ok_or(AppError::File)?).to_string();

        let file_name = format!("{}.{}", Uuid::new_v4(), extension);
        let path = format!("{NEXTCLOUD_FILES_DIR}/{nextcloud_subdir}{file_name}");

        let mut file = File::create(path)?;
        file.write_all(&data)?;

        let mut transaction = context.octopus_database.transaction_begin().await?;

        let nextcloud_file = context
            .octopus_database
            .update_nextcloud_file(
                &mut transaction,
                id,
                &file_name,
                &content_type,
                &original_file_name,
            )
            .await?;

        let file_exists = std::path::Path::new(&old_path).is_file();

        if file_exists {
            remove_file(old_path)?;
        }

        context
            .octopus_database
            .transaction_commit(transaction)
            .await?;

        return Ok((StatusCode::OK, Json(nextcloud_file)).into_response());
    }

    Err(AppError::BadRequest)
}

#[cfg(test)]
mod tests {
    use crate::{api, app, context::Context, entity::NextcloudFile, multipart};
    use axum::{
        body::Body,
        http::{self, Request, StatusCode},
        Router,
    };
    use http_body_util::BodyExt;
    use sqlx::{Postgres, Transaction};
    use std::sync::Arc;
    use tower::ServiceExt;
    use uuid::Uuid;

    pub async fn nextcloud_files_cleanup(
        context: Arc<Context>,
        transaction: &mut Transaction<'_, Postgres>,
        nextcloud_file_id: Uuid,
    ) {
        let _ = context
            .octopus_database
            .try_delete_nextcloud_file_by_id(transaction, nextcloud_file_id)
            .await;
    }

    pub async fn nextcloud_files_create(router: Router, session_id: Uuid) -> NextcloudFile {
        let body =
            multipart::tests::file_data("text/html", "test.html", "data/test/test.html", true)
                .unwrap();

        let value = format!(
            "{}; boundary={}",
            mime::MULTIPART_FORM_DATA,
            multipart::tests::BOUNDARY
        );

        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/api/v1/nextcloud-files")
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
        let body: NextcloudFile = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.original_file_name, "test.html");

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

        let nextcloud_file = nextcloud_files_create(router, session_id).await;
        let nextcloud_file_id = nextcloud_file.id;

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        nextcloud_files_cleanup(app.context.clone(), &mut transaction, nextcloud_file_id).await;

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
    async fn create_400() {
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

        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/api/v1/nextcloud-files")
            .header(
                http::header::CONTENT_TYPE,
                mime::MULTIPART_FORM_DATA.as_ref(),
            )
            .header("X-Auth-Token".to_string(), session_id.to_string())
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

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

        let body =
            multipart::tests::file_data("text/html", "test.html", "data/test/test.html", true)
                .unwrap();

        let value = format!(
            "{}; boundary={}",
            mime::MULTIPART_FORM_DATA,
            multipart::tests::BOUNDARY
        );

        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/api/v1/nextcloud-files")
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

        let nextcloud_file = nextcloud_files_create(router.clone(), session_id).await;
        let nextcloud_file_id = nextcloud_file.id;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::DELETE)
                    .uri(format!("/api/v1/nextcloud-files/{nextcloud_file_id}"))
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

        let nextcloud_file = nextcloud_files_create(router.clone(), session_id).await;
        let nextcloud_file_id = nextcloud_file.id;

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
                    .uri(format!("/api/v1/nextcloud-files/{nextcloud_file_id}"))
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

        nextcloud_files_cleanup(app.context.clone(), &mut transaction, nextcloud_file_id).await;

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

        let nextcloud_file_id = "33847746-0030-4964-a496-f75d04499160";

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::DELETE)
                    .uri(format!("/api/v1/nextcloud-files/{nextcloud_file_id}"))
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

        let nextcloud_file = nextcloud_files_create(router.clone(), session_id).await;
        let nextcloud_file_id = nextcloud_file.id;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri("/api/v1/nextcloud-files".to_string())
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
        let body: Vec<NextcloudFile> = serde_json::from_slice(&body).unwrap();

        assert!(!body.is_empty());

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        nextcloud_files_cleanup(app.context.clone(), &mut transaction, nextcloud_file_id).await;

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

        let nextcloud_file = nextcloud_files_create(router.clone(), session_id).await;
        let nextcloud_file_id = nextcloud_file.id;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri("/api/v1/nextcloud-files".to_string())
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

        nextcloud_files_cleanup(app.context.clone(), &mut transaction, nextcloud_file_id).await;

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

        let nextcloud_file = nextcloud_files_create(router.clone(), session_id).await;
        let nextcloud_file_id = nextcloud_file.id;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("/api/v1/nextcloud-files/{nextcloud_file_id}"))
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
        let body: NextcloudFile = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.original_file_name, "test.html");

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        nextcloud_files_cleanup(app.context.clone(), &mut transaction, nextcloud_file_id).await;

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

        let nextcloud_file = nextcloud_files_create(router.clone(), session_id).await;
        let nextcloud_file_id = nextcloud_file.id;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("/api/v1/nextcloud-files/{nextcloud_file_id}"))
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

        nextcloud_files_cleanup(app.context.clone(), &mut transaction, nextcloud_file_id).await;

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

        let nextcloud_file_id = "33847746-0030-4964-a496-f75d04499160";

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("/api/v1/nextcloud-files/{nextcloud_file_id}"))
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

        let nextcloud_file = nextcloud_files_create(router.clone(), session_id).await;
        let nextcloud_file_id = nextcloud_file.id;

        let body =
            multipart::tests::file_data("text/html", "test.html", "data/test/test.html", true)
                .unwrap();

        let value = format!(
            "{}; boundary={}",
            mime::MULTIPART_FORM_DATA,
            multipart::tests::BOUNDARY
        );

        let request = Request::builder()
            .method(http::Method::PUT)
            .uri(format!("/api/v1/nextcloud-files/{nextcloud_file_id}"))
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
        let body: NextcloudFile = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.original_file_name, "test.html");

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        nextcloud_files_cleanup(app.context.clone(), &mut transaction, nextcloud_file_id).await;

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
    async fn update_400() {
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

        let nextcloud_file = nextcloud_files_create(router.clone(), session_id).await;
        let nextcloud_file_id = nextcloud_file.id;

        let request = Request::builder()
            .method(http::Method::PUT)
            .uri(format!("/api/v1/nextcloud-files/{nextcloud_file_id}"))
            .header(
                http::header::CONTENT_TYPE,
                mime::MULTIPART_FORM_DATA.as_ref(),
            )
            .header("X-Auth-Token".to_string(), session_id.to_string())
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        nextcloud_files_cleanup(app.context.clone(), &mut transaction, nextcloud_file_id).await;

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

        let nextcloud_file = nextcloud_files_create(router.clone(), session_id).await;
        let nextcloud_file_id = nextcloud_file.id;

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
            multipart::tests::file_data("text/html", "test.html", "data/test/test.html", true)
                .unwrap();

        let value = format!(
            "{}; boundary={}",
            mime::MULTIPART_FORM_DATA,
            multipart::tests::BOUNDARY
        );

        let request = Request::builder()
            .method(http::Method::PUT)
            .uri(format!("/api/v1/nextcloud-files/{nextcloud_file_id}"))
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

        nextcloud_files_cleanup(app.context.clone(), &mut transaction, nextcloud_file_id).await;

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

        let nextcloud_file_id = "33847746-0030-4964-a496-f75d04499160";

        let body =
            multipart::tests::file_data("text/html", "test.html", "data/test/test.html", true)
                .unwrap();

        let value = format!(
            "{}; boundary={}",
            mime::MULTIPART_FORM_DATA,
            multipart::tests::BOUNDARY
        );

        let request = Request::builder()
            .method(http::Method::PUT)
            .uri(format!("/api/v1/nextcloud-files/{nextcloud_file_id}"))
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
}
