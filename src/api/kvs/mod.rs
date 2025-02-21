use crate::{
    context::Context,
    entity::{KV, KVAccessType, ROLE_COMPANY_ADMIN_USER},
    error::{AppError, ResponseError},
    session::{ExtractedSession, require_authenticated},
};
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use chrono::{DateTime, Utc};
use regex::Regex;
use serde::Deserialize;
use std::sync::{Arc, LazyLock};
use utoipa::ToSchema;
use validator::Validate;

static VALID_KEY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-zA-Z0-9._~!$&'()*+,;=:@/?-]+$").unwrap());

#[derive(Debug, Deserialize, ToSchema, Validate)]
pub struct KVPost {
    #[validate(regex(path = *VALID_KEY))]
    pub kv_key: String,
    pub kv_value: String,
    pub access_type: Option<KVAccessType>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize, ToSchema, Validate)]
pub struct KVPut {
    #[validate(regex(path = *VALID_KEY))]
    pub kv_key: String,
    pub kv_value: String,
    pub access_type: Option<KVAccessType>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[axum_macros::debug_handler]
#[utoipa::path(
    post,
    path = "/api/v1/kvs",
    request_body = KVPost,
    responses(
        (status = 201, description = "KV created.", body = KV),
        (status = 401, description = "Unauthorized request.", body = ResponseError),
        (status = 403, description = "Forbidden.", body = ResponseError),
        (status = 409, description = "Conflicting request.", body = ResponseError),
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn create(
    State(context): State<Arc<Context>>,
    extracted_session: ExtractedSession,
    Json(input): Json<KVPost>,
) -> Result<impl IntoResponse, AppError> {
    let session = require_authenticated(extracted_session).await?;

    let session_user = context
        .octopus_database
        .try_get_user_by_id(session.user_id)
        .await?
        .ok_or(AppError::Forbidden)?;

    input.validate()?;

    let access_type = input.access_type.unwrap_or(KVAccessType::Owner);

    let kv_exists = context
        .octopus_database
        .try_get_kv_by_kv_key(&input.kv_key)
        .await?;

    match kv_exists {
        None => {
            let mut transaction = context.octopus_database.transaction_begin().await?;

            let kv = context
                .octopus_database
                .insert_kv(
                    &mut transaction,
                    session_user.company_id,
                    session_user.id,
                    access_type,
                    &input.kv_key,
                    &input.kv_value,
                    input.expires_at,
                )
                .await?;

            context
                .octopus_database
                .transaction_commit(transaction)
                .await?;

            Ok((StatusCode::CREATED, Json(kv)).into_response())
        }
        Some(_kv_exists) => Err(AppError::Conflict),
    }
}

#[axum_macros::debug_handler]
#[utoipa::path(
    delete,
    path = "/api/v1/kvs/:kv_key",
    responses(
        (status = 204, description = "KV deleted."),
        (status = 401, description = "Unauthorized request.", body = ResponseError),
        (status = 403, description = "Forbidden.", body = ResponseError),
        (status = 404, description = "KV not found.", body = ResponseError),
    ),
    params(
        ("kv_key" = String, Path, description = "KV id")
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn delete(
    State(context): State<Arc<Context>>,
    extracted_session: ExtractedSession,
    Path(kv_key): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let session = require_authenticated(extracted_session).await?;

    let session_user = context
        .octopus_database
        .try_get_user_by_id(session.user_id)
        .await?
        .ok_or(AppError::Forbidden)?;

    let kv = context
        .octopus_database
        .try_get_kv_by_kv_key(&kv_key)
        .await?
        .ok_or(AppError::NotFound)?;

    if session_user.id != kv.user_id {
        return Err(AppError::Forbidden);
    }

    let mut transaction = context.octopus_database.transaction_begin().await?;

    context
        .octopus_database
        .try_delete_kv_by_id(&mut transaction, kv.id)
        .await?
        .ok_or(AppError::NotFound)?;

    context
        .octopus_database
        .transaction_commit(transaction)
        .await?;

    Ok((StatusCode::NO_CONTENT, ()).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    get,
    path = "/api/v1/kvs",
    responses(
        (status = 200, description = "List of KVs.", body = [KV]),
        (status = 401, description = "Unauthorized request.", body = ResponseError),
        (status = 403, description = "Forbidden.", body = ResponseError),
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

    let mut result = vec![];
    let mut kvs = context
        .octopus_database
        .get_kvs_by_user_id(session_user.id)
        .await?;
    result.append(&mut kvs);

    let mut kvs = context
        .octopus_database
        .get_kvs_by_company_id_and_access_type(session_user.company_id, KVAccessType::Company)
        .await?;
    result.append(&mut kvs);

    Ok((StatusCode::OK, Json(result)).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    get,
    path = "/api/v1/kvs/:kv_key",
    responses(
        (status = 200, description = "KV read.", body = KV),
        (status = 401, description = "Unauthorized request.", body = ResponseError),
        (status = 403, description = "Forbidden.", body = ResponseError),
        (status = 404, description = "KV not found.", body = ResponseError),
    ),
    params(
        ("kv_key" = String, Path, description = "KV id")
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn read(
    State(context): State<Arc<Context>>,
    extracted_session: ExtractedSession,
    Path(kv_key): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let session = require_authenticated(extracted_session).await?;

    let session_user = context
        .octopus_database
        .try_get_user_by_id(session.user_id)
        .await?
        .ok_or(AppError::Forbidden)?;

    let kv = context
        .octopus_database
        .try_get_kv_by_kv_key(&kv_key)
        .await?
        .ok_or(AppError::NotFound)?;

    match kv.access_type {
        KVAccessType::Company => {
            if session_user.company_id != kv.company_id {
                return Err(AppError::Forbidden);
            }
        }
        KVAccessType::Owner => {
            if session_user.id != kv.user_id
                || (session_user
                    .roles
                    .contains(&ROLE_COMPANY_ADMIN_USER.to_string())
                    && session_user.company_id != kv.company_id)
            {
                return Err(AppError::Forbidden);
            }
        }
    }

    Ok((StatusCode::OK, Json(kv)).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    put,
    path = "/api/v1/kvs/:kv_key",
    request_body = KVPut,
    responses(
        (status = 200, description = "KV updated.", body = KV),
        (status = 401, description = "Unauthorized request.", body = ResponseError),
        (status = 403, description = "Forbidden.", body = ResponseError),
        (status = 404, description = "KV not found.", body = ResponseError),
        (status = 409, description = "Conflicting request.", body = ResponseError),
    ),
    params(
        ("kv_key" = String, Path, description = "KV id")
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn update(
    State(context): State<Arc<Context>>,
    extracted_session: ExtractedSession,
    Path(kv_key): Path<String>,
    Json(input): Json<KVPut>,
) -> Result<impl IntoResponse, AppError> {
    let session = require_authenticated(extracted_session).await?;

    let session_user = context
        .octopus_database
        .try_get_user_by_id(session.user_id)
        .await?
        .ok_or(AppError::Forbidden)?;

    input.validate()?;

    let access_type = input.access_type.unwrap_or(KVAccessType::Owner);

    let kv = context
        .octopus_database
        .try_get_kv_by_kv_key(&kv_key)
        .await?
        .ok_or(AppError::NotFound)?;

    if session_user.id != kv.user_id {
        return Err(AppError::Forbidden);
    }

    if input.kv_key != kv_key {
        let kv_exists = context
            .octopus_database
            .try_get_kv_by_kv_key(&input.kv_key)
            .await?;

        if kv_exists.is_some() {
            return Err(AppError::Conflict);
        }
    }

    let mut transaction = context.octopus_database.transaction_begin().await?;

    let kv = context
        .octopus_database
        .update_kv(
            &mut transaction,
            kv.id,
            access_type,
            &input.kv_key,
            &input.kv_value,
            input.expires_at,
        )
        .await?;

    context
        .octopus_database
        .transaction_commit(transaction)
        .await?;

    Ok((StatusCode::OK, Json(kv)).into_response())
}

#[cfg(test)]
mod tests {
    use crate::{api, app, context::Context, entity::KV};
    use axum::{
        Router,
        body::Body,
        http::{self, Request, StatusCode},
    };
    use fake::{Fake, faker::lorem::en::Word};
    use http_body_util::BodyExt;
    use sqlx::{Postgres, Transaction};
    use std::sync::Arc;
    use tower::ServiceExt;
    use uuid::Uuid;

    pub fn get_kv_create_params() -> (String, String) {
        let kv_key = format!(
            "sample-key-{}-{}",
            Word().fake::<String>(),
            Word().fake::<String>()
        );
        let kv_value = format!(
            "sample value {}{}",
            Word().fake::<String>(),
            Word().fake::<String>()
        );

        (kv_key, kv_value)
    }

    pub async fn kv_cleanup(
        context: Arc<Context>,
        transaction: &mut Transaction<'_, Postgres>,
        kv_id: Uuid,
    ) {
        let _ = context
            .octopus_database
            .try_delete_kv_by_id(transaction, kv_id)
            .await;
    }

    pub async fn kv_create(
        router: Router,
        session_id: Uuid,
        access_type: &str,
        kv_key: &str,
        kv_value: &str,
    ) -> KV {
        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/kvs")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "kv_key": &kv_key,
                            "kv_value": &kv_value,
                            "access_type": &access_type,
                        })
                        .to_string(),
                    ))
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
        let body: KV = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.kv_key, kv_key);
        assert_eq!(body.kv_value, kv_value);

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

        let (kv_key, kv_value) = get_kv_create_params();
        let kv = kv_create(router, session_id, "Owner", &kv_key, &kv_value).await;
        let kv_id = kv.id;

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        kv_cleanup(app.context.clone(), &mut transaction, kv_id).await;

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

        let (kv_key, kv_value) = get_kv_create_params();
        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/kvs")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "kv_key": &kv_key,
                            "kv_value": &kv_value,
                        })
                        .to_string(),
                    ))
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

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(app.context.clone(), &mut transaction, &[], &[user_id])
            .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;

        let (kv_key, kv_value) = get_kv_create_params();
        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/kvs")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "kv_key": &kv_key,
                            "kv_value": &kv_value,
                        })
                        .to_string(),
                    ))
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

        api::setup::tests::setup_cleanup(app.context.clone(), &mut transaction, &[company_id], &[])
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

        let (kv_key, kv_value) = get_kv_create_params();
        let kv = kv_create(router.clone(), session_id, "Owner", &kv_key, &kv_value).await;
        let kv_id = kv.id;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/kvs")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "kv_key": &kv_key,
                            "kv_value": &kv_value,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CONFLICT);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        kv_cleanup(app.context.clone(), &mut transaction, kv_id).await;

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

        let (kv_key, kv_value) = get_kv_create_params();
        kv_create(router.clone(), session_id, "Owner", &kv_key, &kv_value).await;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::DELETE)
                    .uri(format!("/api/v1/kvs/{kv_key}"))
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

        let (kv_key, kv_value) = get_kv_create_params();
        let kv = kv_create(router.clone(), session_id, "Owner", &kv_key, &kv_value).await;
        let kv_id = kv.id;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::DELETE)
                    .uri(format!("/api/v1/kvs/{kv_key}"))
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

        kv_cleanup(app.context.clone(), &mut transaction, kv_id).await;

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

        let (kv_key, kv_value) = get_kv_create_params();
        let kv = kv_create(router.clone(), session_id, "Owner", &kv_key, &kv_value).await;
        let kv_id = kv.id;

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
                    .uri(format!("/api/v1/kvs/{kv_key}"))
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

        kv_cleanup(app.context.clone(), &mut transaction, kv_id).await;

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

        let (kv_key, kv_value) = get_kv_create_params();
        let kv = kv_create(router.clone(), session_id, "Owner", &kv_key, &kv_value).await;
        let kv_id = kv.id;

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
                    .uri(format!("/api/v1/kvs/{kv_key}"))
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

        kv_cleanup(app.context.clone(), &mut transaction, kv_id).await;

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

        let kv_key = "33847746-0030-4964-a496-f75d04499160";

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::DELETE)
                    .uri(format!("/api/v1/kvs/{kv_key}"))
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

        let (kv_key, kv_value) = get_kv_create_params();
        let kv = kv_create(router.clone(), session_id, "Owner", &kv_key, &kv_value).await;
        let kv_id = kv.id;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri("/api/v1/kvs")
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
        let body: Vec<KV> = serde_json::from_slice(&body).unwrap();

        assert!(!body.is_empty());

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        kv_cleanup(app.context.clone(), &mut transaction, kv_id).await;

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

        let (kv_key, kv_value) = get_kv_create_params();
        let kv = kv_create(router.clone(), session_id, "Owner", &kv_key, &kv_value).await;
        let kv_id = kv.id;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri("/api/v1/kvs")
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

        kv_cleanup(app.context.clone(), &mut transaction, kv_id).await;

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

        let (kv_key, kv_value) = get_kv_create_params();
        let kv = kv_create(router.clone(), session_id, "Owner", &kv_key, &kv_value).await;
        let kv_id = kv.id;

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
                    .uri("/api/v1/kvs")
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

        kv_cleanup(app.context.clone(), &mut transaction, kv_id).await;

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

        let (kv_key, kv_value) = get_kv_create_params();
        let kv = kv_create(router.clone(), session_id, "Owner", &kv_key, &kv_value).await;
        let kv_id = kv.id;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("/api/v1/kvs/{kv_key}"))
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
        let body: KV = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.kv_key, kv_key);
        assert_eq!(body.kv_value, kv_value);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        kv_cleanup(app.context.clone(), &mut transaction, kv_id).await;

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
    async fn read_200_public() {
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

        let (kv_key, kv_value) = get_kv_create_params();
        let kv = kv_create(router.clone(), session_id, "Company", &kv_key, &kv_value).await;
        let kv_id = kv.id;

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
                    .uri(format!("/api/v1/kvs/{kv_key}"))
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
        let body: KV = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.kv_key, kv_key);
        assert_eq!(body.kv_value, kv_value);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        kv_cleanup(app.context.clone(), &mut transaction, kv_id).await;

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

        let (kv_key, kv_value) = get_kv_create_params();
        let kv = kv_create(router.clone(), session_id, "Owner", &kv_key, &kv_value).await;
        let kv_id = kv.id;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("/api/v1/kvs/{kv_key}"))
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

        kv_cleanup(app.context.clone(), &mut transaction, kv_id).await;

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

        let (kv_key, kv_value) = get_kv_create_params();
        let kv = kv_create(router.clone(), session_id, "Owner", &kv_key, &kv_value).await;
        let kv_id = kv.id;

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
                    .uri(format!("/api/v1/kvs/{kv_key}"))
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

        kv_cleanup(app.context.clone(), &mut transaction, kv_id).await;

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

        let (kv_key, kv_value) = get_kv_create_params();
        let kv = kv_create(router.clone(), session_id, "Owner", &kv_key, &kv_value).await;
        let kv_id = kv.id;

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
                    .uri(format!("/api/v1/kvs/{kv_key}"))
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

        kv_cleanup(app.context.clone(), &mut transaction, kv_id).await;

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

        let kv_key = "33847746-0030-4964-a496-f75d04499160";

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("/api/v1/kvs/{kv_key}"))
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

        let (kv_key, kv_value) = get_kv_create_params();
        let kv = kv_create(router.clone(), session_id, "Owner", &kv_key, &kv_value).await;
        let kv_id = kv.id;

        let (second_kv_key, second_kv_value) = get_kv_create_params();
        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::PUT)
                    .uri(format!("/api/v1/kvs/{kv_key}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "kv_key": &second_kv_key,
                            "kv_value": &second_kv_value,
                        })
                        .to_string(),
                    ))
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
        let body: KV = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.kv_key, second_kv_key);
        assert_eq!(body.kv_value, second_kv_value);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        kv_cleanup(app.context.clone(), &mut transaction, kv_id).await;

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

        let (kv_key, kv_value) = get_kv_create_params();
        let kv = kv_create(router.clone(), session_id, "Owner", &kv_key, &kv_value).await;
        let kv_id = kv.id;

        let (second_kv_key, second_kv_value) = get_kv_create_params();
        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::PUT)
                    .uri(format!("/api/v1/kvs/{kv_key}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "kv_key": &second_kv_key,
                            "kv_value": &second_kv_value,
                        })
                        .to_string(),
                    ))
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

        kv_cleanup(app.context.clone(), &mut transaction, kv_id).await;

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

        let (kv_key, kv_value) = get_kv_create_params();
        let kv = kv_create(router.clone(), session_id, "Owner", &kv_key, &kv_value).await;
        let kv_id = kv.id;

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

        let (second_kv_key, second_kv_value) = get_kv_create_params();
        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::PUT)
                    .uri(format!("/api/v1/kvs/{kv_key}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "kv_key": &second_kv_key,
                            "kv_value": &second_kv_value,
                        })
                        .to_string(),
                    ))
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

        kv_cleanup(app.context.clone(), &mut transaction, kv_id).await;

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

        let (kv_key, kv_value) = get_kv_create_params();
        let kv = kv_create(router.clone(), session_id, "Owner", &kv_key, &kv_value).await;
        let kv_id = kv.id;

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(app.context.clone(), &mut transaction, &[], &[user_id])
            .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;

        let (second_kv_key, second_kv_value) = get_kv_create_params();
        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::PUT)
                    .uri(format!("/api/v1/kvs/{kv_key}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "kv_key": &second_kv_key,
                            "kv_value": &second_kv_value,
                        })
                        .to_string(),
                    ))
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

        kv_cleanup(app.context.clone(), &mut transaction, kv_id).await;

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

        let kv_key = "33847746-0030-4964-a496-f75d04499160";

        let (second_kv_key, second_kv_value) = get_kv_create_params();
        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::PUT)
                    .uri(format!("/api/v1/kvs/{kv_key}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "kv_key": &second_kv_key,
                            "kv_value": &second_kv_value,
                        })
                        .to_string(),
                    ))
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
    async fn update_409() {
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

        let (kv_key, kv_value) = get_kv_create_params();
        let kv = kv_create(router.clone(), session_id, "Owner", &kv_key, &kv_value).await;
        let kv_id = kv.id;

        let (second_kv_key, second_kv_value) = get_kv_create_params();
        let kv = kv_create(
            router.clone(),
            session_id,
            "Owner",
            &second_kv_key,
            &second_kv_value,
        )
        .await;
        let second_kv_id = kv.id;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::PUT)
                    .uri(format!("/api/v1/kvs/{kv_key}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "kv_key": &second_kv_key,
                            "kv_value": &second_kv_value,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CONFLICT);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        kv_cleanup(app.context.clone(), &mut transaction, kv_id).await;
        kv_cleanup(app.context.clone(), &mut transaction, second_kv_id).await;

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
