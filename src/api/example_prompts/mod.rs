use crate::{
    context::Context,
    entity::{ExamplePrompt, ROLE_COMPANY_ADMIN_USER},
    error::{AppError, ResponseError},
    session::{ExtractedSession, require_authenticated},
};
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::Deserialize;
use std::sync::Arc;
use utoipa::ToSchema;
use uuid::Uuid;
use validator::Validate;

#[derive(Debug, Deserialize, ToSchema, Validate)]
pub struct ExamplePromptPost {
    pub example_prompt_category_id: Uuid,
    pub background_file_name: Option<String>,
    pub is_visible: bool,
    pub priority: i32,
    pub prompt: String,
    pub title: String,
}

#[derive(Debug, Deserialize, ToSchema, Validate)]
pub struct ExamplePromptPut {
    pub example_prompt_category_id: Uuid,
    pub background_file_name: Option<String>,
    pub is_visible: bool,
    pub priority: i32,
    pub prompt: String,
    pub title: String,
}

#[axum_macros::debug_handler]
#[utoipa::path(
    post,
    path = "/api/v1/example-prompts",
    request_body = ExamplePromptPost,
    responses(
        (status = 201, description = "Example prompt created.", body = ExamplePrompt),
        (status = 401, description = "Unauthorized request.", body = ResponseError),
        (status = 403, description = "Forbidden.", body = ResponseError),
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn create(
    State(context): State<Arc<Context>>,
    extracted_session: ExtractedSession,
    Json(input): Json<ExamplePromptPost>,
) -> Result<impl IntoResponse, AppError> {
    let session = require_authenticated(extracted_session).await?;

    let session_user = context
        .octopus_database
        .try_get_user_by_id(session.user_id)
        .await?
        .ok_or(AppError::Forbidden)?;

    if !session_user
        .roles
        .contains(&ROLE_COMPANY_ADMIN_USER.to_string())
    {
        return Err(AppError::Forbidden);
    }

    input.validate()?;

    let mut transaction = context.octopus_database.transaction_begin().await?;

    let example_prompt = context
        .octopus_database
        .insert_example_prompt(
            &mut transaction,
            input.example_prompt_category_id,
            input.background_file_name,
            input.is_visible,
            input.priority,
            &input.prompt,
            &input.title,
        )
        .await?;

    context
        .octopus_database
        .transaction_commit(transaction)
        .await?;

    Ok((StatusCode::CREATED, Json(example_prompt)).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    delete,
    path = "/api/v1/example-prompts/:id",
    responses(
        (status = 204, description = "Example prompt deleted."),
        (status = 401, description = "Unauthorized request.", body = ResponseError),
        (status = 403, description = "Forbidden.", body = ResponseError),
        (status = 404, description = "Example prompt not found.", body = ResponseError),
    ),
    params(
        ("id" = String, Path, description = "Example prompt id")
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
    let session = require_authenticated(extracted_session).await?;

    let session_user = context
        .octopus_database
        .try_get_user_by_id(session.user_id)
        .await?
        .ok_or(AppError::Forbidden)?;

    if !session_user
        .roles
        .contains(&ROLE_COMPANY_ADMIN_USER.to_string())
    {
        return Err(AppError::Forbidden);
    }

    let mut transaction = context.octopus_database.transaction_begin().await?;

    context
        .octopus_database
        .try_delete_example_prompt_by_id(&mut transaction, id)
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
    path = "/api/v1/example-prompts",
    responses(
        (status = 200, description = "List of Example prompts.", body = [ExamplePrompt]),
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

    context
        .octopus_database
        .try_get_user_by_id(session.user_id)
        .await?
        .ok_or(AppError::Forbidden)?;

    let example_prompts = context.octopus_database.get_example_prompts().await?;

    Ok((StatusCode::OK, Json(example_prompts)).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    get,
    path = "/api/v1/example-prompts/by-category/:example_prompt_category_id",
    responses(
        (status = 200, description = "List of Example prompts by example prompt category.", body = [ExamplePrompt]),
        (status = 401, description = "Unauthorized request.", body = ResponseError),
        (status = 403, description = "Forbidden.", body = ResponseError),
        (status = 404, description = "Example prompt category not found.", body = ResponseError),
    ),
    params(
        ("example_prompt_category_id" = String, Path, description = "Example prompt category id")
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn list_by_category(
    State(context): State<Arc<Context>>,
    extracted_session: ExtractedSession,
    Path(example_prompt_category_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let session = require_authenticated(extracted_session).await?;

    context
        .octopus_database
        .try_get_user_by_id(session.user_id)
        .await?
        .ok_or(AppError::Forbidden)?;

    let example_prompt_category = context
        .octopus_database
        .try_get_example_prompt_category_by_id(example_prompt_category_id)
        .await?
        .ok_or(AppError::NotFound)?;

    let example_prompts = context
        .octopus_database
        .get_example_prompts_by_example_prompt_category_id(example_prompt_category.id)
        .await?;

    Ok((StatusCode::OK, Json(example_prompts)).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    get,
    path = "/api/v1/example-prompts/:id",
    responses(
        (status = 200, description = "Example prompt read.", body = ExamplePrompt),
        (status = 401, description = "Unauthorized request.", body = ResponseError),
        (status = 403, description = "Forbidden.", body = ResponseError),
        (status = 404, description = "Example prompt not found.", body = ResponseError),
    ),
    params(
        ("id" = String, Path, description = "Example prompt id")
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
    let session = require_authenticated(extracted_session).await?;

    context
        .octopus_database
        .try_get_user_by_id(session.user_id)
        .await?
        .ok_or(AppError::Forbidden)?;

    let example_prompt = context
        .octopus_database
        .try_get_example_prompt_by_id(id)
        .await?
        .ok_or(AppError::NotFound)?;

    Ok((StatusCode::OK, Json(example_prompt)).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    put,
    path = "/api/v1/example-prompts/:id",
    request_body = ExamplePromptPut,
    responses(
        (status = 200, description = "Example prompt updated.", body = ExamplePrompt),
        (status = 401, description = "Unauthorized request.", body = ResponseError),
        (status = 403, description = "Forbidden.", body = ResponseError),
        (status = 404, description = "Example prompt not found.", body = ResponseError),
    ),
    params(
        ("id" = String, Path, description = "Example prompt id")
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn update(
    State(context): State<Arc<Context>>,
    extracted_session: ExtractedSession,
    Path(id): Path<Uuid>,
    Json(input): Json<ExamplePromptPut>,
) -> Result<impl IntoResponse, AppError> {
    let session = require_authenticated(extracted_session).await?;

    let session_user = context
        .octopus_database
        .try_get_user_by_id(session.user_id)
        .await?
        .ok_or(AppError::Forbidden)?;

    if !session_user
        .roles
        .contains(&ROLE_COMPANY_ADMIN_USER.to_string())
    {
        return Err(AppError::Forbidden);
    }

    input.validate()?;

    context
        .octopus_database
        .try_get_example_prompt_id_by_id(id)
        .await?
        .ok_or(AppError::NotFound)?;

    let mut transaction = context.octopus_database.transaction_begin().await?;

    let example_prompt = context
        .octopus_database
        .update_example_prompt(
            &mut transaction,
            id,
            input.example_prompt_category_id,
            input.background_file_name,
            input.is_visible,
            input.priority,
            &input.prompt,
            &input.title,
        )
        .await?;

    context
        .octopus_database
        .transaction_commit(transaction)
        .await?;

    Ok((StatusCode::OK, Json(example_prompt)).into_response())
}

#[cfg(test)]
mod tests {
    use crate::{api, app, context::Context, entity::ExamplePrompt};
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

    pub fn get_example_prompt_create_params() -> (bool, i32, String, String) {
        let is_visible = true;
        let priority = 0;
        let prompt = format!(
            "sample prompt {}{}",
            Word().fake::<String>(),
            Word().fake::<String>()
        );
        let title = format!(
            "sample title {}{}",
            Word().fake::<String>(),
            Word().fake::<String>()
        );

        (is_visible, priority, prompt, title)
    }

    pub async fn example_prompt_cleanup(
        context: Arc<Context>,
        transaction: &mut Transaction<'_, Postgres>,
        example_prompt_id: Uuid,
    ) {
        let _ = context
            .octopus_database
            .try_delete_example_prompt_by_id(transaction, example_prompt_id)
            .await;
    }

    pub async fn example_prompt_create(
        router: Router,
        session_id: Uuid,
        example_prompt_category_id: Uuid,
        is_visible: bool,
        priority: i32,
        prompt: &str,
        title: &str,
    ) -> ExamplePrompt {
        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/example-prompts")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "example_prompt_category_id": &example_prompt_category_id,
                            "is_visible": &is_visible,
                            "priority": &priority,
                            "prompt": &prompt,
                            "title": &title,
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
        let body: ExamplePrompt = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.example_prompt_category_id, example_prompt_category_id);
        assert_eq!(body.is_visible, is_visible);
        assert_eq!(body.priority, priority);
        assert_eq!(body.prompt, prompt);
        assert_eq!(body.title, title);

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

        let (description, is_visible, title) =
            api::example_prompt_categories::tests::get_example_prompt_category_create_params();
        let example_prompt_category =
            api::example_prompt_categories::tests::example_prompt_category_create(
                router.clone(),
                session_id,
                &description,
                is_visible,
                &title,
            )
            .await;
        let example_prompt_category_id = example_prompt_category.id;

        let (is_visible, priority, prompt, title) = get_example_prompt_create_params();
        let example_prompt = example_prompt_create(
            router,
            session_id,
            example_prompt_category_id,
            is_visible,
            priority,
            &prompt,
            &title,
        )
        .await;
        let example_prompt_id = example_prompt.id;

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        example_prompt_cleanup(app.context.clone(), &mut transaction, example_prompt_id).await;

        api::example_prompt_categories::tests::example_prompt_category_cleanup(
            app.context.clone(),
            &mut transaction,
            example_prompt_category_id,
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

        let (description, is_visible, title) =
            api::example_prompt_categories::tests::get_example_prompt_category_create_params();
        let example_prompt_category =
            api::example_prompt_categories::tests::example_prompt_category_create(
                router.clone(),
                session_id,
                &description,
                is_visible,
                &title,
            )
            .await;
        let example_prompt_category_id = example_prompt_category.id;

        let (is_visible, priority, prompt, title) = get_example_prompt_create_params();
        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/example-prompts")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "example_prompt_category_id": &example_prompt_category_id,
                            "is_visible": &is_visible,
                            "priority": &priority,
                            "prompt": &prompt,
                            "title": &title,
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

        api::example_prompt_categories::tests::example_prompt_category_cleanup(
            app.context.clone(),
            &mut transaction,
            example_prompt_category_id,
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

        let (description, is_visible, title) =
            api::example_prompt_categories::tests::get_example_prompt_category_create_params();
        let example_prompt_category =
            api::example_prompt_categories::tests::example_prompt_category_create(
                router.clone(),
                session_id,
                &description,
                is_visible,
                &title,
            )
            .await;
        let example_prompt_category_id = example_prompt_category.id;

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

        let (is_visible, priority, prompt, title) = get_example_prompt_create_params();
        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/example-prompts")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "example_prompt_category_id": &example_prompt_category_id,
                            "is_visible": &is_visible,
                            "priority": &priority,
                            "prompt": &prompt,
                            "title": &title,
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

        api::example_prompt_categories::tests::example_prompt_category_cleanup(
            app.context.clone(),
            &mut transaction,
            example_prompt_category_id,
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

        let (description, is_visible, title) =
            api::example_prompt_categories::tests::get_example_prompt_category_create_params();
        let example_prompt_category =
            api::example_prompt_categories::tests::example_prompt_category_create(
                router.clone(),
                session_id,
                &description,
                is_visible,
                &title,
            )
            .await;
        let example_prompt_category_id = example_prompt_category.id;

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(app.context.clone(), &mut transaction, &[], &[user_id])
            .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;

        let (is_visible, priority, prompt, title) = get_example_prompt_create_params();
        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/example-prompts")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "example_prompt_category_id": &example_prompt_category_id,
                            "is_visible": &is_visible,
                            "priority": &priority,
                            "prompt": &prompt,
                            "title": &title,
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

        api::example_prompt_categories::tests::example_prompt_category_cleanup(
            app.context.clone(),
            &mut transaction,
            example_prompt_category_id,
        )
        .await;

        api::setup::tests::setup_cleanup(app.context.clone(), &mut transaction, &[company_id], &[])
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

        let (description, is_visible, title) =
            api::example_prompt_categories::tests::get_example_prompt_category_create_params();
        let example_prompt_category =
            api::example_prompt_categories::tests::example_prompt_category_create(
                router.clone(),
                session_id,
                &description,
                is_visible,
                &title,
            )
            .await;
        let example_prompt_category_id = example_prompt_category.id;

        let (is_visible, priority, prompt, title) = get_example_prompt_create_params();
        let example_prompt = example_prompt_create(
            router.clone(),
            session_id,
            example_prompt_category_id,
            is_visible,
            priority,
            &prompt,
            &title,
        )
        .await;
        let example_prompt_id = example_prompt.id;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::DELETE)
                    .uri(format!("/api/v1/example-prompts/{example_prompt_id}"))
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

        api::example_prompt_categories::tests::example_prompt_category_cleanup(
            app.context.clone(),
            &mut transaction,
            example_prompt_category_id,
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

        let (description, is_visible, title) =
            api::example_prompt_categories::tests::get_example_prompt_category_create_params();
        let example_prompt_category =
            api::example_prompt_categories::tests::example_prompt_category_create(
                router.clone(),
                session_id,
                &description,
                is_visible,
                &title,
            )
            .await;
        let example_prompt_category_id = example_prompt_category.id;

        let (is_visible, priority, prompt, title) = get_example_prompt_create_params();
        let example_prompt = example_prompt_create(
            router.clone(),
            session_id,
            example_prompt_category_id,
            is_visible,
            priority,
            &prompt,
            &title,
        )
        .await;
        let example_prompt_id = example_prompt.id;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::DELETE)
                    .uri(format!("/api/v1/example-prompts/{example_prompt_id}"))
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

        example_prompt_cleanup(app.context.clone(), &mut transaction, example_prompt_id).await;

        api::example_prompt_categories::tests::example_prompt_category_cleanup(
            app.context.clone(),
            &mut transaction,
            example_prompt_category_id,
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

        let (description, is_visible, title) =
            api::example_prompt_categories::tests::get_example_prompt_category_create_params();
        let example_prompt_category =
            api::example_prompt_categories::tests::example_prompt_category_create(
                router.clone(),
                session_id,
                &description,
                is_visible,
                &title,
            )
            .await;
        let example_prompt_category_id = example_prompt_category.id;

        let (is_visible, priority, prompt, title) = get_example_prompt_create_params();
        let example_prompt = example_prompt_create(
            router.clone(),
            session_id,
            example_prompt_category_id,
            is_visible,
            priority,
            &prompt,
            &title,
        )
        .await;
        let example_prompt_id = example_prompt.id;

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
                    .uri(format!("/api/v1/example-prompts/{example_prompt_id}"))
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

        example_prompt_cleanup(app.context.clone(), &mut transaction, example_prompt_id).await;

        api::example_prompt_categories::tests::example_prompt_category_cleanup(
            app.context.clone(),
            &mut transaction,
            example_prompt_category_id,
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

        let (description, is_visible, title) =
            api::example_prompt_categories::tests::get_example_prompt_category_create_params();
        let example_prompt_category =
            api::example_prompt_categories::tests::example_prompt_category_create(
                router.clone(),
                session_id,
                &description,
                is_visible,
                &title,
            )
            .await;
        let example_prompt_category_id = example_prompt_category.id;

        let (is_visible, priority, prompt, title) = get_example_prompt_create_params();
        let example_prompt = example_prompt_create(
            router.clone(),
            session_id,
            example_prompt_category_id,
            is_visible,
            priority,
            &prompt,
            &title,
        )
        .await;
        let example_prompt_id = example_prompt.id;

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
                    .uri(format!("/api/v1/example-prompts/{example_prompt_id}"))
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

        api::example_prompt_categories::tests::example_prompt_category_cleanup(
            app.context.clone(),
            &mut transaction,
            example_prompt_category_id,
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

        let example_prompt_id = "33847746-0030-4964-a496-f75d04499160";

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::DELETE)
                    .uri(format!("/api/v1/example-prompts/{example_prompt_id}"))
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

        let (description, is_visible, title) =
            api::example_prompt_categories::tests::get_example_prompt_category_create_params();
        let example_prompt_category =
            api::example_prompt_categories::tests::example_prompt_category_create(
                router.clone(),
                session_id,
                &description,
                is_visible,
                &title,
            )
            .await;
        let example_prompt_category_id = example_prompt_category.id;

        let (is_visible, priority, prompt, title) = get_example_prompt_create_params();
        let example_prompt = example_prompt_create(
            router.clone(),
            session_id,
            example_prompt_category_id,
            is_visible,
            priority,
            &prompt,
            &title,
        )
        .await;
        let example_prompt_id = example_prompt.id;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri("/api/v1/example-prompts")
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
        let body: Vec<ExamplePrompt> = serde_json::from_slice(&body).unwrap();

        assert!(!body.is_empty());

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        example_prompt_cleanup(app.context.clone(), &mut transaction, example_prompt_id).await;

        api::example_prompt_categories::tests::example_prompt_category_cleanup(
            app.context.clone(),
            &mut transaction,
            example_prompt_category_id,
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

        let (description, is_visible, title) =
            api::example_prompt_categories::tests::get_example_prompt_category_create_params();
        let example_prompt_category =
            api::example_prompt_categories::tests::example_prompt_category_create(
                router.clone(),
                session_id,
                &description,
                is_visible,
                &title,
            )
            .await;
        let example_prompt_category_id = example_prompt_category.id;

        let (is_visible, priority, prompt, title) = get_example_prompt_create_params();
        let example_prompt = example_prompt_create(
            router.clone(),
            session_id,
            example_prompt_category_id,
            is_visible,
            priority,
            &prompt,
            &title,
        )
        .await;
        let example_prompt_id = example_prompt.id;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri("/api/v1/example-prompts")
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

        example_prompt_cleanup(app.context.clone(), &mut transaction, example_prompt_id).await;

        api::example_prompt_categories::tests::example_prompt_category_cleanup(
            app.context.clone(),
            &mut transaction,
            example_prompt_category_id,
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

        let (description, is_visible, title) =
            api::example_prompt_categories::tests::get_example_prompt_category_create_params();
        let example_prompt_category =
            api::example_prompt_categories::tests::example_prompt_category_create(
                router.clone(),
                session_id,
                &description,
                is_visible,
                &title,
            )
            .await;
        let example_prompt_category_id = example_prompt_category.id;

        let (is_visible, priority, prompt, title) = get_example_prompt_create_params();
        let example_prompt = example_prompt_create(
            router.clone(),
            session_id,
            example_prompt_category_id,
            is_visible,
            priority,
            &prompt,
            &title,
        )
        .await;
        let example_prompt_id = example_prompt.id;

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
                    .uri("/api/v1/example-prompts")
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

        example_prompt_cleanup(app.context.clone(), &mut transaction, example_prompt_id).await;

        api::example_prompt_categories::tests::example_prompt_category_cleanup(
            app.context.clone(),
            &mut transaction,
            example_prompt_category_id,
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
    async fn list_by_category_200() {
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

        let (description, is_visible, title) =
            api::example_prompt_categories::tests::get_example_prompt_category_create_params();
        let example_prompt_category =
            api::example_prompt_categories::tests::example_prompt_category_create(
                router.clone(),
                session_id,
                &description,
                is_visible,
                &title,
            )
            .await;
        let example_prompt_category_id = example_prompt_category.id;

        let (is_visible, priority, prompt, title) = get_example_prompt_create_params();
        let example_prompt = example_prompt_create(
            router.clone(),
            session_id,
            example_prompt_category_id,
            is_visible,
            priority,
            &prompt,
            &title,
        )
        .await;
        let example_prompt_id = example_prompt.id;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!(
                        "/api/v1/example-prompts/by-category/{example_prompt_category_id}"
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
        let body: Vec<ExamplePrompt> = serde_json::from_slice(&body).unwrap();

        assert!(!body.is_empty());

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        example_prompt_cleanup(app.context.clone(), &mut transaction, example_prompt_id).await;

        api::example_prompt_categories::tests::example_prompt_category_cleanup(
            app.context.clone(),
            &mut transaction,
            example_prompt_category_id,
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
    async fn list_by_category_401() {
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

        let (description, is_visible, title) =
            api::example_prompt_categories::tests::get_example_prompt_category_create_params();
        let example_prompt_category =
            api::example_prompt_categories::tests::example_prompt_category_create(
                router.clone(),
                session_id,
                &description,
                is_visible,
                &title,
            )
            .await;
        let example_prompt_category_id = example_prompt_category.id;

        let (is_visible, priority, prompt, title) = get_example_prompt_create_params();
        let example_prompt = example_prompt_create(
            router.clone(),
            session_id,
            example_prompt_category_id,
            is_visible,
            priority,
            &prompt,
            &title,
        )
        .await;
        let example_prompt_id = example_prompt.id;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!(
                        "/api/v1/example-prompts/by-category/{example_prompt_category_id}"
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

        example_prompt_cleanup(app.context.clone(), &mut transaction, example_prompt_id).await;

        api::example_prompt_categories::tests::example_prompt_category_cleanup(
            app.context.clone(),
            &mut transaction,
            example_prompt_category_id,
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
    async fn list_by_category_403_deleted_user() {
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

        let (description, is_visible, title) =
            api::example_prompt_categories::tests::get_example_prompt_category_create_params();
        let example_prompt_category =
            api::example_prompt_categories::tests::example_prompt_category_create(
                router.clone(),
                session_id,
                &description,
                is_visible,
                &title,
            )
            .await;
        let example_prompt_category_id = example_prompt_category.id;

        let (is_visible, priority, prompt, title) = get_example_prompt_create_params();
        let example_prompt = example_prompt_create(
            router.clone(),
            session_id,
            example_prompt_category_id,
            is_visible,
            priority,
            &prompt,
            &title,
        )
        .await;
        let example_prompt_id = example_prompt.id;

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
                        "/api/v1/example-prompts/by-category/{example_prompt_category_id}"
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

        example_prompt_cleanup(app.context.clone(), &mut transaction, example_prompt_id).await;

        api::example_prompt_categories::tests::example_prompt_category_cleanup(
            app.context.clone(),
            &mut transaction,
            example_prompt_category_id,
        )
        .await;

        api::setup::tests::setup_cleanup(app.context.clone(), &mut transaction, &[company_id], &[])
            .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn list_by_category_404() {
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

        let example_prompt_category_id = "33847746-0030-4964-a496-f75d04499160";

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!(
                        "/api/v1/example-prompts/by-category/{example_prompt_category_id}"
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

        let (description, is_visible, title) =
            api::example_prompt_categories::tests::get_example_prompt_category_create_params();
        let example_prompt_category =
            api::example_prompt_categories::tests::example_prompt_category_create(
                router.clone(),
                session_id,
                &description,
                is_visible,
                &title,
            )
            .await;
        let example_prompt_category_id = example_prompt_category.id;

        let (is_visible, priority, prompt, title) = get_example_prompt_create_params();
        let example_prompt = example_prompt_create(
            router.clone(),
            session_id,
            example_prompt_category_id,
            is_visible,
            priority,
            &prompt,
            &title,
        )
        .await;
        let example_prompt_id = example_prompt.id;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("/api/v1/example-prompts/{example_prompt_id}"))
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
        let body: ExamplePrompt = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.is_visible, is_visible);
        assert_eq!(body.priority, priority);
        assert_eq!(body.prompt, prompt);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        example_prompt_cleanup(app.context.clone(), &mut transaction, example_prompt_id).await;

        api::example_prompt_categories::tests::example_prompt_category_cleanup(
            app.context.clone(),
            &mut transaction,
            example_prompt_category_id,
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

        let (description, is_visible, title) =
            api::example_prompt_categories::tests::get_example_prompt_category_create_params();
        let example_prompt_category =
            api::example_prompt_categories::tests::example_prompt_category_create(
                router.clone(),
                session_id,
                &description,
                is_visible,
                &title,
            )
            .await;
        let example_prompt_category_id = example_prompt_category.id;

        let (is_visible, priority, prompt, title) = get_example_prompt_create_params();
        let example_prompt = example_prompt_create(
            router.clone(),
            session_id,
            example_prompt_category_id,
            is_visible,
            priority,
            &prompt,
            &title,
        )
        .await;
        let example_prompt_id = example_prompt.id;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("/api/v1/example-prompts/{example_prompt_id}"))
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

        example_prompt_cleanup(app.context.clone(), &mut transaction, example_prompt_id).await;

        api::example_prompt_categories::tests::example_prompt_category_cleanup(
            app.context.clone(),
            &mut transaction,
            example_prompt_category_id,
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

        let (description, is_visible, title) =
            api::example_prompt_categories::tests::get_example_prompt_category_create_params();
        let example_prompt_category =
            api::example_prompt_categories::tests::example_prompt_category_create(
                router.clone(),
                session_id,
                &description,
                is_visible,
                &title,
            )
            .await;
        let example_prompt_category_id = example_prompt_category.id;

        let (is_visible, priority, prompt, title) = get_example_prompt_create_params();
        let example_prompt = example_prompt_create(
            router.clone(),
            session_id,
            example_prompt_category_id,
            is_visible,
            priority,
            &prompt,
            &title,
        )
        .await;
        let example_prompt_id = example_prompt.id;

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
                    .uri(format!("/api/v1/example-prompts/{example_prompt_id}"))
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

        example_prompt_cleanup(app.context.clone(), &mut transaction, example_prompt_id).await;

        api::example_prompt_categories::tests::example_prompt_category_cleanup(
            app.context.clone(),
            &mut transaction,
            example_prompt_category_id,
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

        let example_prompt_id = "33847746-0030-4964-a496-f75d04499160";

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("/api/v1/example-prompts/{example_prompt_id}"))
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

        let (description, is_visible, title) =
            api::example_prompt_categories::tests::get_example_prompt_category_create_params();
        let example_prompt_category =
            api::example_prompt_categories::tests::example_prompt_category_create(
                router.clone(),
                session_id,
                &description,
                is_visible,
                &title,
            )
            .await;
        let example_prompt_category_id = example_prompt_category.id;

        let (is_visible, priority, prompt, title) = get_example_prompt_create_params();
        let example_prompt = example_prompt_create(
            router.clone(),
            session_id,
            example_prompt_category_id,
            is_visible,
            priority,
            &prompt,
            &title,
        )
        .await;
        let example_prompt_id = example_prompt.id;

        let (is_visible, priority, prompt, title) = get_example_prompt_create_params();
        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::PUT)
                    .uri(format!("/api/v1/example-prompts/{example_prompt_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "example_prompt_category_id": &example_prompt_category_id,
                            "is_visible": &is_visible,
                            "priority": &priority,
                            "prompt": &prompt,
                            "title": &title,
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
        let body: ExamplePrompt = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.is_visible, is_visible);
        assert_eq!(body.priority, priority);
        assert_eq!(body.prompt, prompt);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        example_prompt_cleanup(app.context.clone(), &mut transaction, example_prompt_id).await;

        api::example_prompt_categories::tests::example_prompt_category_cleanup(
            app.context.clone(),
            &mut transaction,
            example_prompt_category_id,
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

        let (description, is_visible, title) =
            api::example_prompt_categories::tests::get_example_prompt_category_create_params();
        let example_prompt_category =
            api::example_prompt_categories::tests::example_prompt_category_create(
                router.clone(),
                session_id,
                &description,
                is_visible,
                &title,
            )
            .await;
        let example_prompt_category_id = example_prompt_category.id;

        let (is_visible, priority, prompt, title) = get_example_prompt_create_params();
        let example_prompt = example_prompt_create(
            router.clone(),
            session_id,
            example_prompt_category_id,
            is_visible,
            priority,
            &prompt,
            &title,
        )
        .await;
        let example_prompt_id = example_prompt.id;

        let (is_visible, priority, prompt, title) = get_example_prompt_create_params();
        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::PUT)
                    .uri(format!("/api/v1/example-prompts/{example_prompt_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "example_prompt_category_id": &example_prompt_category_id,
                            "is_visible": &is_visible,
                            "priority": &priority,
                            "prompt": &prompt,
                            "title": &title,
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

        example_prompt_cleanup(app.context.clone(), &mut transaction, example_prompt_id).await;

        api::example_prompt_categories::tests::example_prompt_category_cleanup(
            app.context.clone(),
            &mut transaction,
            example_prompt_category_id,
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

        let (description, is_visible, title) =
            api::example_prompt_categories::tests::get_example_prompt_category_create_params();
        let example_prompt_category =
            api::example_prompt_categories::tests::example_prompt_category_create(
                router.clone(),
                session_id,
                &description,
                is_visible,
                &title,
            )
            .await;
        let example_prompt_category_id = example_prompt_category.id;

        let (is_visible, priority, prompt, title) = get_example_prompt_create_params();
        let example_prompt = example_prompt_create(
            router.clone(),
            session_id,
            example_prompt_category_id,
            is_visible,
            priority,
            &prompt,
            &title,
        )
        .await;
        let example_prompt_id = example_prompt.id;

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

        let (is_visible, priority, prompt, title) = get_example_prompt_create_params();
        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::PUT)
                    .uri(format!("/api/v1/example-prompts/{example_prompt_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "example_prompt_category_id": &example_prompt_category_id,
                            "is_visible": &is_visible,
                            "priority": &priority,
                            "prompt": &prompt,
                            "title": &title,
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

        example_prompt_cleanup(app.context.clone(), &mut transaction, example_prompt_id).await;

        api::example_prompt_categories::tests::example_prompt_category_cleanup(
            app.context.clone(),
            &mut transaction,
            example_prompt_category_id,
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

        let (description, is_visible, title) =
            api::example_prompt_categories::tests::get_example_prompt_category_create_params();
        let example_prompt_category =
            api::example_prompt_categories::tests::example_prompt_category_create(
                router.clone(),
                session_id,
                &description,
                is_visible,
                &title,
            )
            .await;
        let example_prompt_category_id = example_prompt_category.id;

        let (is_visible, priority, prompt, title) = get_example_prompt_create_params();
        let example_prompt = example_prompt_create(
            router.clone(),
            session_id,
            example_prompt_category_id,
            is_visible,
            priority,
            &prompt,
            &title,
        )
        .await;
        let example_prompt_id = example_prompt.id;

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(app.context.clone(), &mut transaction, &[], &[user_id])
            .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;

        let (is_visible, priority, prompt, title) = get_example_prompt_create_params();
        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::PUT)
                    .uri(format!("/api/v1/example-prompts/{example_prompt_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "example_prompt_category_id": &example_prompt_category_id,
                            "is_visible": &is_visible,
                            "priority": &priority,
                            "prompt": &prompt,
                            "title": &title,
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

        example_prompt_cleanup(app.context.clone(), &mut transaction, example_prompt_id).await;

        api::example_prompt_categories::tests::example_prompt_category_cleanup(
            app.context.clone(),
            &mut transaction,
            example_prompt_category_id,
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

        let example_prompt_id = "33847746-0030-4964-a496-f75d04499160";

        let (description, is_visible, title) =
            api::example_prompt_categories::tests::get_example_prompt_category_create_params();
        let example_prompt_category =
            api::example_prompt_categories::tests::example_prompt_category_create(
                router.clone(),
                session_id,
                &description,
                is_visible,
                &title,
            )
            .await;
        let example_prompt_category_id = example_prompt_category.id;

        let (is_visible, priority, prompt, title) = get_example_prompt_create_params();
        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::PUT)
                    .uri(format!("/api/v1/example-prompts/{example_prompt_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "example_prompt_category_id": &example_prompt_category_id,
                            "is_visible": &is_visible,
                            "priority": &priority,
                            "prompt": &prompt,
                            "title": &title,
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

        api::example_prompt_categories::tests::example_prompt_category_cleanup(
            app.context.clone(),
            &mut transaction,
            example_prompt_category_id,
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
