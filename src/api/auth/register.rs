use crate::{
    api::auth,
    canon,
    context::Context,
    entity::{ROLE_PRIVATE_USER, ROLE_PUBLIC_USER, User},
    error::{AppError, ResponseError},
};
use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use serde::Deserialize;
use std::sync::Arc;
use utoipa::ToSchema;
use validator::Validate;

#[allow(clippy::module_name_repetitions)]
#[derive(Debug, Deserialize, ToSchema, Validate)]
pub struct RegisterPost {
    #[validate(email, length(max = 256))]
    email: String,
    #[validate(length(max = 256, min = 1))]
    job_title: String,
    #[validate(length(max = 256, min = 1))]
    name: String,
    #[validate(length(min = 8))]
    password: String,
    #[validate(length(min = 8))]
    repeat_password: String,
}

#[axum_macros::debug_handler]
#[utoipa::path(
    post,
    path = "/api/v1/auth/register",
    request_body = RegisterPost,
    responses(
        (status = 201, description = "Account created.", body = User),
        (status = 400, description = "Bad request.", body = ResponseError),
        (status = 409, description = "Conflicting request.", body = ResponseError),
    ),
    security(
        ()
    )
)]
pub async fn register(
    State(context): State<Arc<Context>>,
    Json(input): Json<RegisterPost>,
) -> Result<impl IntoResponse, AppError> {
    input.validate()?;

    let email = canon::canonicalize(&input.email);

    let registration_allowed = context
        .get_config()
        .await?
        .get_parameter_registration_allowed()
        .unwrap_or(true);

    if !registration_allowed {
        return Err(AppError::NotFound);
    }

    if input.password != input.repeat_password {
        return Err(AppError::PasswordDoesNotMatch);
    }

    let cloned_password = input.password.clone();
    let config = context.get_config().await?;
    let pw_hash =
        tokio::task::spawn_blocking(move || auth::hash_password(&config, &cloned_password))
            .await??;

    let company = context
        .octopus_database
        .try_get_company_primary()
        .await?
        .ok_or(AppError::CompanyNotFound)?;

    if let Some(allowed_domains) = company.allowed_domains {
        let mut registration_allowed = false;

        for allowed_domain in allowed_domains {
            if email.contains(&allowed_domain) {
                registration_allowed = true;
            }
        }

        if !registration_allowed {
            return Err(AppError::NotAllowedDomain);
        }
    }

    let user_exists = context
        .octopus_database
        .try_get_user_by_email_even_deleted(&email)
        .await?;

    match user_exists {
        None => {
            let mut transaction = context.octopus_database.transaction_begin().await?;

            let user = context
                .octopus_database
                .insert_user(
                    &mut transaction,
                    company.id,
                    &email,
                    true,
                    false,
                    context.get_config().await?.pepper_id,
                    &pw_hash,
                    &[ROLE_PUBLIC_USER.to_string(), ROLE_PRIVATE_USER.to_string()],
                )
                .await?;

            context
                .octopus_database
                .insert_profile(
                    &mut transaction,
                    user.id,
                    Some(input.job_title),
                    Some(input.name),
                )
                .await?;

            context
                .octopus_database
                .transaction_commit(transaction)
                .await?;

            Ok((StatusCode::CREATED, Json(user)).into_response())
        }
        Some(user_exists) => {
            if let Some(_deleted_at) = user_exists.deleted_at {
                let mut transaction = context.octopus_database.transaction_begin().await?;

                let user = context
                    .octopus_database
                    .update_user_undelete(
                        &mut transaction,
                        user_exists.id,
                        company.id,
                        &email,
                        true,
                        false,
                        context.get_config().await?.pepper_id,
                        &pw_hash,
                        &[ROLE_PUBLIC_USER.to_string(), ROLE_PRIVATE_USER.to_string()],
                    )
                    .await?;

                let profile = context
                    .octopus_database
                    .try_get_profile_by_user_id_even_deleted(user.id)
                    .await?;

                match profile {
                    None => {
                        context
                            .octopus_database
                            .insert_profile(
                                &mut transaction,
                                user.id,
                                Some(input.job_title),
                                Some(input.name),
                            )
                            .await?;
                    }
                    Some(profile) => {
                        context
                            .octopus_database
                            .update_profile_undelete(
                                &mut transaction,
                                profile.id,
                                Some(input.job_title),
                                Some(input.name),
                            )
                            .await?;
                    }
                }

                context
                    .octopus_database
                    .transaction_commit(transaction)
                    .await?;

                return Ok((StatusCode::CREATED, Json(user)).into_response());
            }

            Err(AppError::UserAlreadyExists)
        }
    }
}

#[cfg(test)]
pub mod tests {
    use crate::{api, app};
    use axum::{
        body::Body,
        http::{self, Request, StatusCode},
    };
    use tower::ServiceExt;

    #[tokio::test]
    async fn register_201() {
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
    async fn register_400() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let (email, _is_enabled, job_title, name, password, _roles) =
            api::users::tests::get_user_create_params();
        let repeat_password = "password1234";
        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/auth/register".to_string())
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "email": &email,
                            "job_title": &job_title,
                            "name": &name,
                            "password": &password,
                            "repeat_password": &repeat_password,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

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
    async fn register_409() {
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

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/auth/register".to_string())
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

        assert_eq!(response.status(), StatusCode::CONFLICT);

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
}
