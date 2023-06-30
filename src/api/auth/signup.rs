use crate::{api::auth, context::Context, error::AppError};
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::Deserialize;
use std::sync::Arc;
use utoipa::ToSchema;
use validator::Validate;

#[axum_macros::debug_handler]
#[utoipa::path(
    post,
    path = "/api/v1/auth/signup",
    request_body = SignupPost,
    responses(
        (status = 201, description = "Account created.", body = User),
        (status = 409, description = "Conflicting request.", body = ResponseError),
    ),
    security(
        ()
    )
)]
pub async fn signup(
    State(context): State<Arc<Context>>,
    Json(input): Json<SignupPost>,
) -> Result<impl IntoResponse, AppError> {
    input.validate()?;

    let user_exists = context
        .octopus_database
        .try_get_user_by_email(&input.email)
        .await?;

    match user_exists {
        None => {
            let cloned_context = context.clone();
            let cloned_password = input.password.clone();
            let pw_hash = tokio::task::spawn_blocking(move || {
                auth::hash_password(cloned_context, cloned_password)
            })
            .await??;

            let company = context
                .octopus_database
                .insert_company(None, &input.company_name)
                .await?;

            let user = context
                .octopus_database
                .insert_user(
                    company.id,
                    &input.email,
                    true,
                    context.config.pepper_id,
                    &pw_hash,
                    &["ROLE_COMPANY_ADMIN".to_string()],
                )
                .await?;

            Ok((StatusCode::CREATED, Json(user)).into_response())
        }
        Some(_user_exists) => Err(AppError::UserAlreadyExists),
    }
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct SignupPost {
    #[validate(length(max = 256, min = 1))]
    company_name: String,
    #[validate(email, length(max = 256))]
    email: String,
    #[validate(length(min = 8))]
    password: String,
    #[validate(length(min = 8))]
    repeat_password: String,
}
