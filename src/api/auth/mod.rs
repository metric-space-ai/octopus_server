use crate::{context::Context, error::AppError};
use argon2::{password_hash::SaltString, Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use rand_core::OsRng;
use std::sync::Arc;

pub mod change_password;
pub mod login;
pub mod logout;
pub mod register;
pub mod register_company;

pub fn hash_password(context: Arc<Context>, password: String) -> Result<String, AppError> {
    let salt = SaltString::generate(&mut OsRng);
    let peppered = format!("{}{}", context.config.pepper, password);
    let hash = Argon2::default()
        .hash_password(peppered.as_bytes(), &salt)?
        .to_string();

    Ok(hash)
}

pub async fn verify_password(
    context: Arc<Context>,
    hash: String,
    password: String,
) -> Result<bool, AppError> {
    tokio::task::spawn_blocking(move || {
        let Ok(hash) = PasswordHash::new(&hash) else { return false };
        let peppered = format!("{}{}", context.config.pepper, password);
        Argon2::default()
            .verify_password(peppered.as_bytes(), &hash)
            .is_ok()
    })
    .await
    .map_err(AppError::Concurrency)
}
