use crate::{context::Context, error::AppError};
use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
use rand_core::OsRng;
use std::sync::Arc;

pub mod signup;

pub fn hash_password(context: Arc<Context>, password: String) -> Result<String, AppError> {
    let salt = SaltString::generate(&mut OsRng);
    let peppered = format!("{}{}", context.config.pepper, password);
    let hash = Argon2::default()
        .hash_password(peppered.as_bytes(), &salt)?
        .to_string();
    Ok(hash)
}
