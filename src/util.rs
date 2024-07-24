use crate::{context::Context, error::AppError, Result};
use chrono::{DateTime, Duration, Utc};
use std::sync::Arc;

pub async fn get_estimated_response_at(context: Arc<Context>) -> Result<DateTime<Utc>> {
    let estimated_seconds = context
        .octopus_database
        .get_chat_messages_estimated_response_at()
        .await?;

    let estimated_response_at = match estimated_seconds.ceiling {
        None => Utc::now() + Duration::try_seconds(5).ok_or(AppError::FromTime)?,
        Some(estimated_seconds) => {
            Utc::now() + Duration::try_seconds(estimated_seconds + 1).ok_or(AppError::FromTime)?
        }
    };

    Ok(estimated_response_at)
}
