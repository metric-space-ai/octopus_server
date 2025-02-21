use crate::{context::Context, entity::Session, error::AppError};
use axum::{
    extract::{FromRef, FromRequestParts},
    http::{HeaderMap, request::Parts},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{str::FromStr, sync::Arc};
use utoipa::ToSchema;
use uuid::Uuid;

#[allow(clippy::module_name_repetitions)]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ExtractedSession {
    pub session: Option<Session>,
}

#[allow(clippy::module_name_repetitions)]
#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
pub struct SessionResponse {
    pub id: Uuid,
    pub user_id: Uuid,
    pub data: SessionResponseData,
    pub expired_at: DateTime<Utc>,
}

#[allow(clippy::module_name_repetitions)]
#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
pub struct SessionResponseData {
    pub roles: Vec<String>,
}

pub async fn require_authenticated(
    extracted_session: ExtractedSession,
) -> Result<Session, AppError> {
    match extracted_session.session {
        Some(session) => {
            let now = Utc::now();
            if session.expired_at < now {
                return Err(AppError::Unauthorized);
            }

            Ok(session)
        }
        None => Err(AppError::Unauthorized),
    }
}

pub fn get_session_id(headers: &HeaderMap) -> Result<Option<Uuid>, AppError> {
    let token_header = headers.get("X-Auth-Token");

    match token_header {
        None => Ok(None),
        Some(token_header) => {
            let res = Uuid::from_str(token_header.to_str()?)?;
            Ok(Some(res))
        }
    }
}

impl<S> FromRequestParts<S> for ExtractedSession
where
    Arc<Context>: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let context = Arc::from_ref(state);

        let session_id = get_session_id(&parts.headers)?;

        let extracted_session;

        match session_id {
            Some(session_id) => {
                let session = context
                    .octopus_database
                    .try_get_session_by_id(session_id)
                    .await?;

                match session {
                    None => {
                        extracted_session = ExtractedSession { session: None };
                    }
                    Some(session) => {
                        extracted_session = ExtractedSession {
                            session: Some(session),
                        };
                    }
                }
            }
            None => {
                extracted_session = ExtractedSession { session: None };
            }
        }

        Ok(extracted_session)
    }
}
