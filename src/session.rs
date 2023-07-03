use crate::{context::Context, entity::Session, error::AppError};
use axum::{
    async_trait,
    extract::{FromRef, FromRequestParts},
    http::{request::Parts, HeaderMap},
};
use serde::{Deserialize, Serialize};
use std::{str::FromStr, sync::Arc};
use uuid::Uuid;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ExtractedSession {
    pub session: Option<Session>,
}

pub async fn session_id(headers: HeaderMap) -> Result<Option<Uuid>, AppError> {
    let token_header = headers.get("X-Auth-Token");

    match token_header {
        None => Ok(None),
        Some(token_header) => {
            let res = Uuid::from_str(token_header.to_str()?)?;
            Ok(Some(res))
        }
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for ExtractedSession
where
    Arc<Context>: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let context = Arc::from_ref(state);

        let session_id = session_id(parts.headers.clone()).await?;

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
                        let user = context
                            .octopus_database
                            .try_get_user_id_by_id(session.user_id)
                            .await?;

                        match user {
                            None => {
                                extracted_session = ExtractedSession { session: None };
                            }
                            Some(_user) => {
                                extracted_session = ExtractedSession {
                                    session: Some(session),
                                };
                            }
                        }
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
