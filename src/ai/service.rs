use crate::{
    ai::BASE_AI_FUNCTION_URL,
    context::Context,
    entity::{AiService, AiServiceHealthCheckStatus, AiServiceSetupStatus, AiServiceStatus},
    Result,
};
use chrono::Utc;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::time::{sleep, Duration};
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct HealthCheckResponse {
    pub status: AiServiceHealthCheckStatus,
}

#[derive(Debug, Serialize)]
pub struct SetupPost {
    pub force_setup: bool,
}

#[derive(Debug, Deserialize)]
pub struct SetupResponse {
    pub setup: AiServiceSetupStatus,
}

pub async fn service_health_check(
    ai_service_id: Uuid,
    context: Arc<Context>,
    port: i32,
) -> Result<AiService> {
    let url = format!("{BASE_AI_FUNCTION_URL}:{port}/health-check");

    let mut failed_connection_attempts = 0;

    loop {
        let start = Utc::now();

        let response = reqwest::Client::new()
            .get(url.clone())
            .timeout(Duration::from_secs(30))
            .send()
            .await;

        let end = Utc::now();

        let health_check_execution_time = (end - start).num_seconds() as i32;

        let mut transaction = context.octopus_database.transaction_begin().await?;

        if let Ok(response) = response {
            if response.status() == StatusCode::OK {
                let response: HealthCheckResponse = response.json().await?;

                let ai_service = context
                    .octopus_database
                    .update_ai_service_health_check_status(
                        &mut transaction,
                        ai_service_id,
                        health_check_execution_time,
                        response.status,
                    )
                    .await?;

                context
                    .octopus_database
                    .transaction_commit(transaction)
                    .await?;

                return Ok(ai_service);
            }
        } else {
            context
                .octopus_database
                .update_ai_service_health_check_status(
                    &mut transaction,
                    ai_service_id,
                    health_check_execution_time,
                    AiServiceHealthCheckStatus::NotWorking,
                )
                .await?;

            context
                .octopus_database
                .transaction_commit(transaction)
                .await?;

            failed_connection_attempts += 1;

            if failed_connection_attempts > 40 {
                break;
            }

            sleep(Duration::from_secs(30)).await;
        }
    }

    let mut transaction = context.octopus_database.transaction_begin().await?;

    let ai_service = context
        .octopus_database
        .update_ai_service_health_check_status(
            &mut transaction,
            ai_service_id,
            0,
            AiServiceHealthCheckStatus::NotWorking,
        )
        .await?;

    context
        .octopus_database
        .transaction_commit(transaction)
        .await?;

    Ok(ai_service)
}

pub async fn service_prepare(ai_service: AiService, context: Arc<Context>) -> Result<AiService> {
    if ai_service.is_enabled {
        let ai_service =
            service_health_check(ai_service.id, context.clone(), ai_service.port).await?;

        if ai_service.health_check_status == AiServiceHealthCheckStatus::Ok {
            let mut transaction = context.octopus_database.transaction_begin().await?;

            context
                .octopus_database
                .update_ai_service_setup_status(
                    &mut transaction,
                    ai_service.id,
                    0,
                    AiServiceSetupStatus::NotPerformed,
                )
                .await?;

            context
                .octopus_database
                .update_ai_service_status(
                    &mut transaction,
                    ai_service.id,
                    50,
                    AiServiceStatus::Setup,
                )
                .await?;

            context
                .octopus_database
                .transaction_commit(transaction)
                .await?;

            let ai_service = service_setup(ai_service.id, context.clone(), ai_service.port).await?;

            return Ok(ai_service);
        }

        return Ok(ai_service);
    }

    Ok(ai_service)
}

pub async fn service_setup(
    ai_service_id: Uuid,
    context: Arc<Context>,
    port: i32,
) -> Result<AiService> {
    let start = Utc::now();

    let setup_post = SetupPost { force_setup: false };

    let url = format!("{BASE_AI_FUNCTION_URL}:{port}/setup");

    let response: std::result::Result<reqwest::Response, reqwest::Error> = reqwest::Client::new()
        .post(url)
        .json(&setup_post)
        .send()
        .await;

    let end = Utc::now();
    let setup_execution_time = (end - start).num_seconds() as i32;

    let mut transaction = context.octopus_database.transaction_begin().await?;

    if let Ok(response) = response {
        if response.status() == StatusCode::CREATED {
            let response: SetupResponse = response.json().await?;

            let ai_service = context
                .octopus_database
                .update_ai_service_setup_status(
                    &mut transaction,
                    ai_service_id,
                    setup_execution_time,
                    response.setup,
                )
                .await?;

            return Ok(ai_service);
        }
    }

    let ai_service = context
        .octopus_database
        .update_ai_service_setup_status(
            &mut transaction,
            ai_service_id,
            setup_execution_time,
            AiServiceSetupStatus::NotPerformed,
        )
        .await?;

    context
        .octopus_database
        .transaction_commit(transaction)
        .await?;

    Ok(ai_service)
}
