use crate::{
    ai::{
        function_call::{AiFunctionResponse, AiFunctionTextResponse},
        generator,
    },
    api::ai_service_generators::AiServiceGeneratorPost,
    context::Context,
    entity::AiServiceGeneratorStatus,
    Result,
};
use serde::{Deserialize, Serialize};
use serde_json::value::Value;
use std::{str::FromStr, sync::Arc};
use uuid::Uuid;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UserAiServiceGeneratorResponse {
    pub id: Uuid,
    pub description: String,
    pub name: String,
    pub status: AiServiceGeneratorStatus,
}

pub async fn os_internal_create_ai_service(
    context: Arc<Context>,
    function_args: &Value,
    user_id: Uuid,
) -> Result<AiFunctionResponse> {
    let ai_service_generator_post: AiServiceGeneratorPost =
        serde_json::from_value(function_args.clone())?;

    let mut transaction = context.octopus_database.transaction_begin().await?;

    let ai_service_generator = context
        .octopus_database
        .insert_ai_service_generator(
            &mut transaction,
            user_id,
            &ai_service_generator_post.description,
            &ai_service_generator_post.name,
            ai_service_generator_post.sample_code,
            ai_service_generator_post.version.unwrap_or(1),
        )
        .await?;

    context
        .octopus_database
        .transaction_commit(transaction)
        .await?;

    let user_ai_service_generator_response = UserAiServiceGeneratorResponse {
        id: ai_service_generator.id,
        description: ai_service_generator.description,
        name: ai_service_generator.name,
        status: ai_service_generator.status,
    };

    let mut response = String::new();
    response.push_str("```json\n");
    response.push_str(&serde_json::to_string_pretty(
        &user_ai_service_generator_response,
    )?);
    response.push_str("\n```");

    let ai_function_text_response = AiFunctionTextResponse {
        response: Some(response),
    };

    let ai_function_response = AiFunctionResponse::Text(ai_function_text_response);

    Ok(ai_function_response)
}

#[derive(Debug, Deserialize)]
pub struct DeleteAiServicePost {
    pub id: String,
}

pub async fn os_internal_delete_ai_service(
    context: Arc<Context>,
    function_args: &Value,
    user_id: Uuid,
) -> Result<AiFunctionResponse> {
    let delete_ai_service_post: DeleteAiServicePost =
        serde_json::from_value(function_args.clone())?;

    let ai_service_generator_id = Uuid::from_str(&delete_ai_service_post.id)?;

    let mut response = String::new();

    let ai_service_generator = context
        .octopus_database
        .try_get_ai_service_generator_by_id(ai_service_generator_id)
        .await?;

    if let Some(ai_service_generator) = ai_service_generator {
        if user_id == ai_service_generator.user_id {
            let mut transaction = context.octopus_database.transaction_begin().await?;

            context
                .octopus_database
                .try_delete_ai_service_generator_by_id(&mut transaction, ai_service_generator.id)
                .await?;

            context
                .octopus_database
                .transaction_commit(transaction)
                .await?;

            response.push_str(&format!(
                "AI service generator {:?} was deleted.",
                ai_service_generator.id
            ));
        }
    }

    let ai_function_text_response = AiFunctionTextResponse {
        response: Some(response),
    };

    let ai_function_response = AiFunctionResponse::Text(ai_function_text_response);

    Ok(ai_function_response)
}

#[derive(Debug, Deserialize)]
pub struct DeployAiServicePost {
    pub id: String,
}

pub async fn os_internal_deploy_ai_service(
    context: Arc<Context>,
    function_args: &Value,
    user_id: Uuid,
) -> Result<AiFunctionResponse> {
    let deploy_ai_service_post: DeployAiServicePost =
        serde_json::from_value(function_args.clone())?;

    let ai_service_generator_id = Uuid::from_str(&deploy_ai_service_post.id)?;

    let mut response = String::new();

    let ai_service_generator = context
        .octopus_database
        .try_get_ai_service_generator_by_id(ai_service_generator_id)
        .await?;

    if let Some(ai_service_generator) = ai_service_generator {
        if user_id == ai_service_generator.user_id
            && ai_service_generator.status == AiServiceGeneratorStatus::Generated
        {
            if let Some(ref original_function_body) = ai_service_generator.original_function_body {
                generator::deploy(
                    ai_service_generator.clone(),
                    context,
                    original_function_body,
                )
                .await?;

                let user_ai_service_generator_response = UserAiServiceGeneratorResponse {
                    id: ai_service_generator.id,
                    description: ai_service_generator.description,
                    name: ai_service_generator.name,
                    status: ai_service_generator.status,
                };

                response.push_str("```json\n");
                response.push_str(&serde_json::to_string_pretty(
                    &user_ai_service_generator_response,
                )?);
                response.push_str("\n```");
            }
        }
    }

    let ai_function_text_response = AiFunctionTextResponse {
        response: Some(response),
    };

    let ai_function_response = AiFunctionResponse::Text(ai_function_text_response);

    Ok(ai_function_response)
}

#[derive(Debug, Deserialize)]
pub struct GenerateAiServicePost {
    pub id: String,
    pub skip_internet_research_results: Option<bool>,
    pub skip_regenerate_internet_research_results: Option<bool>,
}

pub async fn os_internal_generate_ai_service(
    context: Arc<Context>,
    function_args: &Value,
    user_id: Uuid,
) -> Result<AiFunctionResponse> {
    let generate_ai_service_post: GenerateAiServicePost =
        serde_json::from_value(function_args.clone())?;

    let ai_service_generator_id = Uuid::from_str(&generate_ai_service_post.id)?;

    let mut response = String::new();

    let ai_service_generator = context
        .octopus_database
        .try_get_ai_service_generator_by_id(ai_service_generator_id)
        .await?;

    if let Some(ai_service_generator) = ai_service_generator {
        if user_id == ai_service_generator.user_id {
            let skip_internet_research_results = generate_ai_service_post
                .skip_internet_research_results
                .unwrap_or(false);

            let skip_regenerate_internet_research_results = generate_ai_service_post
                .skip_regenerate_internet_research_results
                .unwrap_or(false);

            let mut transaction = context.octopus_database.transaction_begin().await?;

            let ai_service_generator = context
                .octopus_database
                .update_ai_service_generator_status(
                    &mut transaction,
                    ai_service_generator.id,
                    AiServiceGeneratorStatus::Generating,
                )
                .await?;

            context
                .octopus_database
                .transaction_commit(transaction)
                .await?;

            let cloned_context = context.clone();
            let cloned_ai_service_generator = ai_service_generator.clone();
            tokio::spawn(async move {
                let ai_service_generator = generator::generate(
                    cloned_ai_service_generator,
                    cloned_context,
                    skip_internet_research_results,
                    skip_regenerate_internet_research_results,
                )
                .await;

                if let Err(e) = ai_service_generator {
                    tracing::error!("Error: {:?}", e);
                }
            });

            let user_ai_service_generator_response = UserAiServiceGeneratorResponse {
                id: ai_service_generator.id,
                description: ai_service_generator.description,
                name: ai_service_generator.name,
                status: ai_service_generator.status,
            };

            response.push_str("```json\n");
            response.push_str(&serde_json::to_string_pretty(
                &user_ai_service_generator_response,
            )?);
            response.push_str("\n```");
        }
    }

    let ai_function_text_response = AiFunctionTextResponse {
        response: Some(response),
    };

    let ai_function_response = AiFunctionResponse::Text(ai_function_text_response);

    Ok(ai_function_response)
}

pub async fn os_internal_list_user_generated_ai_services(
    context: Arc<Context>,
    user_id: Uuid,
) -> Result<AiFunctionResponse> {
    let ai_service_generators = context
        .octopus_database
        .get_ai_service_generators_by_user_id(user_id)
        .await?;

    let mut user_ai_service_generator_responses = vec![];

    for ai_service_generator in ai_service_generators {
        let user_ai_service_generator_response = UserAiServiceGeneratorResponse {
            id: ai_service_generator.id,
            description: ai_service_generator.description,
            name: ai_service_generator.name,
            status: ai_service_generator.status,
        };
        user_ai_service_generator_responses.push(user_ai_service_generator_response);
    }

    let mut response = String::new();
    response.push_str("```json\n");
    response.push_str(&serde_json::to_string_pretty(
        &user_ai_service_generator_responses,
    )?);
    response.push_str("\n```");

    let ai_function_text_response = AiFunctionTextResponse {
        response: Some(response),
    };

    let ai_function_response = AiFunctionResponse::Text(ai_function_text_response);

    Ok(ai_function_response)
}

#[derive(Debug, Deserialize)]
pub struct ShowAiServicePost {
    pub id: String,
}

pub async fn os_internal_show_ai_service(
    context: Arc<Context>,
    function_args: &Value,
    user_id: Uuid,
) -> Result<AiFunctionResponse> {
    let show_ai_service_post: ShowAiServicePost = serde_json::from_value(function_args.clone())?;

    let ai_service_generator_id = Uuid::from_str(&show_ai_service_post.id)?;

    let mut response = String::new();

    let ai_service_generator = context
        .octopus_database
        .try_get_ai_service_generator_by_id(ai_service_generator_id)
        .await?;

    if let Some(ai_service_generator) = ai_service_generator {
        if user_id == ai_service_generator.user_id {
            let user_ai_service_generator_response = UserAiServiceGeneratorResponse {
                id: ai_service_generator.id,
                description: ai_service_generator.description,
                name: ai_service_generator.name,
                status: ai_service_generator.status,
            };

            response.push_str("```json\n");
            response.push_str(&serde_json::to_string_pretty(
                &user_ai_service_generator_response,
            )?);
            response.push_str("\n```");
        }
    }

    let ai_function_text_response = AiFunctionTextResponse {
        response: Some(response),
    };

    let ai_function_response = AiFunctionResponse::Text(ai_function_text_response);

    Ok(ai_function_response)
}

#[derive(Debug, Deserialize)]
pub struct ShowAiServiceCodePost {
    pub id: String,
}

pub async fn os_internal_show_ai_service_code(
    context: Arc<Context>,
    function_args: &Value,
    user_id: Uuid,
) -> Result<AiFunctionResponse> {
    let show_ai_service_code_post: ShowAiServiceCodePost =
        serde_json::from_value(function_args.clone())?;

    let ai_service_generator_id = Uuid::from_str(&show_ai_service_code_post.id)?;

    let mut response = String::new();

    let ai_service_generator = context
        .octopus_database
        .try_get_ai_service_generator_by_id(ai_service_generator_id)
        .await?;

    if let Some(ai_service_generator) = ai_service_generator {
        if user_id == ai_service_generator.user_id {
            if let Some(original_function_body) = ai_service_generator.original_function_body {
                response.push_str("```python\n");
                response.push_str(&original_function_body);
                response.push_str("\n```");
            }
        }
    }

    let ai_function_text_response = AiFunctionTextResponse {
        response: Some(response),
    };

    let ai_function_response = AiFunctionResponse::Text(ai_function_text_response);

    Ok(ai_function_response)
}

#[derive(Debug, Deserialize)]
pub struct UpdateAiServicePost {
    pub id: String,
    pub description: String,
    pub name: String,
    pub sample_code: Option<String>,
    pub version: Option<i32>,
}

pub async fn os_internal_update_ai_service(
    context: Arc<Context>,
    function_args: &Value,
    user_id: Uuid,
) -> Result<AiFunctionResponse> {
    let update_ai_service_post: UpdateAiServicePost =
        serde_json::from_value(function_args.clone())?;

    let ai_service_generator_id = Uuid::from_str(&update_ai_service_post.id)?;

    let mut response = String::new();

    let ai_service_generator = context
        .octopus_database
        .try_get_ai_service_generator_by_id(ai_service_generator_id)
        .await?;

    if let Some(ai_service_generator) = ai_service_generator {
        if user_id == ai_service_generator.user_id {
            let mut transaction = context.octopus_database.transaction_begin().await?;

            let ai_service_generator = context
                .octopus_database
                .update_ai_service_generator(
                    &mut transaction,
                    ai_service_generator.id,
                    &update_ai_service_post.description,
                    &update_ai_service_post.name,
                    update_ai_service_post.sample_code,
                    AiServiceGeneratorStatus::Changed,
                    update_ai_service_post.version.unwrap_or(1),
                )
                .await?;

            context
                .octopus_database
                .transaction_commit(transaction)
                .await?;

            let user_ai_service_generator_response = UserAiServiceGeneratorResponse {
                id: ai_service_generator.id,
                description: ai_service_generator.description,
                name: ai_service_generator.name,
                status: ai_service_generator.status,
            };

            response.push_str("```json\n");
            response.push_str(&serde_json::to_string_pretty(
                &user_ai_service_generator_response,
            )?);
            response.push_str("\n```");
        }
    }

    let ai_function_text_response = AiFunctionTextResponse {
        response: Some(response),
    };

    let ai_function_response = AiFunctionResponse::Text(ai_function_text_response);

    Ok(ai_function_response)
}
