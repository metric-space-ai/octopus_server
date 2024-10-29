use crate::{
    ai::{self, code_tools},
    context::Context,
    entity::ScheduledPrompt,
    util, Result,
};
use std::sync::Arc;
use tokio_cron_scheduler::Job;
use uuid::Uuid;

pub async fn create_and_schedule(
    context: Arc<Context>,
    scheduled_prompt: ScheduledPrompt,
) -> Result<ScheduledPrompt> {
    if !context.get_config().await?.test_mode {
        let scheduled_prompt =
            code_tools::open_ai_scheduled_prompts_schedule(context.clone(), scheduled_prompt)
                .await?;

        if let Some(job_id) = scheduled_prompt.job_id {
            context.job_scheduler.remove(&job_id).await?;
        }

        let scheduled_prompt = schedule(context, scheduled_prompt).await?;

        return Ok(scheduled_prompt);
    }

    Ok(scheduled_prompt)
}

pub async fn execute(context: Arc<Context>, scheduled_prompt_id: Uuid) -> Result<bool> {
    let scheduled_prompt = context
        .octopus_database
        .try_get_scheduled_prompt_by_id(scheduled_prompt_id)
        .await?;

    if let Some(scheduled_prompt) = scheduled_prompt {
        let user = context
            .octopus_database
            .try_get_user_by_id(scheduled_prompt.user_id)
            .await?;

        if let Some(user) = user {
            let chat = context
                .octopus_database
                .try_get_chat_by_id(scheduled_prompt.chat_id)
                .await?;

            if let Some(chat) = chat {
                let estimated_response_at =
                    util::get_estimated_response_at(context.clone()).await?;

                let mut transaction = context.octopus_database.transaction_begin().await?;

                let chat_message = context
                    .octopus_database
                    .insert_chat_message(
                        &mut transaction,
                        chat.id,
                        scheduled_prompt.user_id,
                        false,
                        estimated_response_at,
                        &scheduled_prompt.prompt,
                        None,
                        None,
                        None,
                        false,
                        None,
                        None,
                    )
                    .await?;

                context
                    .octopus_database
                    .transaction_commit(transaction)
                    .await?;

                let cloned_context = context.clone();
                let cloned_chat_message = chat_message.clone();
                tokio::spawn(async move {
                    let chat_message =
                        Box::pin(ai::ai_request(cloned_context, cloned_chat_message, user)).await;

                    if let Err(e) = chat_message {
                        tracing::error!("Error: {:?}", e);
                    }
                });

                return Ok(true);
            }
        }
    }

    Ok(false)
}

pub async fn remove(
    context: Arc<Context>,
    scheduled_prompt: ScheduledPrompt,
) -> Result<ScheduledPrompt> {
    if !context.get_config().await?.test_mode {
        if let Some(job_id) = scheduled_prompt.job_id {
            context.job_scheduler.remove(&job_id).await?;
        }
    }

    Ok(scheduled_prompt)
}

pub async fn schedule(
    context: Arc<Context>,
    scheduled_prompt: ScheduledPrompt,
) -> Result<ScheduledPrompt> {
    if let Some(ref schedule) = scheduled_prompt.schedule {
        tracing::info!("AAAAAAAA");
        let cloned_context = context.clone();
        let cloned_scheduled_prompt = scheduled_prompt.clone();
        let job = Job::new_async(schedule.as_str(), move |_uuid, _lock| {
            Box::pin({
                let inner_cloned_context = cloned_context.clone();
                async move {
                    let _ = execute(inner_cloned_context, cloned_scheduled_prompt.id).await;
                }
            })
        });
        match job {
            Err(_) => {}
            Ok(job) => {
                let job_id = context.job_scheduler.add(job).await?;
                let mut transaction = context.octopus_database.transaction_begin().await?;

                let scheduled_prompt = context
                    .octopus_database
                    .update_scheduled_job_id(&mut transaction, scheduled_prompt.id, job_id)
                    .await?;

                context
                    .octopus_database
                    .transaction_commit(transaction)
                    .await?;

                return Ok(scheduled_prompt);
            }
        }
    }

    Ok(scheduled_prompt)
}

pub async fn start(context: Arc<Context>) -> Result<()> {
    let scheduled_prompts = context.octopus_database.get_scheduled_prompts().await?;

    for scheduled_prompt in scheduled_prompts {
        if !context.get_config().await?.test_mode {
            schedule(context.clone(), scheduled_prompt).await?;
        }
    }

    Ok(())
}
