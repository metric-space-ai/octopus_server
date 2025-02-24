use crate::{
    PUBLIC_DIR, Result,
    ai::function_call::AiFunctionResponse,
    context::Context,
    entity::{ChatMessage, ChatMessageStatus},
    error::AppError,
    internal_functions,
};
use async_recursion::async_recursion;
use base64::{Engine, alphabet, engine};
use serde_json::value::Value;
use std::{fs::File, io::Write, sync::Arc};
use tokio::time::{Duration, sleep};
use uuid::Uuid;

pub const COLOR: &str = "#b7b7b7";

#[allow(clippy::module_name_repetitions)]
pub async fn handle_internal_function_call(
    chat_message: &ChatMessage,
    context: Arc<Context>,
    function_args: &Value,
    function_name: &str,
) -> Result<ChatMessage> {
    let mut failed_connection_attempts = 0;

    loop {
        let response = internal_function_call(
            context.clone(),
            function_args,
            function_name,
            chat_message.user_id,
        )
        .await?;

        if let Some(response) = response {
            let chat_message =
                update_chat_message(&response, context.clone(), chat_message).await?;

            return Ok(chat_message);
        }

        tracing::error!("Function call error: No Response");

        failed_connection_attempts += 1;

        if failed_connection_attempts > 10 {
            tracing::error!("Function call error: No Response - health check");

            break;
        }

        sleep(Duration::from_secs(2)).await;
    }

    Ok(chat_message.clone())
}

pub async fn internal_function_call(
    context: Arc<Context>,
    function_args: &Value,
    function_name: &str,
    user_id: Uuid,
) -> Result<Option<AiFunctionResponse>> {
    let response = match function_name {
        "os_internal_create_ai_service" => {
            let ai_function_response =
                internal_functions::ai_service_generators::os_internal_create_ai_service(
                    context,
                    function_args,
                    user_id,
                )
                .await?;

            Some(ai_function_response)
        }
        "os_internal_delete_ai_service" => {
            let ai_function_response =
                internal_functions::ai_service_generators::os_internal_delete_ai_service(
                    context,
                    function_args,
                    user_id,
                )
                .await?;

            Some(ai_function_response)
        }
        "os_internal_deploy_ai_service" => {
            let ai_function_response =
                internal_functions::ai_service_generators::os_internal_deploy_ai_service(
                    context,
                    function_args,
                    user_id,
                )
                .await?;

            Some(ai_function_response)
        }
        "os_internal_generate_ai_service" => {
            let ai_function_response =
                internal_functions::ai_service_generators::os_internal_generate_ai_service(
                    context,
                    function_args,
                    user_id,
                )
                .await?;

            Some(ai_function_response)
        }
        "os_internal_list_user_files" => {
            let ai_function_response =
                internal_functions::files::os_internal_list_user_files(context, user_id).await?;

            Some(ai_function_response)
        }
        "os_internal_list_user_generated_ai_services" => {
            let ai_function_response =
                internal_functions::ai_service_generators::os_internal_list_user_generated_ai_services(context, user_id).await?;

            Some(ai_function_response)
        }
        "os_internal_show_ai_service" => {
            let ai_function_response =
                internal_functions::ai_service_generators::os_internal_show_ai_service(
                    context,
                    function_args,
                    user_id,
                )
                .await?;

            Some(ai_function_response)
        }
        "os_internal_show_ai_service_code" => {
            let ai_function_response =
                internal_functions::ai_service_generators::os_internal_show_ai_service_code(
                    context,
                    function_args,
                    user_id,
                )
                .await?;

            Some(ai_function_response)
        }
        "os_internal_update_ai_service" => {
            let ai_function_response =
                internal_functions::ai_service_generators::os_internal_update_ai_service(
                    context,
                    function_args,
                    user_id,
                )
                .await?;

            Some(ai_function_response)
        }
        _ => None,
    };

    Ok(response)
}

#[async_recursion]
pub async fn update_chat_message(
    ai_function_response: &AiFunctionResponse,
    context: Arc<Context>,
    chat_message: &ChatMessage,
) -> Result<ChatMessage> {
    let mut transaction = context.octopus_database.transaction_begin().await?;

    match ai_function_response {
        AiFunctionResponse::Error(ai_function_error_response) => {
            let chat_message = context
                .octopus_database
                .update_chat_message_from_internal_function_error(
                    &mut transaction,
                    chat_message.id,
                    ai_function_error_response.error.clone(),
                    ChatMessageStatus::Answered,
                    100,
                    Some(COLOR.to_string()),
                )
                .await?;

            context
                .octopus_database
                .transaction_commit(transaction)
                .await?;

            Ok(chat_message)
        }
        AiFunctionResponse::File(ai_function_file_response) => {
            let chat_message = context
                .octopus_database
                .update_chat_message_from_internal_function_status(
                    &mut transaction,
                    chat_message.id,
                    ChatMessageStatus::Answered,
                    100,
                    Some(COLOR.to_string()),
                )
                .await?;

            let mut data = None;

            let engine =
                engine::GeneralPurpose::new(&alphabet::URL_SAFE, engine::general_purpose::PAD);
            let result = engine.decode(ai_function_file_response.content.clone());

            if let Ok(result) = result {
                data = Some(result);
            }

            if data.is_none() {
                let engine =
                    engine::GeneralPurpose::new(&alphabet::STANDARD, engine::general_purpose::PAD);
                let result = engine.decode(ai_function_file_response.content.clone());

                if let Ok(result) = result {
                    data = Some(result);
                }
            }

            if let Some(data) = data {
                let mut extension = None;
                let kind = infer::get(&data).ok_or(AppError::File);
                if let Ok(kind) = kind {
                    extension = Some(kind.extension());
                }

                if extension.is_none() && data.len() >= 4 {
                    if data[0] == 103 && data[1] == 108 && data[2] == 84 && data[3] == 70 {
                        extension = Some("glb");
                    } else if data[0] == 25 && data[1] == 50 && data[2] == 44 && data[3] == 46 {
                        extension = Some("pdf");
                    } else {
                        extension = Some("txt");
                    }
                } else if extension.is_none() {
                    extension = Some("txt");
                }

                if let Some(extension) = extension {
                    let file_name = format!("{}.{}", Uuid::new_v4(), extension);
                    let path = format!("{PUBLIC_DIR}/{file_name}");
                    let mut file = File::create(path)?;
                    file.write_all(&data)?;

                    context
                        .octopus_database
                        .insert_chat_message_file(
                            &mut transaction,
                            chat_message.id,
                            &file_name,
                            &ai_function_file_response.media_type,
                            ai_function_file_response.original_file_name.clone(),
                        )
                        .await?;
                }
            }

            context
                .octopus_database
                .transaction_commit(transaction)
                .await?;

            Ok(chat_message)
        }
        AiFunctionResponse::Mixed(ai_function_responses) => {
            let mut chat_message = chat_message.clone();
            for ai_function_response_tmp in ai_function_responses {
                chat_message =
                    update_chat_message(ai_function_response_tmp, context.clone(), &chat_message)
                        .await?;
            }

            Ok(chat_message)
        }
        AiFunctionResponse::Text(ai_function_text_response) => {
            let chat_message = context
                .octopus_database
                .update_chat_message_from_internal_function(
                    &mut transaction,
                    chat_message.id,
                    ChatMessageStatus::Answered,
                    100,
                    ai_function_text_response.response.clone(),
                    Some(COLOR.to_string()),
                )
                .await?;

            context
                .octopus_database
                .transaction_commit(transaction)
                .await?;

            Ok(chat_message)
        }
    }
}
