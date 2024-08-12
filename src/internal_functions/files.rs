use crate::{
    ai::function_call::{AiFunctionResponse, AiFunctionTextResponse},
    context::Context,
    entity::FileType,
    error::AppError,
    Result, PUBLIC_DIR,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UserFileResponse {
    pub id: Uuid,
    pub original_file_name: String,
    pub url: String,
}

pub async fn os_internal_list_user_files(
    context: Arc<Context>,
    user_id: Uuid,
) -> Result<AiFunctionResponse> {
    let types = vec![
        FileType::Document,
        FileType::KnowledgeBook,
        FileType::Normal,
        FileType::TaskBook,
    ];
    let files = context
        .octopus_database
        .get_files_by_user_id_and_types(user_id, &types)
        .await?;

    let octopus_api_url = context
        .get_config()
        .await?
        .get_parameter_octopus_api_url()
        .ok_or(AppError::SystemParameter)?;
    let url_prefix = format!("{octopus_api_url}/{PUBLIC_DIR}");

    let mut user_file_responses = vec![];

    for file in files {
        let file_with_url_prefix = format!("{url_prefix}/{}", file.file_name);
        let user_file_response = UserFileResponse {
            id: file.id,
            original_file_name: file.original_file_name,
            url: file_with_url_prefix,
        };
        user_file_responses.push(user_file_response);
    }

    let mut response = String::new();
    response.push_str("```json\n");
    response.push_str(&serde_json::to_string_pretty(&user_file_responses)?);
    response.push_str("\n```");

    let ai_function_text_response = AiFunctionTextResponse {
        response: Some(response),
    };

    let ai_function_response = AiFunctionResponse::Text(ai_function_text_response);

    Ok(ai_function_response)
}
