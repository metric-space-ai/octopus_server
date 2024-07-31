use crate::{
    ai::function_call::{AiFunctionResponse, AiFunctionTextResponse},
    context::Context,
    entity::FileType,
    error::AppError,
    Result, PUBLIC_DIR,
};
use std::sync::Arc;
use uuid::Uuid;

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

    let mut file_with_url_prefixes = vec![];

    for file in files {
        let file_with_url_prefix = format!("{url_prefix}/{}", file.file_name);
        file_with_url_prefixes.push(file_with_url_prefix);
    }

    let list_of_user_files = file_with_url_prefixes.join(" , ");

    let ai_function_text_response = AiFunctionTextResponse {
        response: Some(list_of_user_files),
    };

    let ai_function_response = AiFunctionResponse::Text(ai_function_text_response);

    Ok(ai_function_response)
}
