use crate::{
    ai,
    context::Context,
    entity::{
        AiFunctionRequestContentType, AiFunctionResponseContentType, AiService, AiServiceStatus,
    },
    error::AppError,
    parser::configuration::Configuration,
    Result,
};
use std::{str::FromStr, sync::Arc};

mod addons;
mod configuration;
mod detectors;
mod fixes;
mod replacers;

pub async fn ai_service_malicious_code_check(
    ai_service: AiService,
    context: Arc<Context>,
) -> Result<AiService> {
    let malicious_code_detected =
        ai::open_ai_code_check(&ai_service.original_function_body, context.clone()).await?;

    let status = if malicious_code_detected {
        AiServiceStatus::MaliciousCodeDetected
    } else {
        AiServiceStatus::Configuration
    };

    let ai_service = context
        .octopus_database
        .update_ai_service_status(ai_service.id, 100, status)
        .await?;

    Ok(ai_service)
}

pub async fn ai_service_parsing(ai_service: AiService, context: Arc<Context>) -> Result<AiService> {
    let ai_service = context
        .octopus_database
        .update_ai_service_status(ai_service.id, 0, AiServiceStatus::ParsingStarted)
        .await?;

    let original_function_body = ai_service.original_function_body.clone().replace('\r', "");
    let mut code_lines = vec![];
    for line in original_function_body.split('\n') {
        code_lines.push(line.to_string());
    }

    let app_threaded = detectors::detect_app_threaded(&code_lines).await?;

    if let Some(device_map) = ai_service.device_map.clone() {
        code_lines = replacers::replace_device_map(code_lines, device_map).await?;
    }

    code_lines = fixes::fix_apt_get(code_lines).await?;
    code_lines = fixes::fix_apt_install(code_lines).await?;
    code_lines = fixes::fix_input_type_json(code_lines).await?;
    code_lines = fixes::fix_methods_get(code_lines).await?;
    code_lines = fixes::fix_return_code(code_lines).await?;
    code_lines = fixes::fix_return_setup_status(code_lines).await?;
    code_lines = fixes::fix_return_type_string(code_lines).await?;
    code_lines = fixes::fix_type_int(code_lines).await?;
    code_lines = fixes::fix_type_str(code_lines).await?;
    code_lines = fixes::fix_urls(code_lines).await?;

    code_lines = addons::add_health_check(code_lines).await?;
    code_lines = addons::add_handle_exception(code_lines).await?;

    code_lines = replacers::replace_function_names(code_lines, ai_service.id).await?;
    code_lines = replacers::replace_print(code_lines).await?;

    let last_return_jsonify_line = detectors::detect_last_return_jsonify_line(&code_lines).await?;

    code_lines = replacers::cut_code(code_lines, last_return_jsonify_line).await?;

    code_lines = addons::add_argparse(code_lines).await?;
    code_lines = addons::add_main(app_threaded, code_lines).await?;

    code_lines = addons::add_logging(&ai_service, code_lines).await?;

    for code_line in &code_lines {
        tracing::info!("{}", code_line);
    }

    let config_lines = configuration::locate_config(code_lines.clone()).await?;
    let config_lines = config_lines.join("\n");

    let configuration: Configuration = serde_json::from_str(&config_lines)?;

    let processed_function_body = code_lines.join("\n");

    let ai_service = context
        .octopus_database
        .update_ai_service_processed_function_body(
            ai_service.id,
            &processed_function_body,
            100,
            AiServiceStatus::ParsingFinished,
        )
        .await?;

    let ai_service = if let Some(required_python_version) = configuration.required_python_version {
        context
            .octopus_database
            .update_ai_service_required_python_version(ai_service.id, required_python_version)
            .await?
    } else {
        ai_service
    };

    for function in configuration.functions {
        let ai_function_exists = context
            .octopus_database
            .try_get_ai_function_by_name(&function.name)
            .await?;

        let request_content_type = function.input_type.replace('/', "_");
        let response_content_type = function.return_type.replace('/', "_");
        let formatted_name = function
            .name
            .clone()
            .strip_prefix(&format!("{}-", ai_service.id))
            .ok_or(AppError::Parsing)?
            .to_string()
            .replace('-', "_")
            .to_lowercase();

        match ai_function_exists {
            None => {
                context
                    .octopus_database
                    .insert_ai_function(
                        ai_service.id,
                        &function.description,
                        &formatted_name,
                        &function.name,
                        function.parameters,
                        AiFunctionRequestContentType::from_str(&request_content_type)?,
                        AiFunctionResponseContentType::from_str(&response_content_type)?,
                    )
                    .await?;
            }
            Some(ai_function_exists) => {
                context
                    .octopus_database
                    .update_ai_function(
                        ai_function_exists.id,
                        &function.description,
                        &formatted_name,
                        &function.name,
                        function.parameters,
                        AiFunctionRequestContentType::from_str(&request_content_type)?,
                        AiFunctionResponseContentType::from_str(&response_content_type)?,
                    )
                    .await?;
            }
        }
    }

    Ok(ai_service)
}
