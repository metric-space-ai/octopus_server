use crate::{
    ai,
    context::Context,
    entity::{
        AiFunctionRequestContentType, AiFunctionResponseContentType, AiService, AiServiceStatus,
    },
    error::AppError,
    ollama,
    parser::configuration::{Configuration, Model},
    server_resources, Result,
};
use std::{collections::HashMap, str::FromStr, sync::Arc};

mod addons;
pub mod configuration;
mod detectors;
mod fixes;
mod replacers;

pub async fn ai_service_malicious_code_check(
    ai_service: AiService,
    bypass_code_check: bool,
    context: Arc<Context>,
) -> Result<AiService> {
    let parsing_code_check_response = ai::code_tools::open_ai_malicious_code_check(
        &ai_service.original_function_body,
        context.clone(),
    )
    .await?;

    let mut transaction = context.octopus_database.transaction_begin().await?;

    let status = if let Some(parsing_code_check_response) = parsing_code_check_response {
        if parsing_code_check_response.is_passed {
            AiServiceStatus::Configuration
        } else {
            if let Some(fixing_proposal) = parsing_code_check_response.fixing_proposal {
                let fixing_proposal = format!("Malicious code check: {}", fixing_proposal);

                context
                    .octopus_database
                    .update_ai_service_parser_feedback(
                        &mut transaction,
                        ai_service.id,
                        &fixing_proposal,
                        100,
                        AiServiceStatus::MaliciousCodeDetected,
                    )
                    .await?;
            }

            if bypass_code_check {
                AiServiceStatus::Configuration
            } else {
                AiServiceStatus::MaliciousCodeDetected
            }
        }
    } else {
        AiServiceStatus::Configuration
    };

    let ai_service = context
        .octopus_database
        .update_ai_service_status(&mut transaction, ai_service.id, 100, status)
        .await?;

    context
        .octopus_database
        .transaction_commit(transaction)
        .await?;

    Ok(ai_service)
}

pub async fn ai_service_parsing(ai_service: AiService, context: Arc<Context>) -> Result<AiService> {
    let mut transaction = context.octopus_database.transaction_begin().await?;

    let ai_service = context
        .octopus_database
        .update_ai_service_status(
            &mut transaction,
            ai_service.id,
            0,
            AiServiceStatus::ParsingStarted,
        )
        .await?;

    context
        .octopus_database
        .transaction_commit(transaction)
        .await?;

    let original_function_body = ai_service.original_function_body.clone().replace('\r', "");

    let parsing_code_check_response =
        ai::code_tools::open_ai_pre_parsing_code_check(&original_function_body, context.clone())
            .await?;

    if let Some(parsing_code_check_response) = parsing_code_check_response {
        if !parsing_code_check_response.is_passed {
            if let Some(fixing_proposal) = parsing_code_check_response.fixing_proposal {
                let fixing_proposal = format!("Pre parsing code check: {}", fixing_proposal);

                let ai_service_tmp = context
                    .octopus_database
                    .try_get_ai_service_by_id(ai_service.id)
                    .await?;

                let fixing_proposal = if let Some(ai_service_tmp) = ai_service_tmp {
                    if let Some(parser_feedback) = ai_service_tmp.parser_feedback {
                        format!("{parser_feedback} \n\n {fixing_proposal}")
                    } else {
                        fixing_proposal
                    }
                } else {
                    fixing_proposal
                };

                let mut transaction = context.octopus_database.transaction_begin().await?;

                context
                    .octopus_database
                    .update_ai_service_parser_feedback2(
                        &mut transaction,
                        ai_service.id,
                        &fixing_proposal,
                    )
                    .await?;

                context
                    .octopus_database
                    .transaction_commit(transaction)
                    .await?;
            }
        }
    }

    let mut code_lines = vec![];
    for line in original_function_body.split('\n') {
        code_lines.push(line.to_string());
    }

    let is_ai_service = detectors::detect_is_ai_service(&code_lines);
    if !is_ai_service {
        let parser_feedback = "This Python code doesn't look like a proper AI service";

        let mut transaction = context.octopus_database.transaction_begin().await?;

        let ai_service = context
            .octopus_database
            .update_ai_service_parser_feedback(
                &mut transaction,
                ai_service.id,
                parser_feedback,
                100,
                AiServiceStatus::Error,
            )
            .await?;

        context
            .octopus_database
            .transaction_commit(transaction)
            .await?;

        return Ok(ai_service);
    }

    let app_threaded = detectors::detect_app_threaded(&code_lines);

    if let Some(device_map) = ai_service.device_map.clone() {
        code_lines = replacers::replace_device_map(code_lines, &device_map);
    }

    code_lines = fixes::fix_apt_get(code_lines);
    code_lines = fixes::fix_apt_install(code_lines);
    code_lines = fixes::fix_input_type_json(code_lines);
    code_lines = fixes::fix_methods_get(code_lines);
    code_lines = fixes::fix_return_code(code_lines);
    code_lines = fixes::fix_return_setup_status(code_lines);
    code_lines = fixes::fix_return_type_string(code_lines);
    code_lines = fixes::fix_type_int(code_lines);
    code_lines = fixes::fix_type_str(code_lines);
    code_lines = fixes::fix_urls(code_lines);

    code_lines = addons::add_health_check(code_lines);
    code_lines = addons::add_handle_exception(code_lines);

    code_lines = replacers::replace_function_names(&code_lines, ai_service.id)?;
    //code_lines = replacers::replace_pip(code_lines);
    code_lines = replacers::replace_print(code_lines);

    let last_return_jsonify_line = detectors::detect_last_return_jsonify_line(&code_lines);

    code_lines = replacers::cut_code(&code_lines, last_return_jsonify_line);

    code_lines = addons::add_argparse(code_lines);
    code_lines = addons::add_main(app_threaded, code_lines);

    code_lines = addons::add_logging(&ai_service, code_lines)?;
    /*
        for code_line in &code_lines {
            tracing::info!("{}", code_line);
        }
    */
    let config_lines = configuration::locate_config(&code_lines.clone());
    let config_lines = config_lines.join("\n");

    let configuration: Configuration = serde_json::from_str(&config_lines)?;

    let processed_function_body = code_lines.join("\n");

    let parsing_code_check_response =
        ai::code_tools::open_ai_post_parsing_code_check(&processed_function_body, context.clone())
            .await?;

    if let Some(parsing_code_check_response) = parsing_code_check_response {
        if !parsing_code_check_response.is_passed {
            if let Some(fixing_proposal) = parsing_code_check_response.fixing_proposal {
                let fixing_proposal = format!("Post parsing code check: {}", fixing_proposal);

                let ai_service_tmp = context
                    .octopus_database
                    .try_get_ai_service_by_id(ai_service.id)
                    .await?;

                let fixing_proposal = if let Some(ai_service_tmp) = ai_service_tmp {
                    if let Some(parser_feedback) = ai_service_tmp.parser_feedback {
                        format!("{parser_feedback} \n\n {fixing_proposal}")
                    } else {
                        fixing_proposal
                    }
                } else {
                    fixing_proposal
                };

                let mut transaction = context.octopus_database.transaction_begin().await?;

                context
                    .octopus_database
                    .update_ai_service_parser_feedback2(
                        &mut transaction,
                        ai_service.id,
                        &fixing_proposal,
                    )
                    .await?;

                context
                    .octopus_database
                    .transaction_commit(transaction)
                    .await?;
            }
        }
    }

    let mut transaction = context.octopus_database.transaction_begin().await?;

    let ai_service = context
        .octopus_database
        .update_ai_service_processed_function_body(
            &mut transaction,
            ai_service.id,
            &processed_function_body,
            100,
            AiServiceStatus::ParsingFinished,
        )
        .await?;

    let ai_service =
        if let Some(ref required_python_version) = configuration.required_python_version {
            context
                .octopus_database
                .update_ai_service_required_python_version(
                    &mut transaction,
                    ai_service.id,
                    required_python_version.clone(),
                )
                .await?
        } else {
            ai_service
        };

    let describe_functions_response = ai::code_tools::open_ai_describe_functions(
        &processed_function_body,
        &configuration,
        context.clone(),
    )
    .await?;

    if let Some(value) = configuration.models {
        let models: std::result::Result<Vec<Model>, serde_json::error::Error> =
            serde_json::from_value(value.clone());

        if let Ok(models) = models {
            for model in models {
                if let Some(name) = model.name {
                    if name.starts_with("ollama:") {
                        let model_name = name
                            .strip_prefix("ollama:")
                            .ok_or(AppError::Parsing)?
                            .to_string();

                        let ollama_model_exists = context
                            .octopus_database
                            .try_get_ollama_model_by_name(&model_name)
                            .await?;

                        if ollama_model_exists.is_none() {
                            let mut transaction =
                                context.octopus_database.transaction_begin().await?;

                            let ollama_model = context
                                .octopus_database
                                .insert_ollama_model(&mut transaction, &model_name)
                                .await?;

                            context
                                .octopus_database
                                .transaction_commit(transaction)
                                .await?;

                            let cloned_context = context.clone();
                            let cloned_ollama_model = ollama_model.clone();
                            tokio::spawn(async move {
                                let ollama_model =
                                    ollama::pull(cloned_context, cloned_ollama_model).await;

                                if let Err(e) = ollama_model {
                                    tracing::error!("Error: {:?}", e);
                                }
                            });
                        }
                    }
                }
            }
        }

        let model: std::result::Result<Model, serde_json::error::Error> =
            serde_json::from_value(value);

        if let Ok(model) = model {
            if let Some(name) = model.name {
                if name.starts_with("ollama:") {
                    let model_name = name
                        .strip_prefix("ollama:")
                        .ok_or(AppError::Parsing)?
                        .to_string();

                    let ollama_model_exists = context
                        .octopus_database
                        .try_get_ollama_model_by_name(&model_name)
                        .await?;

                    if ollama_model_exists.is_none() {
                        let mut transaction = context.octopus_database.transaction_begin().await?;

                        let ollama_model = context
                            .octopus_database
                            .insert_ollama_model(&mut transaction, &model_name)
                            .await?;

                        context
                            .octopus_database
                            .transaction_commit(transaction)
                            .await?;

                        let cloned_context = context.clone();
                        let cloned_ollama_model = ollama_model.clone();
                        tokio::spawn(async move {
                            let ollama_model =
                                ollama::pull(cloned_context, cloned_ollama_model).await;

                            if let Err(e) = ollama_model {
                                tracing::error!("Error: {:?}", e);
                            }
                        });
                    }
                }
            }
        }
    }

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

        let display_name = match function.display_name {
            None => Some(formatted_name.replace('_', " ")),
            Some(display_name) => Some(display_name),
        };

        let generated_description =
            if let Some(ref describe_functions_response) = describe_functions_response {
                let generated_description = describe_functions_response
                    .functions
                    .iter()
                    .filter(|x| x.name == Some(function.name.clone()))
                    .map(|x| x.description.clone())
                    .collect::<Option<String>>();

                if let Some(mut generated_description) = generated_description {
                    generated_description.truncate(1024);

                    Some(generated_description)
                } else {
                    None
                }
            } else {
                None
            };

        match ai_function_exists {
            None => {
                context
                    .octopus_database
                    .insert_ai_function(
                        &mut transaction,
                        ai_service.id,
                        &function.description,
                        display_name,
                        &formatted_name,
                        generated_description,
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
                        &mut transaction,
                        ai_function_exists.id,
                        &function.description,
                        &formatted_name,
                        generated_description,
                        &function.name,
                        function.parameters,
                        AiFunctionRequestContentType::from_str(&request_content_type)?,
                        AiFunctionResponseContentType::from_str(&response_content_type)?,
                    )
                    .await?;
            }
        }
    }

    context
        .octopus_database
        .transaction_commit(transaction)
        .await?;

    Ok(ai_service)
}

pub async fn ai_service_replace_device_map(
    ai_service: AiService,
    context: Arc<Context>,
) -> Result<AiService> {
    let device_map = ai_service.device_map.clone().ok_or(AppError::Parsing)?;
    let processed_function_body = ai_service
        .processed_function_body
        .clone()
        .ok_or(AppError::Parsing)?;
    let mut code_lines = vec![];
    for line in processed_function_body.split('\n') {
        code_lines.push(line.to_string());
    }

    let server_resources = server_resources::get()?;

    let device_map_hash_map: HashMap<String, String> = serde_json::from_value(device_map)?;
    let mut device_map_new = HashMap::new();
    for (device_key, _device_value) in device_map_hash_map {
        let memory = server_resources.device_map.get(&device_key);

        if let Some(memory) = memory {
            device_map_new.insert(device_key, memory);
        }
    }

    let device_map = serde_json::to_value(device_map_new)?;
    code_lines = replacers::replace_device_map(code_lines, &device_map.clone());

    let processed_function_body = code_lines.join("\n");

    let mut transaction = context.octopus_database.transaction_begin().await?;

    let ai_service = context
        .octopus_database
        .update_ai_service_device_map_and_processed_function_body(
            &mut transaction,
            ai_service.id,
            device_map,
            &processed_function_body,
        )
        .await?;

    context
        .octopus_database
        .transaction_commit(transaction)
        .await?;

    Ok(ai_service)
}
