use crate::{
    ai::{
        code_tools,
        function_call::{function_call, AiFunctionResponse},
    },
    context::Context,
    entity::{
        AiServiceGenerator, AiServiceGeneratorStatus, AiServiceHealthCheckStatus,
        AiServiceSetupStatus, AiServiceStatus,
    },
    get_pwd, Result, SERVICES_SAMPLES_DIR,
};
use serde::Serialize;
use std::{
    fs::{read_dir, read_to_string},
    sync::Arc,
};

#[derive(Debug, Serialize)]
pub struct InternetResearchAgentPost {
    pub full_prompt: String,
}

pub async fn generate(
    ai_service_generator: AiServiceGenerator,
    context: Arc<Context>,
    skip_internet_research_results: bool,
    skip_regenerate_internet_research_results: bool,
) -> Result<AiServiceGenerator> {
    let ai_service_generator = if (ai_service_generator.internet_research_results.is_none()
        || (ai_service_generator.internet_research_results.is_some()
            && !skip_regenerate_internet_research_results))
        && !skip_internet_research_results
    {
        let prompt = format!("Provide internet research that will be needed to create a Python, Flask based service aplication named: {} with the following description: {}", ai_service_generator.name, ai_service_generator.description);
        let mut internet_research_results = None;

        let ai_function = context
            .octopus_database
            .try_get_ai_function_for_direct_call("internet_research_agent")
            .await?;

        if let Some(ai_function) = ai_function {
            let ai_service = context
                .octopus_database
                .try_get_ai_service_by_id(ai_function.ai_service_id)
                .await?;

            if let Some(ai_service) = ai_service {
                if ai_function.is_enabled
                    && ai_service.is_enabled
                    && ai_service.health_check_status == AiServiceHealthCheckStatus::Ok
                    && ai_service.setup_status == AiServiceSetupStatus::Performed
                    && ai_service.status == AiServiceStatus::Running
                {
                    let internet_research_agent_post = InternetResearchAgentPost {
                        full_prompt: prompt,
                    };
                    let function_args = serde_json::to_value(internet_research_agent_post)?;

                    let ai_function_response =
                        function_call(&ai_function, &ai_service, &function_args).await?;

                    if let Some(ai_function_response) = ai_function_response {
                        match ai_function_response {
                            AiFunctionResponse::Mixed(ai_function_responses) => {
                                for ai_function_response in ai_function_responses {
                                    if let AiFunctionResponse::Text(ai_function_text_response) =
                                        ai_function_response
                                    {
                                        if let Some(response) = ai_function_text_response.response {
                                            internet_research_results = Some(response)
                                        }
                                    }
                                }
                            }
                            AiFunctionResponse::Text(ai_function_text_response) => {
                                if let Some(response) = ai_function_text_response.response {
                                    internet_research_results = Some(response)
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        if let Some(internet_research_results) = internet_research_results {
            let mut transaction = context.octopus_database.transaction_begin().await?;

            let ai_service_generator = context
                .octopus_database
                .update_ai_service_generator_internet_research_results(
                    &mut transaction,
                    ai_service_generator.id,
                    &internet_research_results,
                )
                .await?;

            context
                .octopus_database
                .transaction_commit(transaction)
                .await?;

            ai_service_generator
        } else {
            ai_service_generator
        }
    } else {
        ai_service_generator
    };

    let pwd = get_pwd()?;

    let mut sample_services = vec![];
    let sample_services_dir_path = format!("{pwd}/{SERVICES_SAMPLES_DIR}");

    match read_dir(sample_services_dir_path) {
        Err(_e) => {}
        Ok(read_dir) => {
            for dir_entry in read_dir {
                match dir_entry {
                    Err(_e) => {}
                    Ok(dir_entry) => {
                        let path_buff = dir_entry.path();
                        let content = read_to_string(path_buff)?;
                        sample_services.push(content);
                    }
                }
            }
        }
    }

    let original_function_body = code_tools::open_ai_create_ai_service(
        context.clone(),
        &ai_service_generator.description,
        ai_service_generator.internet_research_results.clone(),
        ai_service_generator.sample_code.clone(),
        &sample_services,
        skip_internet_research_results,
    )
    .await?;

    let ai_service_generator = if let Some(original_function_body) = original_function_body {
        let mut transaction = context.octopus_database.transaction_begin().await?;

        let ai_service_generator = context
            .octopus_database
            .update_ai_service_generator_original_function_body(
                &mut transaction,
                ai_service_generator.id,
                &original_function_body,
                AiServiceGeneratorStatus::Generated,
            )
            .await?;

        context
            .octopus_database
            .transaction_commit(transaction)
            .await?;

        ai_service_generator
    } else {
        ai_service_generator
    };

    Ok(ai_service_generator)
}
