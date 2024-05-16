use crate::{
    ai::function_call::{function_call, AiFunctionResponse},
    context::Context,
    entity::{AiServiceHealthCheckStatus, AiServiceSetupStatus, AiServiceStatus},
    Result,
};
use fantoccini::ClientBuilder;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub async fn scraper(context: Arc<Context>, url: &str) -> Result<String> {
    if !context.get_config().await?.test_mode {
        if let Some(web_driver_url) = context.get_config().await?.web_driver_url {
            let client = ClientBuilder::native().connect(&web_driver_url).await?;

            client.goto(url).await?;

            let source = client.source().await?;

            client.close().await?;

            return Ok(source);
        }
    }

    Ok(String::new())
}

#[derive(Deserialize, Serialize)]
pub struct ScraperPost {
    url: String,
}

#[derive(Deserialize, Serialize)]
pub struct SearchPost {
    search_prompt: String,
}

pub async fn scraper_search_service(context: Arc<Context>, prompt: &str) -> Result<String> {
    if !context.get_config().await?.test_mode {
        let ai_function = context
            .octopus_database
            .try_get_ai_function_for_direct_call("google_search")
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
                    let search_post = SearchPost {
                        search_prompt: prompt.to_string(),
                    };
                    let function_args = serde_json::to_value(search_post)?;

                    let ai_function_response =
                        function_call(&ai_function, &ai_service, &function_args).await?;

                    if let Some(ai_function_response) = ai_function_response {
                        match ai_function_response {
                            AiFunctionResponse::Mixed(ai_function_text_responses) => {
                                for ai_function_text_response in ai_function_text_responses {
                                    if let AiFunctionResponse::Text(ai_function_text_response) =
                                        ai_function_text_response
                                    {
                                        if let Some(response) = ai_function_text_response.response {
                                            return Ok(response);
                                        }
                                    }
                                }
                            }
                            AiFunctionResponse::Text(ai_function_text_response) => {
                                if let Some(response) = ai_function_text_response.response {
                                    return Ok(response);
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
    }

    Ok(String::new())
}

pub async fn scraper_service(context: Arc<Context>, url: &str) -> Result<String> {
    if !context.get_config().await?.test_mode {
        let ai_function = context
            .octopus_database
            .try_get_ai_function_for_direct_call("scrape_url")
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
                    let scraper_post = ScraperPost {
                        url: url.to_string(),
                    };
                    let function_args = serde_json::to_value(scraper_post)?;

                    let ai_function_response =
                        function_call(&ai_function, &ai_service, &function_args).await?;

                    if let Some(ai_function_response) = ai_function_response {
                        match ai_function_response {
                            AiFunctionResponse::Mixed(ai_function_text_responses) => {
                                for ai_function_text_response in ai_function_text_responses {
                                    if let AiFunctionResponse::Text(ai_function_text_response) =
                                        ai_function_text_response
                                    {
                                        if let Some(response) = ai_function_text_response.response {
                                            return Ok(response);
                                        }
                                    }
                                }
                            }
                            AiFunctionResponse::Text(ai_function_text_response) => {
                                if let Some(response) = ai_function_text_response.response {
                                    return Ok(response);
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
    }

    Ok(String::new())
}
