use crate::{
    ai::{open_ai_get_client, AiClient, MODEL128K},
    context::Context,
    error::AppError,
    Result,
};
use async_openai::types::{
    ChatCompletionRequestMessage, ChatCompletionRequestSystemMessageArgs,
    ChatCompletionRequestUserMessageArgs, CreateChatCompletionRequestArgs,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub async fn open_ai_malicious_code_check(code: &str, context: Arc<Context>) -> Result<bool> {
    let ai_client = open_ai_get_client(context.clone()).await?;

    let mut messages = vec![];

    let text = format!("Check if the following code contains sections that looks malicious and provide YES or NO answer {code}");

    let chat_completion_request_message = ChatCompletionRequestUserMessageArgs::default()
        .content(text)
        .build()?;

    messages.push(ChatCompletionRequestMessage::User(
        chat_completion_request_message,
    ));

    if !context.get_config().await?.test_mode {
        let request = CreateChatCompletionRequestArgs::default()
            .max_tokens(512u16)
            .model(MODEL128K)
            .messages(messages)
            .build();

        match request {
            Err(e) => {
                tracing::error!("OpenAIError: {e}");
            }
            Ok(request) => {
                let response_message = match ai_client {
                    AiClient::Azure(ai_client) => ai_client.chat().create(request).await,
                    AiClient::OpenAI(ai_client) => ai_client.chat().create(request).await,
                };

                match response_message {
                    Err(e) => {
                        tracing::error!("OpenAIError: {e}");
                    }
                    Ok(response_message) => {
                        let response_message = response_message.choices.first();

                        match response_message {
                            None => {
                                tracing::error!("BadResponse");
                            }
                            Some(response_message) => {
                                let response_message = response_message.message.clone();

                                if let Some(content) = response_message.content {
                                    if content == "YES" {
                                        return Ok(true);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(false)
}

#[derive(Debug, Deserialize)]
pub struct ParsingCodeCheckResponse {
    pub fixing_proposal: Option<String>,
    pub is_passed: bool,
    pub reason: Option<String>,
}

pub async fn open_ai_post_parsing_code_check(
    code: &str,
    context: Arc<Context>,
) -> Result<Option<ParsingCodeCheckResponse>> {
    let ai_client = open_ai_get_client(context.clone()).await?;

    let mut messages = vec![];

    let text = "you check python source code of a flask app. you response a json with {{\"is_passed\": true}} or {{\"is_passed\": false, \"reason\": <enter the reason here>, \"fixing_proposal\": <enter a proposal to fix here>}}. Make sure your resonse is a valid JSON. Regard only the given questions or instructions in the prompt and always return only a json.".to_string();

    let chat_completion_request_message = ChatCompletionRequestSystemMessageArgs::default()
        .content(text)
        .build()?;

    messages.push(ChatCompletionRequestMessage::System(
        chat_completion_request_message,
    ));

    let text = format!(
        "Is there a config_str definition with valid json of transformers 'device_map' definition? Check, if the device_map has valid keys and as well as if the values are valid for transformers device map.\n\n {code}"
    );

    let chat_completion_request_message = ChatCompletionRequestUserMessageArgs::default()
        .content(text)
        .build()?;

    messages.push(ChatCompletionRequestMessage::User(
        chat_completion_request_message,
    ));

    if context.get_config().await?.test_mode {
        let response = ParsingCodeCheckResponse {
            fixing_proposal: None,
            is_passed: true,
            reason: None,
        };

        return Ok(Some(response));
    }

    let request = CreateChatCompletionRequestArgs::default()
        .max_tokens(512u16)
        .model(MODEL128K)
        .messages(messages)
        .build();

    match request {
        Err(e) => {
            tracing::error!("OpenAIError: {e}");
        }
        Ok(request) => {
            let response_message = match ai_client {
                AiClient::Azure(ai_client) => ai_client.chat().create(request).await,
                AiClient::OpenAI(ai_client) => ai_client.chat().create(request).await,
            };

            match response_message {
                Err(e) => {
                    tracing::error!("OpenAIError: {e}");
                }
                Ok(response_message) => {
                    let response_message = response_message.choices.first();

                    match response_message {
                        None => {
                            tracing::error!("BadResponse");
                        }
                        Some(response_message) => {
                            let response_message = response_message.message.clone();

                            if let Some(response_content) = response_message.content {
                                let response_content = if response_content.starts_with("```json")
                                    && response_content.ends_with("```")
                                {
                                    response_content
                                        .strip_prefix("```json")
                                        .ok_or(AppError::Parsing)?
                                        .to_string()
                                        .strip_suffix("```")
                                        .ok_or(AppError::Parsing)?
                                        .to_string()
                                } else {
                                    response_content
                                };

                                let response: std::result::Result<
                                    ParsingCodeCheckResponse,
                                    serde_json::error::Error,
                                > = serde_json::from_str(&response_content);

                                match response {
                                    Err(_) => return Ok(None),
                                    Ok(response) => {
                                        return Ok(Some(response));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(None)
}

pub async fn open_ai_pre_parsing_code_check(
    code: &str,
    context: Arc<Context>,
) -> Result<Option<ParsingCodeCheckResponse>> {
    let ai_client = open_ai_get_client(context.clone()).await?;

    let mut messages = vec![];

    let text = "you check python source code of a flask app. you response a json with {{\"is_passed\": true}} or {{\"is_passed\": false, \"reason\": <enter the reason here>, \"fixing_proposal\": <enter a proposal to fix here>}}. Make sure your resonse is a valid JSON. Regard only the given questions or instructions in the prompt and always return only a json.".to_string();

    let chat_completion_request_message = ChatCompletionRequestSystemMessageArgs::default()
        .content(text)
        .build()?;

    messages.push(ChatCompletionRequestMessage::System(
        chat_completion_request_message,
    ));

    let text = format!(
        "Is there a config_str definition with valid json of transformers 'device_map' definition? Check, if the device_map has valid keys and as well as if the values are valid for transformers device map.\n\n {code}"
    );

    let chat_completion_request_message = ChatCompletionRequestUserMessageArgs::default()
        .content(text)
        .build()?;

    messages.push(ChatCompletionRequestMessage::User(
        chat_completion_request_message,
    ));

    if context.get_config().await?.test_mode {
        let response = ParsingCodeCheckResponse {
            fixing_proposal: None,
            is_passed: true,
            reason: None,
        };

        return Ok(Some(response));
    }

    let request = CreateChatCompletionRequestArgs::default()
        .max_tokens(512u16)
        .model(MODEL128K)
        .messages(messages)
        .build();

    match request {
        Err(e) => {
            tracing::error!("OpenAIError: {e}");
        }
        Ok(request) => {
            let response_message = match ai_client {
                AiClient::Azure(ai_client) => ai_client.chat().create(request).await,
                AiClient::OpenAI(ai_client) => ai_client.chat().create(request).await,
            };

            match response_message {
                Err(e) => {
                    tracing::error!("OpenAIError: {e}");
                }
                Ok(response_message) => {
                    let response_message = response_message.choices.first();

                    match response_message {
                        None => {
                            tracing::error!("BadResponse");
                        }
                        Some(response_message) => {
                            let response_message = response_message.message.clone();

                            if let Some(response_content) = response_message.content {
                                let response_content = if response_content.starts_with("```json")
                                    && response_content.ends_with("```")
                                {
                                    response_content
                                        .strip_prefix("```json")
                                        .ok_or(AppError::Parsing)?
                                        .to_string()
                                        .strip_suffix("```")
                                        .ok_or(AppError::Parsing)?
                                        .to_string()
                                } else {
                                    response_content
                                };

                                let response: std::result::Result<
                                    ParsingCodeCheckResponse,
                                    serde_json::error::Error,
                                > = serde_json::from_str(&response_content);

                                match response {
                                    Err(_) => return Ok(None),
                                    Ok(response) => {
                                        return Ok(Some(response));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(None)
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SimpleAppMeta {
    pub description: String,
    pub title: String,
}

pub async fn open_ai_simple_app_meta_extraction(
    code: &str,
    context: Arc<Context>,
) -> Result<SimpleAppMeta> {
    let ai_client = open_ai_get_client(context.clone()).await?;

    let mut messages = vec![];

    let text = "you extract title and description from the HTML code. you response a json with {{\"title\": string, \"description\": string}}. Make sure your resonse is a valid JSON. Regard only the given questions or instructions in the prompt and always return only a json.".to_string();

    let chat_completion_request_message = ChatCompletionRequestSystemMessageArgs::default()
        .content(text)
        .build()?;

    messages.push(ChatCompletionRequestMessage::System(
        chat_completion_request_message,
    ));

    let text = code.to_string();

    let chat_completion_request_message = ChatCompletionRequestUserMessageArgs::default()
        .content(text)
        .build()?;

    messages.push(ChatCompletionRequestMessage::User(
        chat_completion_request_message,
    ));

    if context.get_config().await?.test_mode {
        let simple_app_meta = SimpleAppMeta {
            title: "test title".to_string(),
            description: "test description".to_string(),
        };

        return Ok(simple_app_meta);
    }

    let request = CreateChatCompletionRequestArgs::default()
        .max_tokens(512u16)
        .model(MODEL128K)
        .messages(messages)
        .build();

    match request {
        Err(e) => {
            tracing::error!("OpenAIError: {e}");
        }
        Ok(request) => {
            let response_message = match ai_client {
                AiClient::Azure(ai_client) => ai_client.chat().create(request).await,
                AiClient::OpenAI(ai_client) => ai_client.chat().create(request).await,
            };

            match response_message {
                Err(e) => {
                    tracing::error!("OpenAIError: {e}");
                }
                Ok(response_message) => {
                    let response_message = response_message.choices.first();

                    match response_message {
                        None => {
                            tracing::error!("BadResponse");
                        }
                        Some(response_message) => {
                            let response_message = response_message.message.clone();

                            if let Some(response_content) = response_message.content {
                                let response_content = if response_content.starts_with("```json")
                                    && response_content.ends_with("```")
                                {
                                    response_content
                                        .strip_prefix("```json")
                                        .ok_or(AppError::Parsing)?
                                        .to_string()
                                        .strip_suffix("```")
                                        .ok_or(AppError::Parsing)?
                                        .to_string()
                                } else {
                                    response_content
                                };

                                let simple_app_meta: SimpleAppMeta =
                                    serde_json::from_str(&response_content)?;

                                return Ok(simple_app_meta);
                            }
                        }
                    }
                }
            }
        }
    }

    Err(Box::new(AppError::Parsing))
}
