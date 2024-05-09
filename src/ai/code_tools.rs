use crate::{
    ai::{open_ai_get_client, AiClient, MODEL128K},
    context::Context,
    error::AppError,
    parser::configuration::Configuration,
    Result,
};
use async_openai::types::{
    ChatCompletionRequestMessage, ChatCompletionRequestSystemMessageArgs,
    ChatCompletionRequestUserMessageArgs, CreateChatCompletionRequestArgs,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use utoipa::ToSchema;

#[derive(Clone, Debug, Deserialize)]
pub struct DescribeFunctionResponse {
    pub name: Option<String>,
    pub description: Option<String>,
    pub debug: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct DescribeFunctionsResponse {
    pub functions: Vec<DescribeFunctionResponse>,
}

#[derive(Debug, Deserialize)]
pub struct ParsingCodeCheckResponse {
    pub fixing_proposal: Option<String>,
    pub is_passed: bool,
    pub reason: Option<String>,
}

pub async fn open_ai_describe_functions(
    code: &str,
    configuration: &Configuration,
    context: Arc<Context>,
) -> Result<Option<DescribeFunctionsResponse>> {
    let ai_client = open_ai_get_client(context.clone()).await?;

    let mut messages = vec![];

    let mut text = String::new();

    text.push_str(r#"I will give you a system prompt and descriptions and the corresponding codes for several functions. I like to use them for openAI Function Calling API.The descriptions might be not good as they are in the context of the system prompt. Please optimize and extend the description for me, so that they are not too generic neither specific and do not fight with each others. Also add up to 3 examples, when the function should be called as well as in which cases the functions should not be called. This is important to avoid conflict with other functions or the user expects no function calling. Also add a debug information for the developer of the function in the case he did not provide sufficient information what the function is actually doing in regard of the source of information that the function is using in the background that makes it not clear, how it is related to the whole application.Give me a list of the optimized config_str entities "functions.name" and "functions.description" as well as "functions.debug" in the format:config_str = '{
        "functions": ["#);

    for function in &configuration.functions {
        let function_doc = format!(
            r#"{{
                "name": "{}"
                "description": "<optimized description for {} in here as well as the positive and negative examples>",
                "debug": "<input questions for missing information for {} as effect of unsufficient information the user provided to write a proper description>",
              }},"#,
            function.name, function.name, function.name
        );
        text.push_str(&function_doc);
    }

    text.push_str(&format!(
        r#"]}}
    Just give me the json, nothing else. Do not explain yourself. {}"#,
        code
    ));

    let chat_completion_request_message = ChatCompletionRequestUserMessageArgs::default()
        .content(text)
        .build()?;

    messages.push(ChatCompletionRequestMessage::User(
        chat_completion_request_message,
    ));

    let ai_system_prompt = context.get_config().await?.get_parameter_ai_system_prompt();

    if let Some(ai_system_prompt) = ai_system_prompt {
        let chat_completion_request_system_message =
            ChatCompletionRequestSystemMessageArgs::default()
                .content(ai_system_prompt)
                .build()?;

        messages.push(ChatCompletionRequestMessage::System(
            chat_completion_request_system_message,
        ));
    }

    if context.get_config().await?.test_mode {
        let response = DescribeFunctionsResponse { functions: vec![] };

        return Ok(Some(response));
    }

    let request = CreateChatCompletionRequestArgs::default()
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
                                    DescribeFunctionsResponse,
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

pub async fn open_ai_malicious_code_check(
    code: &str,
    context: Arc<Context>,
) -> Result<Option<ParsingCodeCheckResponse>> {
    let ai_client = open_ai_get_client(context.clone()).await?;

    let mut messages = vec![];

    let text = "you check source code of an app. you response a json with {{\"is_passed\": true}} or {{\"is_passed\": false, \"reason\": <enter the reason here>, \"fixing_proposal\": <enter a proposal to fix here>}}. Make sure your resonse is a valid JSON. Regard only the given questions or instructions in the prompt and always return only a json.".to_string();

    let chat_completion_request_message = ChatCompletionRequestSystemMessageArgs::default()
        .content(text)
        .build()?;

    messages.push(ChatCompletionRequestMessage::System(
        chat_completion_request_message,
    ));

    let text = format!("Check if the following code contains sections that looks malicious {code}");

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
        "Check the code for the following problems. Is there a config_str definition with valid json of transformers 'device_map' definition? Check, if the device_map has valid keys and as well as if the values are valid for transformers device map. Syntax Errors. Check for syntax errors by running the code or using static analysis tools like pylint or flake8. Suggestion. Correct any syntax errors reported by the interpreter or static analysis tools. Code Style. Check for adherence to PEP 8 guidelines or any other coding standards used in the project. Suggestion. Refactor code to follow the established coding style. Variable Naming. Ensure meaningful and consistent variable names are used throughout the code. Suggestion. Rename variables for clarity if needed. Unused Variables. Identify variables that are defined but never used in the code. Suggestion. Remove or refactor unused variables. Unused Imports. Detect imports that are not used in the code. Suggestion. Remove unnecessary imports to improve code readability and performance. Code Duplication. Identify duplicate code blocks that can be refactored into functions or classes. Suggestion. Refactor duplicate code into reusable functions or classes to improve maintainability. Error Handling. Check for appropriate error handling mechanisms such as try-except blocks or custom error messages. Suggestion. Implement error handling to gracefully handle exceptions and provide informative error messages. Memory Management. Look for memory leaks or inefficient memory usage patterns, especially in long-running processes. Suggestion. Use context managers or explicit memory management techniques to optimize memory usage. Performance Bottlenecks. Identify areas of the code that may be causing performance bottlenecks or inefficiencies. Suggestion. Profile the code using tools like cProfile or line_profiler to pinpoint performance issues and optimize critical sections. Security Vulnerabilities. Scan for potential security vulnerabilities such as SQL injection, cross-site scripting (XSS), or insecure file operations. Suggestion. Follow security best practices and sanitize inputs to prevent common security vulnerabilities. Compatibility. Verify that the code is compatible with different Python versions and dependencies. Suggestion. Use tools like tox or virtual environments to test compatibility across multiple Python versions. Concurrency and Parallelism. Assess whether the code can benefit from concurrency or parallelism to improve performance. Suggestion. Consider using threading, multiprocessing, or asynchronous programming techniques where applicable. Code Complexity. Analyze the complexity of the code using metrics such as cyclomatic complexity or nesting depth. Suggestion. Refactor complex code into smaller, more manageable components to improve readability and maintainability.\n\n {code}"
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
        "Check the code for the following problems. Is there a config_str definition with valid json of transformers 'device_map' definition? Check, if the device_map has valid keys and as well as if the values are valid for transformers device map. Syntax Errors. Check for syntax errors by running the code or using static analysis tools like pylint or flake8. Suggestion. Correct any syntax errors reported by the interpreter or static analysis tools. Code Style. Check for adherence to PEP 8 guidelines or any other coding standards used in the project. Suggestion. Refactor code to follow the established coding style. Variable Naming. Ensure meaningful and consistent variable names are used throughout the code. Suggestion. Rename variables for clarity if needed. Unused Variables. Identify variables that are defined but never used in the code. Suggestion. Remove or refactor unused variables. Unused Imports. Detect imports that are not used in the code. Suggestion. Remove unnecessary imports to improve code readability and performance. Code Duplication. Identify duplicate code blocks that can be refactored into functions or classes. Suggestion. Refactor duplicate code into reusable functions or classes to improve maintainability. Error Handling. Check for appropriate error handling mechanisms such as try-except blocks or custom error messages. Suggestion. Implement error handling to gracefully handle exceptions and provide informative error messages. Memory Management. Look for memory leaks or inefficient memory usage patterns, especially in long-running processes. Suggestion. Use context managers or explicit memory management techniques to optimize memory usage. Performance Bottlenecks. Identify areas of the code that may be causing performance bottlenecks or inefficiencies. Suggestion. Profile the code using tools like cProfile or line_profiler to pinpoint performance issues and optimize critical sections. Security Vulnerabilities. Scan for potential security vulnerabilities such as SQL injection, cross-site scripting (XSS), or insecure file operations. Suggestion. Follow security best practices and sanitize inputs to prevent common security vulnerabilities. Compatibility. Verify that the code is compatible with different Python versions and dependencies. Suggestion. Use tools like tox or virtual environments to test compatibility across multiple Python versions. Concurrency and Parallelism. Assess whether the code can benefit from concurrency or parallelism to improve performance. Suggestion. Consider using threading, multiprocessing, or asynchronous programming techniques where applicable. Code Complexity. Analyze the complexity of the code using metrics such as cyclomatic complexity or nesting depth. Suggestion. Refactor complex code into smaller, more manageable components to improve readability and maintainability.\n\n {code}"
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

pub async fn open_ai_simple_app_advanced_meta_extraction(
    code: &str,
    context: Arc<Context>,
) -> Result<SimpleAppMeta> {
    let ai_client = open_ai_get_client(context.clone()).await?;

    let mut messages = vec![];

    let text = "you try to create a title and description for the app from given source code. you response a json with {{\"title\": string, \"description\": string}}. Make sure your resonse is a valid JSON. Regard only the given questions or instructions in the prompt and always return only a json.".to_string();

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

#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct WaspAppMeta {
    pub description: String,
    pub title: String,
}

pub async fn open_ai_wasp_app_advanced_meta_extraction(
    code: &str,
    context: Arc<Context>,
) -> Result<WaspAppMeta> {
    let ai_client = open_ai_get_client(context.clone()).await?;

    let mut messages = vec![];

    let text = "you try to create a title and description for the app from given source code. focus only on user visible features. do not mention technologies. you response a json with {{\"title\": string, \"description\": string}}. Make sure your resonse is a valid JSON. Regard only the given questions or instructions in the prompt and always return only a json.".to_string();

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
        let wasp_app_meta = WaspAppMeta {
            title: "test title".to_string(),
            description: "test description".to_string(),
        };

        return Ok(wasp_app_meta);
    }

    let request = CreateChatCompletionRequestArgs::default()
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

                                let wasp_app_meta: WaspAppMeta =
                                    serde_json::from_str(&response_content)?;

                                return Ok(wasp_app_meta);
                            }
                        }
                    }
                }
            }
        }
    }

    Err(Box::new(AppError::Parsing))
}
