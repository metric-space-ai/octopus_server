use crate::{
    Result,
    ai::open_ai::{AiClient, PRIMARY_MODEL, open_ai_get_client},
    context::Context,
    entity::ScheduledPrompt,
    error::AppError,
    parser::configuration::Configuration,
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
    #[allow(dead_code)]
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
    #[allow(dead_code)]
    pub reason: Option<String>,
}

pub async fn open_ai_create_ai_service(
    context: Arc<Context>,
    description: &str,
    internet_research_results: Option<String>,
    sample_code: Option<String>,
    sample_services: &[String],
    skip_internet_research_results: bool,
) -> Result<Option<String>> {
    let mut messages = vec![];

    let mut text = String::new();

    text.push_str(r#"I will give you a set of example code, a user input and optionally an internet search result and optionally sample code from user to do the task. Generate me now a matching python code. It is important to build the app like this. Make sure you use latest Flask version. Use only "application/json" as "input_type" and "return_type". Only output the final python file in markdown. Do not explain yourself.\n\n"#);

    text.push_str(r#"Here is a desired response format for Flask Python service: {"response": string, "file_attachments": [{"content": string, "file_name": string, "media_type": string}]} both response and file_attachments fields are optional. Make sure that response field is always string. Convert numbers to string. Convert arrays to string. You can use both response and file_attachments in case you want to save both text response and files. You can send only response field or only file_attachments. content field in file_attachments must be base64 encoded. Even if you want to save plain text file, make sure that you encode it with base64. Also binary files like mp3, png, jpg must be encoded with base64. Setup endpoint should have the following response format {"setup": "Performed"}\n\n"#);

    text.push_str(
        "Make sure that you place imports from installed libraries after installation section.\n\n",
    );

    text.push_str("Make sure that you have a proper imports for all used functions.\n\n");

    text.push_str(r#"When generating code related to OpenAI make sure that you use OPENAI_API_KEY ENV value. You can just define client this way client = OpenAI(). Also make sure that you have a proper "models": {"model": "gpt-4o-mini-2024-07-18"} section in service configuration.\n\n"#);

    text.push_str(r#"When generating configuration related to AI models make sure that you have a proper "models" definition like "models": {"model": "microsoft/Phi-3-vision-128k-instruct"} section in service configuration. Don't use outdated "model_setup". Convert "model_setup" to "models".\n\n"#);

    text.push_str(r#"When user wants to use Ollama make sure that you use OLLAMA_HOST enviromental variable for host url. When generating configuration related to Ollama AI models make sure that you have a proper "models" definition like "models": [{"name": "ollama:llama3:8b"}, {"name": "ollama:qwen2:7b"}] section in service configuration. This list of Ollama models will allow octopus_server to pre pull models that are desired by AI service on server start. Generated service should use ollama Python library. If user provided sample Ollama code make sure that you follow samples.\n\n"#);

    text.push_str(
        "When a user wants to use the scraper make sure that you thread all scraped data as HTML.\n\n",
    );

    text.push_str(
        "When a user wants to use Nextcloud make sure that you use NC_USERNAME, NC_URL and NC_PASSWORD environment variables values to access it. Use nc_py_api library for Nextcloud.\n\n",
    );

    text.push_str(
        "Make sure you don't use a names longer than 28 chars for API functions names.\n\n",
    );

    text.push_str(
        "When using a temporary files make sure that you use randomized names that don't collide with other names.\n\n",
    );

    text.push_str(
        r#"Make sure that everything related to AI model load/setup is done in setup endpoint. Make sure to import subprocess. Make sure you use a correct information about CUDA/CPU device selected by user and defined in device_map section in configuration. Make sure you use .to(device) when its needed. Use code similar to the following to select a proper device:
def command_result_as_int(command):
    return int(subprocess.check_output(command, shell=True).decode('utf-8').strip())

def select_device_with_larger_free_memory(available_devices):
    device = None
    memory = 0

    for available_device in available_devices:
        id = available_device.split(":")
        id = id[-1]
        try:
            free_memory = self.command_result_as_int(f"nvidia-smi --query-gpu=memory.free --format=csv,nounits,noheader --id={id}")
            if free_memory > memory:
                memory = free_memory
                device = available_device
        except:
            print(f"problem with executing nvidia-smi --query-gpu=memory.free --format=csv,nounits,noheader --id={id}")

    return device if device else "cpu"

def select_device():
    if not torch.cuda.is_available():
        return "cpu"

    device_map = config.get('device_map', {})
    available_devices = list(device_map.keys())
    return select_device_with_larger_free_memory(available_devices)

device = select_device()"#,
    );

    text.push_str("Here is a list of example templates that demonstrate how to build a plugin for the octopus system:");

    for sample_service in sample_services {
        let sample = format!("\n\n\nSample:\n\n{sample_service}");
        text.push_str(&sample);
    }

    text.push_str(&format!("\n\n\nHere is the user input:\n\n{description}"));

    if let Some(sample_code) = sample_code {
        text.push_str(&format!(
            "\n\n\nHere is the sample code provided by user. In terms of used libraries try to reuse as much technology as you can:\n\n{sample_code}"
        ));
    }

    if !skip_internet_research_results {
        if let Some(internet_research_results) = internet_research_results {
            text.push_str(&format!("\n\n\nHere is the internet research with addition information to do the task:\n\n{internet_research_results}"));
        }
    }

    let chat_completion_request_message = ChatCompletionRequestUserMessageArgs::default()
        .content(text)
        .build()?;

    messages.push(ChatCompletionRequestMessage::User(
        chat_completion_request_message,
    ));

    let ai_system_prompt = context
        .get_config()
        .await?
        .get_parameter_main_llm_system_prompt();

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
        return Ok(Some(String::new()));
    }

    let ai_client = open_ai_get_client(context.clone()).await?;

    let main_llm_openai_primary_model = context
        .get_config()
        .await?
        .get_parameter_main_llm_openai_primary_model()
        .unwrap_or(PRIMARY_MODEL.to_string());

    let request = CreateChatCompletionRequestArgs::default()
        .model(main_llm_openai_primary_model)
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
                                let response_content = if response_content.starts_with("```python")
                                    && response_content.ends_with("```")
                                {
                                    response_content
                                        .strip_prefix("```python")
                                        .ok_or(AppError::Parsing)?
                                        .to_string()
                                        .strip_suffix("```")
                                        .ok_or(AppError::Parsing)?
                                        .to_string()
                                } else if response_content.starts_with("```markdown")
                                    && response_content.ends_with("```")
                                {
                                    response_content
                                        .strip_prefix("```markdown")
                                        .ok_or(AppError::Parsing)?
                                        .to_string()
                                        .strip_suffix("```")
                                        .ok_or(AppError::Parsing)?
                                        .to_string()
                                } else {
                                    response_content
                                };

                                return Ok(Some(response_content));
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(None)
}

pub async fn open_ai_describe_functions(
    code: &str,
    configuration: &Configuration,
    context: Arc<Context>,
) -> Result<Option<DescribeFunctionsResponse>> {
    let mut messages = vec![];

    let mut text = String::new();

    text.push_str(r#"I will give you a system prompt and descriptions and the corresponding codes for several functions. I like to use them for openAI Function Calling API.The descriptions might be not good as they are in the context of the system prompt. Please optimize and extend the description for me, so that they are not too generic neither specific and do not fight with each others. Also add up to 3 examples, when the function should be called as well as in which cases the functions should not be called. This is important to avoid conflict with other functions or the user expects no function calling. Also add a debug information for the developer of the function in the case he did not provide sufficient information what the function is actually doing in regard of the source of information that the function is using in the background that makes it not clear, how it is related to the whole application. Make sure that description is below 1024 chars. Give me a list of the optimized config_str entities "functions.name" and "functions.description" as well as "functions.debug" in the format:config_str = '{
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
    Just give me the json, nothing else. Do not explain yourself. {code}"#
    ));

    let chat_completion_request_message = ChatCompletionRequestUserMessageArgs::default()
        .content(text)
        .build()?;

    messages.push(ChatCompletionRequestMessage::User(
        chat_completion_request_message,
    ));

    let ai_system_prompt = context
        .get_config()
        .await?
        .get_parameter_main_llm_system_prompt();

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

    let ai_client = open_ai_get_client(context.clone()).await?;

    let main_llm_openai_primary_model = context
        .get_config()
        .await?
        .get_parameter_main_llm_openai_primary_model()
        .unwrap_or(PRIMARY_MODEL.to_string());

    let request = CreateChatCompletionRequestArgs::default()
        .model(main_llm_openai_primary_model)
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

    let ai_client = open_ai_get_client(context.clone()).await?;

    let main_llm_openai_primary_model = context
        .get_config()
        .await?
        .get_parameter_main_llm_openai_primary_model()
        .unwrap_or(PRIMARY_MODEL.to_string());

    let request = CreateChatCompletionRequestArgs::default()
        .model(main_llm_openai_primary_model)
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
    let mut messages = vec![];

    let text = "you check python source code of a flask app. you response a json with {{\"is_passed\": true}} or {{\"is_passed\": false, \"reason\": <enter the reason here>, \"fixing_proposal\": <enter a proposal to fix here>}}. Make sure your resonse is a valid JSON. Regard only the given questions or instructions in the prompt and always return only a json.".to_string();

    let chat_completion_request_message = ChatCompletionRequestSystemMessageArgs::default()
        .content(text)
        .build()?;

    messages.push(ChatCompletionRequestMessage::System(
        chat_completion_request_message,
    ));

    let text = format!(
        "Check the code for the following problems. Is there a config_str definition with valid json of transformers 'device_map' definition? Check, if the device_map has valid keys and as well as if the values are valid for transformers device map. Syntax Errors. Check for syntax errors by running the code or using static analysis tools like pylint or flake8. Suggestion. Correct any syntax errors reported by the interpreter or static analysis tools. Code Style. Check for adherence to PEP 8 guidelines or any other coding standards used in the project. Suggestion. Refactor code to follow the established coding style. Variable Naming. Ensure meaningful and consistent variable names are used throughout the code. Suggestion. Rename variables for clarity if needed. Unused Variables. Identify variables that are defined but never used in the code. Suggestion. Remove or refactor unused variables. Unused Imports. Detect imports that are not used in the code. Suggestion. Remove unnecessary imports to improve code readability and performance. Code Duplication. Identify duplicate code blocks that can be refactored into functions or classes. Suggestion. Refactor duplicate code into reusable functions or classes to improve maintainability. Error Handling. Check for appropriate error handling mechanisms such as try-except blocks or custom error messages. Suggestion. Implement error handling to gracefully handle exceptions and provide informative error messages. Memory Management. Look for memory leaks or inefficient memory usage patterns, especially in long-running processes. Suggestion. Use context managers or explicit memory management techniques to optimize memory usage. Performance Bottlenecks. Identify areas of the code that may be causing performance bottlenecks or inefficiencies. Suggestion. Profile the code using tools like cProfile or line_profiler to pinpoint performance issues and optimize critical sections. Security Vulnerabilities. Scan for potential security vulnerabilities such as SQL injection, cross-site scripting (XSS), or insecure file operations. Suggestion. Follow security best practices and sanitize inputs to prevent common security vulnerabilities. Compatibility. Verify that the code is compatible with different Python versions and dependencies. Suggestion. Use tools like tox or virtual environments to test compatibility across multiple Python versions. Concurrency and Parallelism. Assess whether the code can benefit from concurrency or parallelism to improve performance. Suggestion. Consider using threading, multiprocessing, or asynchronous programming techniques where applicable. Code Complexity. Analyze the complexity of the code using metrics such as cyclomatic complexity or nesting depth. Suggestion. Refactor complex code into smaller, more manageable components to improve readability and maintainability. Identify places in code that may need additional error handling to work reliable in network environment.\n\n {code}"
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

    let ai_client = open_ai_get_client(context.clone()).await?;

    let main_llm_openai_primary_model = context
        .get_config()
        .await?
        .get_parameter_main_llm_openai_primary_model()
        .unwrap_or(PRIMARY_MODEL.to_string());

    let request = CreateChatCompletionRequestArgs::default()
        .model(main_llm_openai_primary_model)
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
    let mut messages = vec![];

    let text = "you check python source code of a flask app. you response a json with {{\"is_passed\": true}} or {{\"is_passed\": false, \"reason\": <enter the reason here>, \"fixing_proposal\": <enter a proposal to fix here>}}. Make sure your resonse is a valid JSON. Regard only the given questions or instructions in the prompt and always return only a json.".to_string();

    let chat_completion_request_message = ChatCompletionRequestSystemMessageArgs::default()
        .content(text)
        .build()?;

    messages.push(ChatCompletionRequestMessage::System(
        chat_completion_request_message,
    ));

    let text = format!(
        "Check the code for the following problems. Is there a config_str definition with valid json of transformers 'device_map' definition? Check, if the device_map has valid keys and as well as if the values are valid for transformers device map. Syntax Errors. Check for syntax errors by running the code or using static analysis tools like pylint or flake8. Suggestion. Correct any syntax errors reported by the interpreter or static analysis tools. Code Style. Check for adherence to PEP 8 guidelines or any other coding standards used in the project. Suggestion. Refactor code to follow the established coding style. Variable Naming. Ensure meaningful and consistent variable names are used throughout the code. Suggestion. Rename variables for clarity if needed. Unused Variables. Identify variables that are defined but never used in the code. Suggestion. Remove or refactor unused variables. Unused Imports. Detect imports that are not used in the code. Suggestion. Remove unnecessary imports to improve code readability and performance. Code Duplication. Identify duplicate code blocks that can be refactored into functions or classes. Suggestion. Refactor duplicate code into reusable functions or classes to improve maintainability. Error Handling. Check for appropriate error handling mechanisms such as try-except blocks or custom error messages. Suggestion. Implement error handling to gracefully handle exceptions and provide informative error messages. Memory Management. Look for memory leaks or inefficient memory usage patterns, especially in long-running processes. Suggestion. Use context managers or explicit memory management techniques to optimize memory usage. Performance Bottlenecks. Identify areas of the code that may be causing performance bottlenecks or inefficiencies. Suggestion. Profile the code using tools like cProfile or line_profiler to pinpoint performance issues and optimize critical sections. Security Vulnerabilities. Scan for potential security vulnerabilities such as SQL injection, cross-site scripting (XSS), or insecure file operations. Suggestion. Follow security best practices and sanitize inputs to prevent common security vulnerabilities. Compatibility. Verify that the code is compatible with different Python versions and dependencies. Suggestion. Use tools like tox or virtual environments to test compatibility across multiple Python versions. Concurrency and Parallelism. Assess whether the code can benefit from concurrency or parallelism to improve performance. Suggestion. Consider using threading, multiprocessing, or asynchronous programming techniques where applicable. Code Complexity. Analyze the complexity of the code using metrics such as cyclomatic complexity or nesting depth. Suggestion. Refactor complex code into smaller, more manageable components to improve readability and maintainability. Identify places in code that may need additional error handling to work reliable in network environment.\n\n {code}"
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

    let ai_client = open_ai_get_client(context.clone()).await?;

    let main_llm_openai_primary_model = context
        .get_config()
        .await?
        .get_parameter_main_llm_openai_primary_model()
        .unwrap_or(PRIMARY_MODEL.to_string());

    let request = CreateChatCompletionRequestArgs::default()
        .model(main_llm_openai_primary_model)
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
pub struct ScheduledPromptsSchedule {
    pub schedule_time: String,
}

pub async fn open_ai_scheduled_prompts_schedule(
    context: Arc<Context>,
    scheduled_prompt: ScheduledPrompt,
) -> Result<ScheduledPrompt> {
    let mut messages = vec![];

    let text = r#"User provides schedule time for a prompt. Convert this schedule time to the following format "minutes; hours; day of month; month; day of week; year" that is similar to cron. Convert semicolons to spaces. Make sure you use specified format, not default cron. Make sure you understand provided format - it starts with minutes and you need to use all 6 fields. You response a json with {{\"schedule_time\": string}}. Make sure your resonse is a valid JSON. Regard only the given questions or instructions in the prompt and always return only a json."#.to_string();

    let chat_completion_request_message = ChatCompletionRequestSystemMessageArgs::default()
        .content(text)
        .build()?;

    messages.push(ChatCompletionRequestMessage::System(
        chat_completion_request_message,
    ));

    let text = "Here are a few examples:\n\n
    At minute 1 - 1 * * * * *\n
    At minute 10 - 10 * * * * *\n
    At minute 45 - 45 * * * * *\n
    At every 5th minute from 0 through 59 - 0/5 * * * * *\n
    At every 10th minute from 0 through 59 - 0/10 * * * * *\n
    At every 15th minute from 0 through 59 - 0/15 * * * * *\n
    At 01:00 - 0 1 * * * *\n
    At 05:00 - 0 5 * * * *\n
    At 15:00 - 0 15 * * * *\n
    At minute 0 past every 2nd hour from 0 through 23 - 0 0/2 * * * *\n
    At minute 0 past every 4th hour from 0 through 23 - 0 0/4 * * * *\n
    At minute 0 past every 6th hour from 0 through 23 - 0 0/6 * * * *\n
    At 00:00 on day-of-month 1 - 0 0 1 * * *\n
    At 00:00 on day-of-month 10 - 0 0 10 * * *\n
    At 00:00 on day-of-month 22 - 0 0 22 * * *\n
    At 00:00 on every 2nd day-of-month from 1 through 31 - 0 0 1/2 * * *\n
    At 00:00 on every 4th day-of-month from 1 through 31 - 0 0 1/4 * * *\n
    At 00:00 on every 7th day-of-month from 1 through 31 - 0 0 1/7 * * *\n
    At 00:00 in January - 0 0 * 1 * *\n
    At 00:00 in April - 0 0 * 4 * *\n
    At 00:00 in August - 0 0 * 8 * *\n
    At 00:00 in every 2nd month from January through December - 0 0 * 1/2 * *\n
    At 00:00 in every 3rd month from January through December - 0 0 * 1/3 * *\n
    At 00:00 in every 4th month from January through December - 0 0 * 1/4 * *\n
    At 10:13 on day-of-month 23 in June - 13 10 23 6 * *\n
    At 13:44 on day-of-month 19 in September - 44 13 19 9 * *\n
    At 09:45 on day-of-month 12 in December - 45 09 12 12 * *\n
    At 03:25 on day-of-month 16 in December - 25 03 16 12 * *\n
    At 00:00 on Monday - 0 0 * * 1 *\n
    At 00:00 on Tuesday - 0 0 * * 2 *\n
    At 00:00 on Friday - 0 0 * * 5 *\n
    \nHere is desired user schedule that you need to convert:"
        .to_string();

    let chat_completion_request_message = ChatCompletionRequestSystemMessageArgs::default()
        .content(text)
        .build()?;

    messages.push(ChatCompletionRequestMessage::System(
        chat_completion_request_message,
    ));

    let text = scheduled_prompt.desired_schedule.clone();

    let chat_completion_request_message = ChatCompletionRequestUserMessageArgs::default()
        .content(text)
        .build()?;

    messages.push(ChatCompletionRequestMessage::User(
        chat_completion_request_message,
    ));

    if context.get_config().await?.test_mode {
        return Ok(scheduled_prompt);
    }

    let ai_client = open_ai_get_client(context.clone()).await?;

    let main_llm_openai_primary_model = context
        .get_config()
        .await?
        .get_parameter_main_llm_openai_primary_model()
        .unwrap_or(PRIMARY_MODEL.to_string());

    let request = CreateChatCompletionRequestArgs::default()
        .model(main_llm_openai_primary_model)
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

                                let scheduled_prompts_schedule: ScheduledPromptsSchedule =
                                    serde_json::from_str(&response_content)?;

                                let mut transaction =
                                    context.octopus_database.transaction_begin().await?;

                                let scheduled_prompt = context
                                    .octopus_database
                                    .update_scheduled_prompt_schedule(
                                        &mut transaction,
                                        scheduled_prompt.id,
                                        &scheduled_prompts_schedule.schedule_time,
                                    )
                                    .await?;

                                context
                                    .octopus_database
                                    .transaction_commit(transaction)
                                    .await?;

                                return Ok(scheduled_prompt);
                            }
                        }
                    }
                }
            }
        }
    }

    Err(Box::new(AppError::Parsing))
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

    let ai_client = open_ai_get_client(context.clone()).await?;

    let main_llm_openai_primary_model = context
        .get_config()
        .await?
        .get_parameter_main_llm_openai_primary_model()
        .unwrap_or(PRIMARY_MODEL.to_string());

    let request = CreateChatCompletionRequestArgs::default()
        .model(main_llm_openai_primary_model)
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

    let ai_client = open_ai_get_client(context.clone()).await?;

    let main_llm_openai_primary_model = context
        .get_config()
        .await?
        .get_parameter_main_llm_openai_primary_model()
        .unwrap_or(PRIMARY_MODEL.to_string());

    let request = CreateChatCompletionRequestArgs::default()
        .model(main_llm_openai_primary_model)
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

    let ai_client = open_ai_get_client(context.clone()).await?;

    let main_llm_openai_primary_model = context
        .get_config()
        .await?
        .get_parameter_main_llm_openai_primary_model()
        .unwrap_or(PRIMARY_MODEL.to_string());

    let request = CreateChatCompletionRequestArgs::default()
        .model(main_llm_openai_primary_model)
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
