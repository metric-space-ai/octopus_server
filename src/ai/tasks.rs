use crate::{
    Result,
    ai::open_ai::{AiClient, PRIMARY_MODEL, open_ai_get_client},
    context::Context,
    entity::{Task, TaskStatus, TaskTest, TaskType},
    error::AppError,
};
use async_openai::types::{
    ChatCompletionRequestMessage, ChatCompletionRequestUserMessageArgs,
    CreateChatCompletionRequestArgs,
};
use serde::Deserialize;
use std::sync::Arc;
use tracing::error;
use uuid::Uuid;

pub const PROMPT1: &str = "User needs to complete a task made by supervisor. Assist in completing task. Make sure that task was completed. Here is a description of the task:";

#[derive(Debug, Deserialize)]
pub struct ChatInfoResult {
    pub description: Option<String>,
    pub is_task: bool,
    pub is_test: bool,
    pub title: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ChatTaskInfoResult {
    pub task_description_message: String,
}

#[derive(Debug, Deserialize)]
pub struct ChatTaskResult {
    pub is_completed: bool,
}

#[derive(Debug, Deserialize)]
pub struct ChatTask2Result {
    pub is_completed: bool,
    pub test_result: String,
}

#[derive(Debug, Deserialize)]
pub struct ChatTestInfoResult {
    pub task_questions: Vec<TaskQuestion>,
}

#[derive(Debug)]
pub struct TaskInfo {
    pub description: Option<String>,
    pub task_description_message: Option<String>,
    pub task_questions: Vec<TaskQuestion>,
    pub title: Option<String>,
    pub r#type: TaskType,
}

#[derive(Clone, Debug, Deserialize)]
pub struct TaskQuestion {
    pub question: String,
}

#[derive(Debug, Deserialize)]
pub struct TaskTestResult {
    pub answer_is_correct: bool,
}

pub async fn check_task_result(context: Arc<Context>, chat_id: Uuid) -> Result<Option<Task>> {
    let all_task_messages = get_all_task_messages(context.clone(), chat_id).await?;
    let chat_task_result = get_chat_task_result(context.clone(), &all_task_messages).await?;

    if let Some(chat_task_result) = chat_task_result {
        if chat_task_result.is_completed {
            let task = context
                .octopus_database
                .try_get_task_by_assigned_user_chat_id(chat_id)
                .await?;

            if let Some(task) = task {
                let mut transaction = context.octopus_database.transaction_begin().await?;

                let task = context
                    .octopus_database
                    .update_task_status(&mut transaction, task.id, TaskStatus::Completed)
                    .await?;

                context
                    .octopus_database
                    .transaction_commit(transaction)
                    .await?;

                return Ok(Some(task));
            }
        }
    }

    Ok(None)
}

pub async fn check_task_result2(context: Arc<Context>, task_id: Uuid) -> Result<Option<Task>> {
    let task = context.octopus_database.try_get_task_by_id(task_id).await?;

    if let Some(task) = task {
        let all_task_messages = get_all_task_messages(context.clone(), task.chat_id).await?;
        let all_task_test_messages = get_all_task_test_messages2(context.clone(), task_id).await?;
        let chat_task_result =
            get_chat_task_result2(context.clone(), &all_task_messages, &all_task_test_messages)
                .await?;

        if let Some(chat_task_result) = chat_task_result {
            if chat_task_result.is_completed {
                let mut transaction = context.octopus_database.transaction_begin().await?;

                let task = context
                    .octopus_database
                    .update_task_status_and_test_result(
                        &mut transaction,
                        task.id,
                        TaskStatus::Completed,
                        &chat_task_result.test_result,
                    )
                    .await?;

                context
                    .octopus_database
                    .transaction_commit(transaction)
                    .await?;

                return Ok(Some(task));
            }
        }
    }

    Ok(None)
}

pub async fn check_task_test_result(
    context: Arc<Context>,
    task_test_id: Uuid,
) -> Result<Option<TaskTest>> {
    let all_task_test_messages = get_all_task_test_messages(context.clone(), task_test_id).await?;
    let task_test_result = get_task_test_result(context.clone(), &all_task_test_messages).await?;

    if let Some(task_test_result) = task_test_result {
        if task_test_result.answer_is_correct {
            let mut transaction = context.octopus_database.transaction_begin().await?;

            let task_test = context
                .octopus_database
                .update_task_test_answer_is_correct(
                    &mut transaction,
                    task_test_id,
                    task_test_result.answer_is_correct,
                )
                .await?;

            context
                .octopus_database
                .transaction_commit(transaction)
                .await?;

            let task_tests = context
                .octopus_database
                .get_task_tests_by_task_id(task_test.task_id)
                .await?;

            let mut all_correct = true;

            for task_test in task_tests {
                if !task_test.answer_is_correct {
                    all_correct = false;
                }
            }

            if all_correct {
                tokio::spawn(async move {
                    let task = check_task_result2(context, task_test.task_id).await;

                    if let Err(e) = task {
                        error!("Error: {:?}", e);
                    }
                });
            }

            return Ok(Some(task_test));
        }
    }

    Ok(None)
}

pub async fn get_all_messages(context: Arc<Context>, chat_id: Uuid) -> Result<String> {
    let chat_messages = context
        .octopus_database
        .get_chat_messages_by_chat_id(chat_id)
        .await?;

    let mut all_messages = String::new();

    for chat_message in chat_messages {
        all_messages.push_str("\nQuestion: ");
        all_messages.push_str(&chat_message.message);
        if let Some(response) = chat_message.response {
            all_messages.push_str("\nAnswer: ");
            all_messages.push_str(&response);
        }
    }

    Ok(all_messages)
}

pub async fn get_all_task_messages(context: Arc<Context>, chat_id: Uuid) -> Result<String> {
    let chat_messages = context
        .octopus_database
        .get_chat_messages_by_chat_id(chat_id)
        .await?;

    let mut all_messages = String::new();

    for chat_message in chat_messages {
        if chat_message.is_task_description {
            all_messages.push_str(&format!("\n{} ", PROMPT1));
            all_messages.push_str(&chat_message.message);
        } else {
            all_messages.push_str("\nQuestion: ");
            all_messages.push_str(&chat_message.message);
        }

        if let Some(response) = chat_message.response {
            all_messages.push_str("\nAnswer: ");
            all_messages.push_str(&response);
        }
    }

    Ok(all_messages)
}

pub async fn get_all_task_test_messages(
    context: Arc<Context>,
    task_test_id: Uuid,
) -> Result<String> {
    let task_test = context
        .octopus_database
        .try_get_task_test_by_id(task_test_id)
        .await?;

    let mut all_messages = String::new();

    if let Some(task_test) = task_test {
        all_messages.push_str("\nQuestion: ");
        all_messages.push_str(&task_test.question);

        if let Some(answer) = task_test.answer {
            all_messages.push_str("\nAnswer: ");
            all_messages.push_str(&answer);
        }
    }

    Ok(all_messages)
}

pub async fn get_all_task_test_messages2(context: Arc<Context>, task_id: Uuid) -> Result<String> {
    let task_tests = context
        .octopus_database
        .get_task_tests_by_task_id(task_id)
        .await?;

    let mut all_messages = String::new();

    for task_test in task_tests {
        all_messages.push_str("\nQuestion: ");
        all_messages.push_str(&task_test.question);

        if let Some(answer) = task_test.answer {
            all_messages.push_str("\nAnswer: ");
            all_messages.push_str(&answer);
        }
    }

    Ok(all_messages)
}

pub async fn get_chat_info_result(
    context: Arc<Context>,
    all_messages: &str,
) -> Result<Option<ChatInfoResult>> {
    let mut messages = vec![];

    let mut text = String::new();

    text.push_str(r#"I'll give you a history of conversation with chat. Determinate if supervisor wants to create a task or test/exam for user. Try to determine task title and description. Respond in format { "description": "string", "is_task": bool, "is_test": bool, "title": "string" }. Make sure your resonse is a valid JSON. Regard only the given questions or instructions in the prompt and always return only a json.\n\n"#);
    text.push_str(all_messages);

    let chat_completion_request_message = ChatCompletionRequestUserMessageArgs::default()
        .content(text)
        .build()?;

    messages.push(ChatCompletionRequestMessage::User(
        chat_completion_request_message,
    ));

    if context.get_config().await?.test_mode {
        return Ok(None);
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

    let chat_info_result = match request {
        Err(e) => {
            tracing::error!("OpenAIError: {e}");

            None
        }
        Ok(request) => {
            let response_message = match ai_client {
                AiClient::Azure(ai_client) => ai_client.chat().create(request).await,
                AiClient::OpenAI(ai_client) => ai_client.chat().create(request).await,
            };

            match response_message {
                Err(e) => {
                    tracing::error!("OpenAIError: {e}");

                    None
                }
                Ok(response_message) => {
                    let response_message = response_message.choices.first();

                    match response_message {
                        None => {
                            tracing::error!("BadResponse");

                            None
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
                                    ChatInfoResult,
                                    serde_json::error::Error,
                                > = serde_json::from_str(&response_content);

                                match response {
                                    Err(_) => None,
                                    Ok(response) => Some(response),
                                }
                            } else {
                                None
                            }
                        }
                    }
                }
            }
        }
    };

    Ok(chat_info_result)
}

pub async fn get_chat_task_result(
    context: Arc<Context>,
    all_messages: &str,
) -> Result<Option<ChatTaskResult>> {
    let ai_client = open_ai_get_client(context.clone()).await?;

    let mut messages = vec![];

    let mut text = String::new();

    text.push_str(r#"I'll give you a history of conversation with chat. Determine if user completed task. Respond in format { "is_completed": bool }. Make sure your resonse is a valid JSON. Regard only the given questions or instructions in the prompt and always return only a json.\n\n"#);
    text.push_str(all_messages);

    let chat_completion_request_message = ChatCompletionRequestUserMessageArgs::default()
        .content(text)
        .build()?;

    messages.push(ChatCompletionRequestMessage::User(
        chat_completion_request_message,
    ));

    if context.get_config().await?.test_mode {
        return Ok(None);
    }

    let main_llm_openai_primary_model = context
        .get_config()
        .await?
        .get_parameter_main_llm_openai_primary_model()
        .unwrap_or(PRIMARY_MODEL.to_string());

    let request = CreateChatCompletionRequestArgs::default()
        .model(main_llm_openai_primary_model)
        .messages(messages)
        .build();

    let chat_info_result = match request {
        Err(e) => {
            tracing::error!("OpenAIError: {e}");

            None
        }
        Ok(request) => {
            let response_message = match ai_client {
                AiClient::Azure(ai_client) => ai_client.chat().create(request).await,
                AiClient::OpenAI(ai_client) => ai_client.chat().create(request).await,
            };

            match response_message {
                Err(e) => {
                    tracing::error!("OpenAIError: {e}");

                    None
                }
                Ok(response_message) => {
                    let response_message = response_message.choices.first();

                    match response_message {
                        None => {
                            tracing::error!("BadResponse");

                            None
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
                                    ChatTaskResult,
                                    serde_json::error::Error,
                                > = serde_json::from_str(&response_content);

                                match response {
                                    Err(_) => None,
                                    Ok(response) => Some(response),
                                }
                            } else {
                                None
                            }
                        }
                    }
                }
            }
        }
    };

    Ok(chat_info_result)
}

pub async fn get_chat_task_result2(
    context: Arc<Context>,
    all_messages: &str,
    all_task_test_messages: &str,
) -> Result<Option<ChatTask2Result>> {
    let ai_client = open_ai_get_client(context.clone()).await?;

    let mut messages = vec![];

    let mut text = String::new();

    text.push_str(r#"I'll give you a history of conversation with chat. I'll give you a list of questions and user answers. Determine if user completed test. Provide test result description. Respond in format { "is_completed": bool, "test_result": string }. Make sure your resonse is a valid JSON. Regard only the given questions or instructions in the prompt and always return only a json.\n\n"#);
    text.push_str("\n\nConversation with chat:");
    text.push_str(all_messages);
    text.push_str("\n\nQestions and user answers:");
    text.push_str(all_task_test_messages);

    let chat_completion_request_message = ChatCompletionRequestUserMessageArgs::default()
        .content(text)
        .build()?;

    messages.push(ChatCompletionRequestMessage::User(
        chat_completion_request_message,
    ));

    if context.get_config().await?.test_mode {
        return Ok(None);
    }

    let main_llm_openai_primary_model = context
        .get_config()
        .await?
        .get_parameter_main_llm_openai_primary_model()
        .unwrap_or(PRIMARY_MODEL.to_string());

    let request = CreateChatCompletionRequestArgs::default()
        .model(main_llm_openai_primary_model)
        .messages(messages)
        .build();

    let chat_info_result = match request {
        Err(e) => {
            tracing::error!("OpenAIError: {e}");

            None
        }
        Ok(request) => {
            let response_message = match ai_client {
                AiClient::Azure(ai_client) => ai_client.chat().create(request).await,
                AiClient::OpenAI(ai_client) => ai_client.chat().create(request).await,
            };

            match response_message {
                Err(e) => {
                    tracing::error!("OpenAIError: {e}");

                    None
                }
                Ok(response_message) => {
                    let response_message = response_message.choices.first();

                    match response_message {
                        None => {
                            tracing::error!("BadResponse");

                            None
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
                                    ChatTask2Result,
                                    serde_json::error::Error,
                                > = serde_json::from_str(&response_content);

                                match response {
                                    Err(_) => None,
                                    Ok(response) => Some(response),
                                }
                            } else {
                                None
                            }
                        }
                    }
                }
            }
        }
    };

    Ok(chat_info_result)
}

pub async fn get_chat_task_info_result(
    context: Arc<Context>,
    all_messages: &str,
) -> Result<Option<ChatTaskInfoResult>> {
    let mut messages = vec![];

    let mut text = String::new();

    text.push_str(r#"I'll give you a history of conversation with chat. Summarize it and provide a clear task description for the user. Respond in format { "task_description_message": "string" }. Make sure your resonse is a valid JSON. Regard only the given questions or instructions in the prompt and always return only a json.\n\n"#);
    text.push_str(all_messages);

    let chat_completion_request_message = ChatCompletionRequestUserMessageArgs::default()
        .content(text)
        .build()?;

    messages.push(ChatCompletionRequestMessage::User(
        chat_completion_request_message,
    ));

    if context.get_config().await?.test_mode {
        return Ok(None);
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

    let chat_task_info_result = match request {
        Err(e) => {
            tracing::error!("OpenAIError: {e}");

            None
        }
        Ok(request) => {
            let response_message = match ai_client {
                AiClient::Azure(ai_client) => ai_client.chat().create(request).await,
                AiClient::OpenAI(ai_client) => ai_client.chat().create(request).await,
            };

            match response_message {
                Err(e) => {
                    tracing::error!("OpenAIError: {e}");

                    None
                }
                Ok(response_message) => {
                    let response_message = response_message.choices.first();

                    match response_message {
                        None => {
                            tracing::error!("BadResponse");

                            None
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
                                    ChatTaskInfoResult,
                                    serde_json::error::Error,
                                > = serde_json::from_str(&response_content);

                                match response {
                                    Err(_) => None,
                                    Ok(response) => Some(response),
                                }
                            } else {
                                None
                            }
                        }
                    }
                }
            }
        }
    };

    Ok(chat_task_info_result)
}

pub async fn get_chat_test_info_result(
    context: Arc<Context>,
    all_messages: &str,
) -> Result<Option<ChatTestInfoResult>> {
    let mut messages = vec![];

    let mut text = String::new();

    text.push_str(r#"I'll give you a history of conversation with chat. Respond with nicely formated questions. Respond in format { "task_questions": [ { "question": "string" } ] }. Make sure your resonse is a valid JSON. Regard only the given questions or instructions in the prompt and always return only a json.\n\n"#);
    text.push_str(all_messages);

    let chat_completion_request_message = ChatCompletionRequestUserMessageArgs::default()
        .content(text)
        .build()?;

    messages.push(ChatCompletionRequestMessage::User(
        chat_completion_request_message,
    ));

    if context.get_config().await?.test_mode {
        return Ok(None);
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

    let chat_test_info_result = match request {
        Err(e) => {
            tracing::error!("OpenAIError: {e}");

            None
        }
        Ok(request) => {
            let response_message = match ai_client {
                AiClient::Azure(ai_client) => ai_client.chat().create(request).await,
                AiClient::OpenAI(ai_client) => ai_client.chat().create(request).await,
            };

            match response_message {
                Err(e) => {
                    tracing::error!("OpenAIError: {e}");

                    None
                }
                Ok(response_message) => {
                    let response_message = response_message.choices.first();

                    match response_message {
                        None => {
                            tracing::error!("BadResponse");

                            None
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
                                    ChatTestInfoResult,
                                    serde_json::error::Error,
                                > = serde_json::from_str(&response_content);

                                match response {
                                    Err(_) => None,
                                    Ok(response) => Some(response),
                                }
                            } else {
                                None
                            }
                        }
                    }
                }
            }
        }
    };

    Ok(chat_test_info_result)
}

pub async fn get_task_info(context: Arc<Context>, chat_id: Uuid) -> Result<Option<TaskInfo>> {
    let all_messages = get_all_messages(context.clone(), chat_id).await?;
    let chat_info_result = get_chat_info_result(context.clone(), &all_messages).await?;

    if let Some(chat_info_result) = chat_info_result {
        if chat_info_result.is_task {
            let chat_task_info_result =
                get_chat_task_info_result(context.clone(), &all_messages).await?;

            if let Some(chat_task_info_result) = chat_task_info_result {
                let task_info = TaskInfo {
                    description: chat_info_result.description,
                    task_description_message: Some(chat_task_info_result.task_description_message),
                    task_questions: vec![],
                    title: chat_info_result.title,
                    r#type: TaskType::Normal,
                };

                return Ok(Some(task_info));
            }
        } else if chat_info_result.is_test {
            let chat_test_info_result =
                get_chat_test_info_result(context.clone(), &all_messages).await?;

            if let Some(chat_test_info_result) = chat_test_info_result {
                let task_info = TaskInfo {
                    description: chat_info_result.description,
                    task_description_message: None,
                    task_questions: chat_test_info_result.task_questions,
                    title: chat_info_result.title,
                    r#type: TaskType::Test,
                };

                return Ok(Some(task_info));
            }
        }
    }

    Ok(None)
}

pub async fn get_task_test_result(
    context: Arc<Context>,
    all_messages: &str,
) -> Result<Option<TaskTestResult>> {
    let ai_client = open_ai_get_client(context.clone()).await?;

    let mut messages = vec![];

    let mut text = String::new();

    text.push_str(r#"I'll give you a test question and user answer. Determine if user answer is correct. Respond in format { "answer_is_correct": bool }. Make sure your resonse is a valid JSON. Regard only the given questions or instructions in the prompt and always return only a json.\n\n"#);
    text.push_str(all_messages);

    let chat_completion_request_message = ChatCompletionRequestUserMessageArgs::default()
        .content(text)
        .build()?;

    messages.push(ChatCompletionRequestMessage::User(
        chat_completion_request_message,
    ));

    if context.get_config().await?.test_mode {
        return Ok(None);
    }

    let main_llm_openai_primary_model = context
        .get_config()
        .await?
        .get_parameter_main_llm_openai_primary_model()
        .unwrap_or(PRIMARY_MODEL.to_string());

    let request = CreateChatCompletionRequestArgs::default()
        .model(main_llm_openai_primary_model)
        .messages(messages)
        .build();

    let chat_info_result = match request {
        Err(e) => {
            tracing::error!("OpenAIError: {e}");

            None
        }
        Ok(request) => {
            let response_message = match ai_client {
                AiClient::Azure(ai_client) => ai_client.chat().create(request).await,
                AiClient::OpenAI(ai_client) => ai_client.chat().create(request).await,
            };

            match response_message {
                Err(e) => {
                    tracing::error!("OpenAIError: {e}");

                    None
                }
                Ok(response_message) => {
                    let response_message = response_message.choices.first();

                    match response_message {
                        None => {
                            tracing::error!("BadResponse");

                            None
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
                                    TaskTestResult,
                                    serde_json::error::Error,
                                > = serde_json::from_str(&response_content);

                                match response {
                                    Err(_) => None,
                                    Ok(response) => Some(response),
                                }
                            } else {
                                None
                            }
                        }
                    }
                }
            }
        }
    };

    Ok(chat_info_result)
}
