use crate::{
    context::Context,
    entity::{ChatMessage, ChatMessageStatus},
    error::AppError,
};
use async_openai::{
    types::{
        ChatCompletionFunctionsArgs, ChatCompletionRequestMessageArgs,
        CreateChatCompletionRequestArgs, Role,
    },
    Client,
};
use serde_json::json;
use std::{collections::HashMap, sync::Arc};
use tracing::info;

pub async fn open_ai_request(
    context: Arc<Context>,
    chat_message: ChatMessage,
) -> Result<ChatMessage, AppError> {
    let client = Client::new();

    let mut messages = vec![];

    let chat_messages = context
        .octopus_database
        .get_chat_messages_by_chat_id(chat_message.chat_id)
        .await?;

    for chat_message_tmp in chat_messages {
        let chat_completion_request_message = ChatCompletionRequestMessageArgs::default()
            .role(Role::User)
            .content(chat_message_tmp.message.clone())
            .build()?;

        messages.append(&mut vec![chat_completion_request_message]);
    }

    let request = CreateChatCompletionRequestArgs::default()
        .max_tokens(512u16)
        .model("gpt-3.5-turbo-0613")
        .messages(messages)
        .functions([ChatCompletionFunctionsArgs::default()
            .name("get_current_weather")
            .description("Get the current weather in a given location")
            .parameters(json!({
                "type": "object",
                "properties": {
                    "location": {
                        "type": "string",
                        "description": "The city and state, e.g. San Francisco, CA",
                    },
                    "unit": { "type": "string", "enum": ["celsius", "fahrenheit"] },
                },
                "required": ["location"],
            }))
            .build()?])
        .function_call("auto")
        .build()?;

    let response_message = client
        .chat()
        .create(request)
        .await?
        .choices
        .get(0)
        .unwrap()
        .message
        .clone();

    info!("{:?}", response_message);

    if let Some(function_call) = response_message.function_call {
        let mut available_functions: HashMap<&str, fn(&str, &str) -> serde_json::Value> =
            HashMap::new();
        available_functions.insert("get_current_weather", get_current_weather);
        let function_name = function_call.name;
        let function_args: serde_json::Value = function_call.arguments.parse().unwrap();

        let location = function_args["location"].as_str().unwrap();
        let unit = "fahrenheit";
        let function = available_functions.get(function_name.as_str()).unwrap();
        let function_response = function(location, unit);

        let message = vec![
            ChatCompletionRequestMessageArgs::default()
                .role(Role::User)
                .content("What's the weather like in Boston?")
                .build()?,
            ChatCompletionRequestMessageArgs::default()
                .role(Role::Function)
                .name(function_name)
                .content(function_response.to_string())
                .build()?,
        ];

        let request = CreateChatCompletionRequestArgs::default()
            .max_tokens(512u16)
            .model("gpt-3.5-turbo-0613")
            .messages(message)
            .build()?;

        let response = client.chat().create(request).await?;

        for choice in response.choices {
            if let Some(content) = choice.message.content {
                let chat_message = context
                    .octopus_database
                    .update_chat_message(chat_message.id, &content, ChatMessageStatus::Answered)
                    .await?;

                return Ok(chat_message);
            }
        }
    }

    if let Some(content) = response_message.content {
        let chat_message = context
            .octopus_database
            .update_chat_message(chat_message.id, &content, ChatMessageStatus::Answered)
            .await?;

        return Ok(chat_message);
    }

    Ok(chat_message)
}

fn get_current_weather(location: &str, unit: &str) -> serde_json::Value {
    let weather_info = json!({
        "location": location,
        "temperature": "72",
        "unit": unit,
        "forecast": ["sunny", "windy"]
    });

    weather_info
}
