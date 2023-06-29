use crate::{config::Config, error::AppError};
use async_openai::{
    types::{
        ChatCompletionFunctionsArgs, ChatCompletionRequestMessageArgs,
        CreateChatCompletionRequestArgs, Role,
    },
    Client,
};
use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use tracing::info;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{collections::HashMap, sync::Arc};
use validator::Validate;

#[axum_macros::debug_handler]
pub async fn create(
    State(config): State<Arc<Config>>,
    Json(input): Json<CreateChatMessage>,
) -> Result<impl IntoResponse, AppError> {
    input.validate()?;

    let client = Client::new();

    let request = CreateChatCompletionRequestArgs::default()
        .max_tokens(512u16)
        .model("gpt-3.5-turbo-0613")
        .messages([ChatCompletionRequestMessageArgs::default()
            .role(Role::User)
            .content(input.message.clone())
            .build()?])
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

        info!("\nResponse:\n");
        for choice in response.choices {
            info!(
                "{}: Role: {}  Content: {:?}",
                choice.index, choice.message.role, choice.message.content
            );
        }
    }

    Ok((StatusCode::CREATED, Json(input)).into_response())
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

#[derive(Debug, Deserialize, Serialize, Validate)]
pub struct CreateChatMessage {
    message: String,
}
