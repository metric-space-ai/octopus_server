use crate::{
    Result,
    ai::function_call::{AiFunctionFileResponse, AiFunctionResponse, AiFunctionTextResponse},
};
use base64::{Engine, alphabet, engine};
use crowbook::{Book, Number};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::value::Value;
use std::fs::{read, remove_file};
use uuid::Uuid;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MarkdownConverterPost {
    pub url: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MarkdownFile {
    pub book: String,
    pub topic: String,
    pub outline: String,
    pub model: String,
    pub chapters: Vec<String>,
    pub summary: String,
}

pub async fn os_internal_markdown_converter(function_args: &Value) -> Result<AiFunctionResponse> {
    let markdown_converter_post: MarkdownConverterPost =
        serde_json::from_value(function_args.clone())?;

    let response = reqwest::ClientBuilder::new()
        .build()?
        .get(markdown_converter_post.url)
        .send()
        .await;

    match response {
        Err(error) => {
            tracing::error!("Function call error: {error:?}");
        }
        Ok(response) => {
            if response.status() == StatusCode::OK {
                let markdown_file: std::result::Result<MarkdownFile, reqwest::Error> =
                    response.json().await;

                if let Ok(markdown_file) = markdown_file {
                    let result = create_book(markdown_file).await?;

                    let ai_function_file_response = AiFunctionFileResponse {
                        content: result,
                        media_type: "application/pdf".to_string(),
                        original_file_name: None,
                    };

                    let ai_function_response = AiFunctionResponse::File(ai_function_file_response);

                    return Ok(ai_function_response);
                }
            }
        }
    }

    let ai_function_text_response = AiFunctionTextResponse {
        response: Some("".to_string()),
    };

    let ai_function_response = AiFunctionResponse::Text(ai_function_text_response);

    Ok(ai_function_response)
}

pub async fn create_book(markdown_file: MarkdownFile) -> Result<String> {
    let mut book = Book::new();
    book.set_options(&[("author", "Octopus"), ("title", &markdown_file.topic)]);

    for chapter in markdown_file.chapters {
        book.add_chapter_from_source(Number::Default, chapter.as_bytes(), false)?;
    }

    let format = "pdf";
    let file_path = format!("/tmp/{}.{}", Uuid::new_v4(), format);

    book.render_format_to_file(format, &file_path)?;

    let content = read(&file_path)?;

    let engine = engine::GeneralPurpose::new(&alphabet::URL_SAFE, engine::general_purpose::PAD);
    let content = engine.encode(content);

    remove_file(file_path)?;

    Ok(content)
}
