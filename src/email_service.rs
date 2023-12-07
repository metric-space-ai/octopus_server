use crate::{context::Context, Result};
use reqwest::header::AUTHORIZATION;
use serde::Serialize;
use std::sync::Arc;

pub const FROM_EMAIL: &str = "noreply@metric-space.ai";
pub const SENDGRID_API_URL: &str = "https://api.sendgrid.com/v3";

#[derive(Serialize)]
pub struct Content {
    pub r#type: String,
    pub value: String,
}

#[derive(Serialize)]
pub struct Email {
    pub email: String,
}

#[derive(Serialize)]
pub struct Message {
    pub content: Vec<Content>,
    pub from: Email,
    pub personalizations: Vec<Personalization>,
    pub subject: String,
}

#[derive(Serialize)]
pub struct Personalization {
    pub to: Vec<Email>,
}

pub async fn send_invitation_email(
    context: Arc<Context>,
    email: &str,
    password: &str,
) -> Result<()> {
    let content = format!("<p>Hi,</p><p>We are pleased to inform you that you have been invited to Octopus. Below is a password that you need to use to login.</p><p>{password}</p>");
    let subject = "Invitation";

    let from = Email {
        email: FROM_EMAIL.to_string(),
    };
    let to = Email {
        email: email.to_string(),
    };
    let personalization = Personalization { to: vec![to] };
    let content = Content {
        r#type: "text/html".to_string(),
        value: content,
    };
    let message = Message {
        content: vec![content],
        from,
        personalizations: vec![personalization],
        subject: subject.to_string(),
    };

    if !context.get_config().await?.test_mode {
        let sendgrid_api_key = context.get_config().await?.get_parameter_sendgrid_api_key();

        if let Some(sendgrid_api_key) = sendgrid_api_key {
            reqwest::Client::new()
                .post(format!("{SENDGRID_API_URL}/mail/send"))
                .json(&message)
                .header(AUTHORIZATION, format!("Bearer {sendgrid_api_key}"))
                .send()
                .await?;
        } else {
            tracing::error!("Missing SENDGRID_API_KEY");
        }
    }

    Ok(())
}

pub async fn send_password_reset_request_email(
    context: Arc<Context>,
    email: &str,
    token: &str,
) -> Result<()> {
    let content = format!("<p>Hi,</p><p>We received your request for a password reset. Below is a token that you need to use to validate your request.</p><p>{token}</p>");
    let subject = "Password reset request";

    let from = Email {
        email: FROM_EMAIL.to_string(),
    };
    let to = Email {
        email: email.to_string(),
    };
    let personalization = Personalization { to: vec![to] };
    let content = Content {
        r#type: "text/html".to_string(),
        value: content,
    };
    let message = Message {
        content: vec![content],
        from,
        personalizations: vec![personalization],
        subject: subject.to_string(),
    };

    if !context.get_config().await?.test_mode {
        let sendgrid_api_key = context.get_config().await?.get_parameter_sendgrid_api_key();

        if let Some(sendgrid_api_key) = sendgrid_api_key {
            reqwest::Client::new()
                .post(format!("{SENDGRID_API_URL}/mail/send"))
                .json(&message)
                .header(AUTHORIZATION, format!("Bearer {sendgrid_api_key}"))
                .send()
                .await?;
        } else {
            tracing::error!("Missing SENDGRID_API_KEY");
        }
    }

    Ok(())
}
