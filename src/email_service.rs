/*
use crate::{Result, context::Context, error::AppError};
//use sendgrid::error::SendgridError;
//use sendgrid::v3::*;
use sendgrid::SGClient;
use sendgrid::{Destination, Mail};
use std::sync::Arc;

pub const FROM_EMAIL: &str = "noreply@metric-space.ai";

pub fn send_password_reset_request_email(context: Arc<Context>, email: &str, token: &str) -> Result<()> {
    let content = format!("<p>Hi,</p><p>We received your request for a password reset. Below is a token that you need to use to validate your request.</p><p>{token}</p>");
    /*
    let personalization = Personalization::new(Email::new(email));
    let message = Message::new(Email::new(FROM_EMAIL))
        .set_subject("Password reset request")
        .add_content(
            Content::new()
                .set_content_type("text/html")
                .set_value("test"),
        )
        .add_personalization(personalization);

    let sender = Sender::new(context.config.sendgrid_api_key.clone());
    let resp = sender.send(&message)?;
    tracing::info!("status: {}", resp.status());
*/

    let sg = SGClient::new(context.config.sendgrid_api_key.clone());
    let x_smtpapi = String::new();
/*
    let mail_info = Mail::new()
        .add_to(Destination {
            address: email,
            name: email,
        })
        .add_from(FROM_EMAIL)
        .add_subject("Password reset request")
        .add_html(&content)
        .add_from_name("Octopus")
        .add_x_smtpapi(&x_smtpapi);

    match sg.send(mail_info) {
        Err(err) => tracing::info!("Error: {}", err),
        Ok(body) => tracing::info!("Response: {:?}", body),
    };
*/
    Ok(())
}
*/
