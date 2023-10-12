use crate::{Args, Result};

#[derive(Clone, Debug)]
pub struct Config {
    pub azure_openai_api_key: Option<String>,
    pub azure_openai_deployment_id: Option<String>,
    pub azure_openai_enabled: bool,
    pub database_url: String,
    pub openai_api_key: Option<String>,
    pub pepper: String,
    pub pepper_id: i32,
    pub port: u16,
    pub sendgrid_api_key: String,
}

impl Config {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        azure_openai_api_key: Option<String>,
        azure_openai_deployment_id: Option<String>,
        azure_openai_enabled: bool,
        database_url: String,
        openai_api_key: Option<String>,
        pepper: String,
        pepper_id: i32,
        port: u16,
        sendgrid_api_key: String,
    ) -> Self {
        Self {
            azure_openai_api_key,
            azure_openai_deployment_id,
            azure_openai_enabled,
            database_url,
            openai_api_key,
            pepper,
            pepper_id,
            port,
            sendgrid_api_key,
        }
    }
}

pub fn load(args: Args) -> Result<Config> {
    let mut azure_openai_api_key: Option<String> = None;
    let mut azure_openai_deployment_id: Option<String> = None;
    let mut azure_openai_enabled = false;
    let mut database_url: Option<String> = None;
    let mut openai_api_key: Option<String> = None;
    let mut port = 8080;
    let mut sendgrid_api_key: Option<String> = None;

    if let Ok(val) = std::env::var("AZURE_OPENAI_API_KEY") {
        azure_openai_api_key = Some(val);
    }

    if let Some(val) = args.azure_openai_api_key {
        azure_openai_api_key = Some(val);
    }

    if let Ok(val) = std::env::var("AZURE_OPENAI_DEPLOYMENT_ID") {
        azure_openai_deployment_id = Some(val);
    }

    if let Some(val) = args.azure_openai_deployment_id {
        azure_openai_deployment_id = Some(val);
    }

    if let Ok(val) = std::env::var("AZURE_OPENAI_ENABLED")?.parse::<bool>() {
        azure_openai_enabled = val;
    }

    if let Some(val) = args.azure_openai_enabled {
        azure_openai_enabled = val;
    }

    if let Ok(val) = std::env::var("DATABASE_URL") {
        database_url = Some(val);
    }

    if let Some(val) = args.database_url {
        database_url = Some(val);
    }

    if let Ok(val) = std::env::var("OPENAI_API_KEY") {
        openai_api_key = Some(val);
    }

    if let Some(val) = args.openai_api_key {
        openai_api_key = Some(val);
    }

    let pepper = std::env::var("OCTOPUS_PEPPER")?;
    let pepper_id = std::env::var("OCTOPUS_PEPPER_ID")?.parse::<i32>()?;

    if let Ok(val) = std::env::var("OCTOPUS_SERVER_PORT") {
        port = val.parse::<u16>()?;
    }

    if let Some(val) = args.port {
        port = val;
    }

    if let Ok(val) = std::env::var("SENDGRID_API_KEY") {
        sendgrid_api_key = Some(val);
    }

    if azure_openai_enabled
        && (azure_openai_api_key.is_none() || azure_openai_deployment_id.is_none())
    {
        azure_openai_api_key
            .clone()
            .expect("Azure OpenAI API key not provided");
        azure_openai_api_key
            .clone()
            .expect("Azure OpenAI deployment id not provided");
    }

    if !azure_openai_enabled && openai_api_key.is_none() {
        openai_api_key.clone().expect("OpenAI API key not provided");
    }

    let config = Config::new(
        azure_openai_api_key,
        azure_openai_deployment_id,
        azure_openai_enabled,
        database_url.expect("Unknown database url"),
        openai_api_key,
        pepper,
        pepper_id,
        port,
        sendgrid_api_key.expect("SendGrid API key not provided"),
    );

    Ok(config)
}
