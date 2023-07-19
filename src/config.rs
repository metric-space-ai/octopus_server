use crate::{Args, Result};

#[derive(Clone, Debug)]
pub struct Config {
    pub database_url: String,
    pub openai_api_key: String,
    pub pepper: String,
    pub pepper_id: i32,
    pub port: u16,
}

impl Config {
    pub fn new(
        database_url: String,
        openai_api_key: String,
        pepper: String,
        pepper_id: i32,
        port: u16,
    ) -> Self {
        Self {
            database_url,
            openai_api_key,
            pepper,
            pepper_id,
            port,
        }
    }
}

pub fn load(args: Args) -> Result<Config> {
    let mut database_url: Option<String> = None;
    let mut openai_api_key: Option<String> = None;
    let mut port = 8080;

    if let Ok(val) = std::env::var("DATABASE_URL") {
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

    let config = Config::new(
        database_url.expect("Unknown database url"),
        openai_api_key.expect("OpenAI API key not provided"),
        pepper,
        pepper_id,
        port,
    );

    Ok(config)
}
