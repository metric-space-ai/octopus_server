use crate::{Args, Result};

#[derive(Clone, Debug)]
pub struct Config {
    pub openai_api_key: String,
    pub port: u16,
}

impl Config {
    pub fn new(openai_api_key: String, port: u16) -> Self {
        Self { openai_api_key, port }
    }
}

pub fn load(args: Args) -> Result<Config> {
    let mut openai_api_key: Option<String> = None;
    let mut port = 8080;

    if let Ok(val) = std::env::var("OCTOPUS_SERVER_OPENAI_API_KEY") {
        openai_api_key = Some(val)
    }

    if let Some(val) = args.openai_api_key {
        openai_api_key = Some(val)
    }

    if let Ok(val) = std::env::var("OCTOPUS_SERVER_PORT") {
        port = val.parse::<u16>()?
    }

    if let Some(val) = args.port {
        port = val
    }

    let config = Config::new(openai_api_key.expect("OpenAI API key not provided"), port);

    Ok(config)
}