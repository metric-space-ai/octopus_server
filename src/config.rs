use crate::{
    entity::{
        Parameter, PARAMETER_NAME_HUGGING_FACE_TOKEN_ACCESS, PARAMETER_NAME_MAIN_LLM,
        PARAMETER_NAME_MAIN_LLM_ANTHROPIC_API_KEY, PARAMETER_NAME_MAIN_LLM_ANTHROPIC_MODEL,
        PARAMETER_NAME_MAIN_LLM_AZURE_OPENAI_API_KEY,
        PARAMETER_NAME_MAIN_LLM_AZURE_OPENAI_DEPLOYMENT_ID,
        PARAMETER_NAME_MAIN_LLM_AZURE_OPENAI_ENABLED, PARAMETER_NAME_MAIN_LLM_AZURE_OPENAI_URL,
        PARAMETER_NAME_MAIN_LLM_OLLAMA_MODEL, PARAMETER_NAME_MAIN_LLM_OPENAI_API_KEY,
        PARAMETER_NAME_MAIN_LLM_OPENAI_PRIMARY_MODEL,
        PARAMETER_NAME_MAIN_LLM_OPENAI_SECONDARY_MODEL, PARAMETER_NAME_MAIN_LLM_OPENAI_TEMPERATURE,
        PARAMETER_NAME_MAIN_LLM_SYSTEM_PROMPT, PARAMETER_NAME_NEXTCLOUD_PASSWORD,
        PARAMETER_NAME_NEXTCLOUD_URL, PARAMETER_NAME_NEXTCLOUD_USERNAME,
        PARAMETER_NAME_OCTOPUS_API_URL, PARAMETER_NAME_OCTOPUS_WS_URL,
        PARAMETER_NAME_REGISTRATION_ALLOWED, PARAMETER_NAME_SCRAPINGBEE_API_KEY,
        PARAMETER_NAME_SENDGRID_API_KEY,
    },
    Args, Result,
};

#[derive(Clone, Debug)]
pub struct Config {
    pub database_url: String,
    pub nextcloud_subdir: String,
    pub ollama_host: Option<String>,
    pub parameters: Vec<Parameter>,
    pub pepper: String,
    pub pepper_id: i32,
    pub port: u16,
    pub test_mode: bool,
    pub wasp_database_url: String,
    pub web_driver_url: Option<String>,
    pub ws_port: u16,
}

impl Config {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        database_url: String,
        nextcloud_subdir: String,
        ollama_host: Option<String>,
        parameters: Vec<Parameter>,
        pepper: String,
        pepper_id: i32,
        port: u16,
        test_mode: bool,
        wasp_database_url: String,
        web_driver_url: Option<String>,
        ws_port: u16,
    ) -> Self {
        Self {
            database_url,
            nextcloud_subdir,
            ollama_host,
            parameters,
            pepper,
            pepper_id,
            port,
            test_mode,
            wasp_database_url,
            web_driver_url,
            ws_port,
        }
    }

    pub fn get_parameter_hugging_face_token_access(&self) -> Option<String> {
        let hugging_face_token_access =
            self.get_parameter_value(PARAMETER_NAME_HUGGING_FACE_TOKEN_ACCESS);

        if let Some(hugging_face_token_access) = hugging_face_token_access {
            if hugging_face_token_access != *"default" {
                return Some(hugging_face_token_access);
            }
        }

        None
    }

    pub fn get_parameter_main_llm(&self) -> Option<String> {
        let main_llm = self.get_parameter_value(PARAMETER_NAME_MAIN_LLM);

        if let Some(main_llm) = main_llm {
            if main_llm == *"default" {
                return Some("gpt".to_string());
            } else {
                return Some(main_llm);
            }
        }

        None
    }

    pub fn get_parameter_main_llm_anthropic_api_key(&self) -> Option<String> {
        let main_llm_anthropic_api_key =
            self.get_parameter_value(PARAMETER_NAME_MAIN_LLM_ANTHROPIC_API_KEY);

        if let Some(main_llm_anthropic_api_key) = main_llm_anthropic_api_key {
            if main_llm_anthropic_api_key != *"default" {
                return Some(main_llm_anthropic_api_key);
            }
        }

        None
    }

    pub fn get_parameter_main_llm_anthropic_model(&self) -> Option<String> {
        let main_llm_anthropic_model =
            self.get_parameter_value(PARAMETER_NAME_MAIN_LLM_ANTHROPIC_MODEL);

        if let Some(main_llm_anthropic_model) = main_llm_anthropic_model {
            if main_llm_anthropic_model != *"default" {
                return Some(main_llm_anthropic_model);
            }
        }

        None
    }

    pub fn get_parameter_main_llm_azure_openai_api_key(&self) -> Option<String> {
        let main_llm_azure_openai_api_key =
            self.get_parameter_value(PARAMETER_NAME_MAIN_LLM_AZURE_OPENAI_API_KEY);

        if let Some(main_llm_azure_openai_api_key) = main_llm_azure_openai_api_key {
            if main_llm_azure_openai_api_key != *"default" {
                return Some(main_llm_azure_openai_api_key);
            }
        }

        None
    }

    pub fn get_parameter_main_llm_azure_openai_deployment_id(&self) -> Option<String> {
        let main_llm_azure_openai_deployment_id =
            self.get_parameter_value(PARAMETER_NAME_MAIN_LLM_AZURE_OPENAI_DEPLOYMENT_ID);

        if let Some(main_llm_azure_openai_deployment_id) = main_llm_azure_openai_deployment_id {
            if main_llm_azure_openai_deployment_id != *"default" {
                return Some(main_llm_azure_openai_deployment_id);
            }
        }

        None
    }

    pub fn get_parameter_main_llm_azure_openai_enabled(&self) -> bool {
        let main_llm_azure_openai_enabled =
            self.get_parameter_value(PARAMETER_NAME_MAIN_LLM_AZURE_OPENAI_ENABLED);

        if let Some(main_llm_azure_openai_enabled) = main_llm_azure_openai_enabled {
            if main_llm_azure_openai_enabled != *"default" {
                if let Ok(val) = main_llm_azure_openai_enabled.parse::<bool>() {
                    return val;
                } else {
                    return false;
                }
            } else {
                return false;
            }
        }

        false
    }

    pub fn get_parameter_main_llm_azure_openai_url(&self) -> Option<String> {
        let main_llm_azure_openai_url =
            self.get_parameter_value(PARAMETER_NAME_MAIN_LLM_AZURE_OPENAI_URL);

        if let Some(main_llm_azure_openai_url) = main_llm_azure_openai_url {
            if main_llm_azure_openai_url != *"default" {
                return Some(main_llm_azure_openai_url);
            }
        }

        None
    }

    pub fn get_parameter_main_llm_ollama_model(&self) -> Option<String> {
        let main_llm_ollama_model = self.get_parameter_value(PARAMETER_NAME_MAIN_LLM_OLLAMA_MODEL);

        if let Some(main_llm_ollama_model) = main_llm_ollama_model {
            if main_llm_ollama_model != *"default" {
                return Some(main_llm_ollama_model);
            }
        }

        None
    }

    pub fn get_parameter_main_llm_openai_api_key(&self) -> Option<String> {
        let main_llm_openai_api_key =
            self.get_parameter_value(PARAMETER_NAME_MAIN_LLM_OPENAI_API_KEY);

        if let Some(main_llm_openai_api_key) = main_llm_openai_api_key {
            if main_llm_openai_api_key != *"default" {
                return Some(main_llm_openai_api_key);
            }
        }

        if let Ok(val) = std::env::var("OPENAI_API_KEY") {
            return Some(val);
        }

        None
    }

    pub fn get_parameter_main_llm_openai_primary_model(&self) -> Option<String> {
        let main_llm_openai_primary_model =
            self.get_parameter_value(PARAMETER_NAME_MAIN_LLM_OPENAI_PRIMARY_MODEL);

        if let Some(main_llm_openai_primary_model) = main_llm_openai_primary_model {
            if main_llm_openai_primary_model != *"default" {
                return Some(main_llm_openai_primary_model);
            }
        }

        None
    }

    pub fn get_parameter_main_llm_openai_secondary_model(&self) -> Option<String> {
        let main_llm_openai_secondary_model =
            self.get_parameter_value(PARAMETER_NAME_MAIN_LLM_OPENAI_SECONDARY_MODEL);

        if let Some(main_llm_openai_secondary_model) = main_llm_openai_secondary_model {
            if main_llm_openai_secondary_model != *"default" {
                return Some(main_llm_openai_secondary_model);
            }
        }

        None
    }

    pub fn get_parameter_main_llm_openai_temperature(&self) -> Option<f32> {
        let main_llm_openai_temperature =
            self.get_parameter_value(PARAMETER_NAME_MAIN_LLM_OPENAI_TEMPERATURE);

        if let Some(main_llm_openai_temperature) = main_llm_openai_temperature {
            if main_llm_openai_temperature != *"default" {
                let main_llm_openai_temperature = main_llm_openai_temperature.parse::<f32>();

                match main_llm_openai_temperature {
                    Err(_) => return Some(0.7),
                    Ok(main_llm_openai_temperature) => return Some(main_llm_openai_temperature),
                }
            }
        }

        None
    }

    pub fn get_parameter_main_llm_system_prompt(&self) -> Option<String> {
        let main_llm_system_prompt =
            self.get_parameter_value(PARAMETER_NAME_MAIN_LLM_SYSTEM_PROMPT);

        if let Some(main_llm_system_prompt) = main_llm_system_prompt {
            if main_llm_system_prompt != *"default" {
                return Some(main_llm_system_prompt);
            }
        }

        None
    }

    pub fn get_parameter_nextcloud_password(&self) -> Option<String> {
        let nextcloud_password = self.get_parameter_value(PARAMETER_NAME_NEXTCLOUD_PASSWORD);

        if let Some(nextcloud_password) = nextcloud_password {
            if nextcloud_password != *"default" {
                return Some(nextcloud_password);
            }
        }

        None
    }

    pub fn get_parameter_nextcloud_url(&self) -> Option<String> {
        let nextcloud_url = self.get_parameter_value(PARAMETER_NAME_NEXTCLOUD_URL);

        if let Some(nextcloud_url) = nextcloud_url {
            if nextcloud_url != *"default" {
                return Some(nextcloud_url);
            }
        }

        None
    }

    pub fn get_parameter_nextcloud_username(&self) -> Option<String> {
        let nextcloud_username = self.get_parameter_value(PARAMETER_NAME_NEXTCLOUD_USERNAME);

        if let Some(nextcloud_username) = nextcloud_username {
            if nextcloud_username != *"default" {
                return Some(nextcloud_username);
            }
        }

        None
    }

    pub fn get_parameter_octopus_api_url(&self) -> Option<String> {
        let octopus_api_url = self.get_parameter_value(PARAMETER_NAME_OCTOPUS_API_URL);

        if let Some(octopus_api_url) = octopus_api_url {
            if octopus_api_url == *"default" {
                return Some("http://localhost:8080".to_string());
            } else {
                return Some(octopus_api_url);
            }
        }

        None
    }

    pub fn get_parameter_octopus_ws_url(&self) -> Option<String> {
        let octopus_ws_url = self.get_parameter_value(PARAMETER_NAME_OCTOPUS_WS_URL);

        if let Some(octopus_ws_url) = octopus_ws_url {
            if octopus_ws_url != *"default" {
                return Some(octopus_ws_url);
            }
        }

        None
    }

    pub fn get_parameter_registration_allowed(&self) -> Option<bool> {
        let registration_allowed = self.get_parameter_value(PARAMETER_NAME_REGISTRATION_ALLOWED);

        if let Some(registration_allowed) = registration_allowed {
            if registration_allowed != *"default" {
                if let Ok(val) = registration_allowed.parse::<bool>() {
                    return Some(val);
                } else {
                    return Some(true);
                }
            } else {
                return Some(true);
            }
        }

        None
    }

    pub fn get_parameter_scrapingbee_api_key(&self) -> Option<String> {
        let scrapingbee_api_key = self.get_parameter_value(PARAMETER_NAME_SCRAPINGBEE_API_KEY);

        if let Some(scrapingbee_api_key) = scrapingbee_api_key {
            if scrapingbee_api_key != *"default" {
                return Some(scrapingbee_api_key);
            }
        }

        None
    }

    pub fn get_parameter_sendgrid_api_key(&self) -> Option<String> {
        match self.get_parameter_value(PARAMETER_NAME_SENDGRID_API_KEY) {
            None => {
                if let Ok(val) = std::env::var("SENDGRID_API_KEY") {
                    Some(val)
                } else {
                    None
                }
            }
            Some(sendgrid_api_key) => Some(sendgrid_api_key),
        }
    }

    pub fn get_parameter_value(&self, name: &str) -> Option<String> {
        for parameter in &self.parameters {
            if parameter.name == name {
                return Some(parameter.value.clone());
            }
        }

        None
    }

    pub fn set_parameters(&mut self, parameters: Vec<Parameter>) -> Config {
        self.parameters = parameters;

        self.clone()
    }
}

pub fn load(args: Args) -> Result<Config> {
    let mut database_url: Option<String> = None;
    let mut nextcloud_subdir = String::new();
    let mut ollama_host = None;
    let parameters = vec![];
    let mut port = 8080;
    let mut test_mode = false;
    let mut wasp_database_url: Option<String> = None;
    let mut web_driver_url = None;
    let mut ws_port = 8081;

    if let Ok(val) = std::env::var("DATABASE_URL") {
        database_url = Some(val);
    }

    if let Some(val) = args.database_url {
        database_url = Some(val);
    }

    if let Ok(val) = std::env::var("NEXTCLOUD_SUBDIR") {
        nextcloud_subdir = val;
    }

    if let Ok(val) = std::env::var("OLLAMA_HOST") {
        ollama_host = Some(val);
    }

    let pepper = std::env::var("OCTOPUS_PEPPER")?;
    let pepper_id = std::env::var("OCTOPUS_PEPPER_ID")?.parse::<i32>()?;

    if let Ok(val) = std::env::var("OCTOPUS_SERVER_PORT") {
        port = val.parse::<u16>()?;
    }

    if let Ok(val) = std::env::var("OCTOPUS_WS_SERVER_PORT") {
        ws_port = val.parse::<u16>()?;
    }

    if let Some(val) = args.port {
        port = val;
    }

    if let Some(val) = args.test_mode {
        test_mode = val;
    }

    if let Ok(val) = std::env::var("WASP_DATABASE_URL") {
        wasp_database_url = Some(val);
    }

    if let Some(val) = args.wasp_database_url {
        wasp_database_url = Some(val);
    }

    if let Ok(val) = std::env::var("WEB_DRIVER_URL") {
        web_driver_url = Some(val);
    }

    let config = Config::new(
        database_url.expect("Unknown database url"),
        nextcloud_subdir,
        ollama_host,
        parameters,
        pepper,
        pepper_id,
        port,
        test_mode,
        wasp_database_url.expect("Unknown wasp database url"),
        web_driver_url,
        ws_port,
    );

    Ok(config)
}
