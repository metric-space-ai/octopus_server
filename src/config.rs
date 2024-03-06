use crate::{
    entity::{
        Parameter, PARAMETER_NAME_AI_MODEL, PARAMETER_NAME_AI_SYSTEM_PROMPT,
        PARAMETER_NAME_AZURE_OPENAI_API_KEY, PARAMETER_NAME_AZURE_OPENAI_DEPLOYMENT_ID,
        PARAMETER_NAME_AZURE_OPENAI_ENABLED, PARAMETER_NAME_HUGGING_FACE_TOKEN_ACCESS,
        PARAMETER_NAME_NEXTCLOUD_PASSWORD, PARAMETER_NAME_NEXTCLOUD_USERNAME,
        PARAMETER_NAME_OCTOPUS_API_URL, PARAMETER_NAME_OCTOPUS_WS_URL,
        PARAMETER_NAME_OPENAI_API_KEY, PARAMETER_NAME_REGISTRATION_ALLOWED,
        PARAMETER_NAME_SENDGRID_API_KEY,
    },
    Args, Result,
};

#[derive(Clone, Debug)]
pub struct Config {
    pub database_url: String,
    pub parameters: Vec<Parameter>,
    pub pepper: String,
    pub pepper_id: i32,
    pub port: u16,
    pub test_mode: bool,
    pub wasp_database_url: String,
    pub ws_port: u16,
}

impl Config {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        database_url: String,
        parameters: Vec<Parameter>,
        pepper: String,
        pepper_id: i32,
        port: u16,
        test_mode: bool,
        wasp_database_url: String,
        ws_port: u16,
    ) -> Self {
        Self {
            database_url,
            parameters,
            pepper,
            pepper_id,
            port,
            test_mode,
            wasp_database_url,
            ws_port,
        }
    }

    pub fn get_parameter_ai_model(&self) -> Option<String> {
        let ai_model = self.get_parameter_value(PARAMETER_NAME_AI_MODEL);

        if let Some(ai_model) = ai_model {
            if ai_model != *"default" {
                return Some(ai_model);
            }
        }

        None
    }

    pub fn get_parameter_ai_system_prompt(&self) -> Option<String> {
        let ai_system_prompt = self.get_parameter_value(PARAMETER_NAME_AI_SYSTEM_PROMPT);

        if let Some(ai_system_prompt) = ai_system_prompt {
            if ai_system_prompt != *"default" {
                return Some(ai_system_prompt);
            }
        }

        None
    }

    pub fn get_parameter_azure_openai_api_key(&self) -> Option<String> {
        match self.get_parameter_value(PARAMETER_NAME_AZURE_OPENAI_API_KEY) {
            None => {
                if let Ok(val) = std::env::var("AZURE_OPENAI_API_KEY") {
                    Some(val)
                } else {
                    None
                }
            }
            Some(azure_openai_api_key) => Some(azure_openai_api_key),
        }
    }

    pub fn get_parameter_azure_openai_deployment_id(&self) -> Option<String> {
        match self.get_parameter_value(PARAMETER_NAME_AZURE_OPENAI_DEPLOYMENT_ID) {
            None => {
                if let Ok(val) = std::env::var("AZURE_OPENAI_DEPLOYMENT_ID") {
                    Some(val)
                } else {
                    None
                }
            }
            Some(azure_openai_deployment_id) => Some(azure_openai_deployment_id),
        }
    }

    pub fn get_parameter_azure_openai_enabled(&self) -> bool {
        match self.get_parameter_value(PARAMETER_NAME_AZURE_OPENAI_ENABLED) {
            None => {
                let val = std::env::var("AZURE_OPENAI_ENABLED");
                if let Ok(val) = val {
                    if let Ok(val) = val.parse::<bool>() {
                        val
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            Some(azure_openai_enabled) => {
                let parse_result = azure_openai_enabled.parse::<bool>();

                parse_result.unwrap_or(false)
            }
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

    pub fn get_parameter_nextcloud_password(&self) -> Option<String> {
        self.get_parameter_value(PARAMETER_NAME_NEXTCLOUD_PASSWORD)
    }

    pub fn get_parameter_nextcloud_username(&self) -> Option<String> {
        self.get_parameter_value(PARAMETER_NAME_NEXTCLOUD_USERNAME)
    }

    pub fn get_parameter_octopus_api_url(&self) -> Option<String> {
        self.get_parameter_value(PARAMETER_NAME_OCTOPUS_API_URL)
    }

    pub fn get_parameter_octopus_ws_url(&self) -> Option<String> {
        self.get_parameter_value(PARAMETER_NAME_OCTOPUS_WS_URL)
    }

    pub fn get_parameter_openai_api_key(&self) -> Option<String> {
        match self.get_parameter_value(PARAMETER_NAME_OPENAI_API_KEY) {
            None => {
                if let Ok(val) = std::env::var("OPENAI_API_KEY") {
                    Some(val)
                } else {
                    None
                }
            }
            Some(openai_api_key) => Some(openai_api_key),
        }
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
    let parameters = vec![];
    let mut port = 8080;
    let mut test_mode = false;
    let mut wasp_database_url: Option<String> = None;
    let mut ws_port = 8081;

    if let Ok(val) = std::env::var("DATABASE_URL") {
        database_url = Some(val);
    }

    if let Some(val) = args.database_url {
        database_url = Some(val);
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

    let config = Config::new(
        database_url.expect("Unknown database url"),
        parameters,
        pepper,
        pepper_id,
        port,
        test_mode,
        wasp_database_url.expect("Unknown wasp database url"),
        ws_port,
    );

    Ok(config)
}
