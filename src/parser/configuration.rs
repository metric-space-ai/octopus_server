use crate::entity::AiServiceRequiredPythonVersion;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Configuration {
    pub required_python_version: Option<AiServiceRequiredPythonVersion>,
    pub functions: Vec<Function>,
    pub models: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct Function {
    pub description: String,
    pub input_type: String,
    pub name: String,
    pub parameters: serde_json::Value,
    pub return_type: String,
}

#[derive(Debug, Deserialize)]
pub struct Model {
    pub name: Option<String>,
}

pub fn locate_config(code_lines: &[String]) -> Vec<String> {
    let mut config_section_identified = false;
    let mut config_section_identified_line = 0;
    let mut config_lines = vec![];
    let mut parsed_config_lines = vec![];
    for (i, code_line) in code_lines.iter().enumerate() {
        if code_line.contains("config")
            && code_line.contains('=')
            && (code_line.contains("'''") || code_line.contains("\"\"\""))
        {
            if code_line.contains('{') {
                config_lines.push("{".to_string());
            }
            config_section_identified = true;
            config_section_identified_line = i;
        }

        if config_section_identified {
            config_lines.push(code_line.clone());
        }

        if config_section_identified
            && config_section_identified_line < i
            && (code_line.contains("'''") || code_line.contains("\"\"\""))
            && !config_lines.is_empty()
        {
            if code_line.contains(']') {
                config_lines.push("]".to_string());
            }
            if code_line.contains('}') {
                config_lines.push("}".to_string());
            }
            config_section_identified = false;
        }
    }

    for config_line in config_lines {
        if !(config_line.contains("'''") || config_line.contains("\"\"\"")) {
            parsed_config_lines.push(config_line);
        }
    }

    parsed_config_lines
}
