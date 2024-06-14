use crate::{error::AppError, Result};
use uuid::Uuid;

pub fn cut_code(code_lines: &[String], line: usize) -> Vec<String> {
    let mut parsed_code_lines = vec![];

    for (i, code_line) in code_lines.iter().enumerate() {
        if i <= line {
            parsed_code_lines.push(code_line.to_string());
        }
    }

    parsed_code_lines
}

pub fn replace_device_map(code_lines: Vec<String>, device_map: &serde_json::Value) -> Vec<String> {
    let mut parsed_code_lines = vec![];
    let mut remove_mode = false;
    let mut ends_in_same_line = false;

    for code_line in code_lines {
        if code_line.contains("\"device_map\":") {
            remove_mode = true;
            if code_line.contains('}') {
                ends_in_same_line = true;
            }
            parsed_code_lines.push(format!("    \"device_map\": {device_map},"));
        }
        if !remove_mode {
            parsed_code_lines.push(code_line);
        } else if code_line.contains('}') {
            remove_mode = false;
        }
        if ends_in_same_line {
            remove_mode = false;
        }
    }

    parsed_code_lines
}

pub fn replace_function_names(code_lines: &[String], ai_service_id: Uuid) -> Result<Vec<String>> {
    let mut function_names = vec![];
    let mut parsed_code_lines = vec![];
    let mut functions_section_identified = false;

    for code_line in code_lines {
        if code_line.contains("\"functions\":") {
            functions_section_identified = true;
        }
        if code_line.contains("\"models\":") {
            functions_section_identified = false;
        }
        if code_line.contains("\"tokenizer\":") {
            functions_section_identified = false;
        }
        if code_line.contains("json.loads(") {
            functions_section_identified = false;
        }
        if code_line.contains("app = Flask") {
            functions_section_identified = false;
        }

        if functions_section_identified && code_line.contains("\"name\":") {
            let name = (*code_line
                .split(':')
                .collect::<Vec<&str>>()
                .last()
                .ok_or(AppError::Parsing)?)
            .to_string()
            .strip_prefix(" \"")
            .ok_or(AppError::Parsing)?
            .to_string()
            .strip_suffix("\",")
            .ok_or(AppError::Parsing)?
            .to_string();

            function_names.push(name);
        }
    }

    let mut last_saved_line = 0;

    for (i, code_line) in code_lines.iter().enumerate() {
        let mut was_replaced = false;

        for function_name in &function_names {
            if code_line.contains(function_name)
                && (code_line.contains("name\":") || code_line.contains("app.route"))
                && !code_line.contains("def")
                && !was_replaced
            {
                let new_function_name = function_name.to_lowercase();
                let new_line = code_line.replace(
                    function_name,
                    &format!("{ai_service_id}-{new_function_name}"),
                );
                parsed_code_lines.push(new_line);
                last_saved_line = i;
                was_replaced = true;
            }
        }

        if i == 0 || last_saved_line < i {
            parsed_code_lines.push(code_line.clone());
        }
    }

    Ok(parsed_code_lines)
}
/*
pub fn replace_pip(code_lines: Vec<String>) -> Vec<String> {
    let mut parsed_code_lines = vec![];

    for code_line in code_lines {
        if code_line.contains("pip")
            && code_line.contains("install")
            && !code_line.contains("accelerate")
            && !code_line.contains("bpy")
            && !code_line.contains("nc_py_api")
            && !code_line.contains("reduct-py")
            && !code_line.contains("tqdm")
        {
            let new_line = code_line.replace("pip", "mamba");
            parsed_code_lines.push(new_line);
        } else {
            parsed_code_lines.push(code_line);
        }
    }

    parsed_code_lines
}
*/
pub fn replace_print(code_lines: Vec<String>) -> Vec<String> {
    let mut parsed_code_lines = vec![];

    for code_line in code_lines {
        if code_line.contains("print(") {
            let new_line = code_line.replace("print(", "logging.info(");
            parsed_code_lines.push(new_line);
        } else {
            parsed_code_lines.push(code_line);
        }
    }

    parsed_code_lines
}
