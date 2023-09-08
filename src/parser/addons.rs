use crate::Result;

pub async fn add_health_check(code_lines: Vec<String>) -> Result<Vec<String>> {
    let mut health_check_present = false;

    for code_line in &code_lines {
        if code_line.contains("app.route") && code_line.contains("health-check") {
            health_check_present = true;
        }
    }

    if !health_check_present {
        let mut parsed_code_lines = vec![];

        for code_line in code_lines {
            if code_line.contains("app.route") && code_line.contains("setup") {
                parsed_code_lines
                    .push("@app.route(\"/health-check\", methods=[\"GET\"])".to_string());
                parsed_code_lines.push("def health_check():".to_string());
                parsed_code_lines.push("    return {\"status\": \"Ok\"}, 200".to_string());
                parsed_code_lines.push("".to_string());
                parsed_code_lines.push(code_line);
            } else {
                parsed_code_lines.push(code_line);
            }
        }

        return Ok(parsed_code_lines);
    }

    Ok(code_lines)
}
