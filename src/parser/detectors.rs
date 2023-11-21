use crate::Result;

pub fn detect_app_threaded(code_lines: &Vec<String>) -> Result<bool> {
    let mut app_threaded = true;

    for code_line in code_lines {
        if code_line.contains("app.run")
            && code_line.contains("threaded")
            && code_line.contains("False")
        {
            app_threaded = false;
        }
    }

    Ok(app_threaded)
}

pub fn detect_last_return_jsonify_line(code_lines: &[String]) -> Result<usize> {
    let mut last_return_jsonify_line = 0;

    for (i, code_line) in code_lines.iter().enumerate() {
        if code_line.contains("return") && code_line.contains("jsonify") {
            last_return_jsonify_line = i;
        }
    }

    Ok(last_return_jsonify_line)
}

pub fn detect_is_ai_service(code_lines: &Vec<String>) -> Result<bool> {
    let mut dependencies = false;
    let mut functions = false;
    let mut setup = false;

    for code_line in code_lines {
        if code_line.contains("dependencies") && code_line.contains('=') && code_line.contains('[')
        {
            dependencies = true;
        }
    }

    for code_line in code_lines {
        if code_line.contains("functions") && code_line.contains('[') {
            functions = true;
        }
    }

    for code_line in code_lines {
        if code_line.contains("app.route") && code_line.contains("setup") {
            setup = true;
        }
    }

    if dependencies && functions && setup {
        return Ok(true);
    }

    Ok(false)
}
