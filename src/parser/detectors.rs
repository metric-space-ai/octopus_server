use crate::Result;

pub async fn detect_app_threaded(code_lines: &Vec<String>) -> Result<bool> {
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

pub async fn detect_last_return_jsonify_line(code_lines: &[String]) -> Result<usize> {
    let mut last_return_jsonify_line = 0;

    for (i, code_line) in code_lines.iter().enumerate() {
        if code_line.contains("return") && code_line.contains("jsonify") {
            last_return_jsonify_line = i;
        }
    }

    Ok(last_return_jsonify_line)
}
