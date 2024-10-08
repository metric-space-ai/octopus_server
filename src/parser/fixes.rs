pub fn fix_apt_get(code_lines: Vec<String>) -> Vec<String> {
    let mut parsed_code_lines = vec![];

    for code_line in code_lines {
        if code_line.contains("apt")
            && code_line.contains("install")
            && !code_line.contains("apt-get")
            && !code_line.contains("wrapt")
        {
            let new_line = code_line.replace("apt", "apt-get");
            parsed_code_lines.push(new_line);
        } else {
            parsed_code_lines.push(code_line);
        }
    }

    parsed_code_lines
}

pub fn fix_apt_install(code_lines: Vec<String>) -> Vec<String> {
    let mut parsed_code_lines = vec![];

    for code_line in code_lines {
        if code_line.contains("apt")
            && code_line.contains("install")
            && !code_line.contains("-y")
            && !code_line.contains("wrapt")
        {
            let new_line = code_line.replace("install", "install -y");
            parsed_code_lines.push(new_line);
        } else {
            parsed_code_lines.push(code_line);
        }
    }

    parsed_code_lines
}

pub fn fix_input_type_json(code_lines: Vec<String>) -> Vec<String> {
    let mut parsed_code_lines = vec![];

    for code_line in code_lines {
        if code_line.contains("input_type")
            && code_line.contains("json")
            && !code_line.contains("application/json")
            && !code_line.contains("jsonify")
        {
            let new_line = code_line.replace("json", "application/json");
            parsed_code_lines.push(new_line);
        } else {
            parsed_code_lines.push(code_line);
        }
    }

    parsed_code_lines
}

pub fn fix_methods_get(code_lines: Vec<String>) -> Vec<String> {
    let mut parsed_code_lines = vec![];

    for code_line in code_lines {
        if code_line.contains("methods") && code_line.contains("GET") {
            let new_line = code_line.replace("GET", "POST");
            parsed_code_lines.push(new_line);
        } else {
            parsed_code_lines.push(code_line);
        }
    }

    parsed_code_lines
}

pub fn fix_return_code(code_lines: Vec<String>) -> Vec<String> {
    let mut parsed_code_lines = vec![];

    for code_line in code_lines {
        if code_line.contains("return")
            && (code_line.contains("jsonify") || code_line.contains("app.response_class"))
            && !code_line.contains("200")
            && !code_line.contains("201")
            && !code_line.contains("400")
            && !code_line.contains("404")
            && !code_line.contains("500")
        {
            let new_line = format!("{code_line}, 201");
            parsed_code_lines.push(new_line);
        } else if code_line.contains("return")
            && (code_line.contains("jsonify") || code_line.contains("app.response_class"))
            && code_line.contains("200")
        {
            let new_line = code_line.replace("200", "201");
            parsed_code_lines.push(new_line);
        } else {
            parsed_code_lines.push(code_line);
        }
    }

    parsed_code_lines
}

pub fn fix_return_type_image_jpg(code_lines: Vec<String>) -> Vec<String> {
    let mut parsed_code_lines = vec![];

    for code_line in code_lines {
        if code_line.contains("return_type") && code_line.contains("image/jpg") {
            let new_line = code_line.replace("image/jpg", "image/jpeg");
            parsed_code_lines.push(new_line);
        } else {
            parsed_code_lines.push(code_line);
        }
    }

    parsed_code_lines
}

pub fn fix_return_type_string(code_lines: Vec<String>) -> Vec<String> {
    let mut parsed_code_lines = vec![];

    for code_line in code_lines {
        if code_line.contains("return_type") && code_line.contains("string") {
            let new_line = code_line.replace("string", "text/plain");
            parsed_code_lines.push(new_line);
        } else if code_line.contains("return_type") && code_line.contains("String") {
            let new_line = code_line.replace("String", "text/plain");
            parsed_code_lines.push(new_line);
        } else {
            parsed_code_lines.push(code_line);
        }
    }

    parsed_code_lines
}

pub fn fix_return_setup_status(code_lines: Vec<String>) -> Vec<String> {
    let mut parsed_code_lines = vec![];

    for code_line in code_lines {
        if code_line.contains("return")
            && code_line.contains("jsonify")
            && code_line.contains("status")
            && !code_line.contains("Performed")
        {
            let new_line = code_line.replace('}', ", \"setup\": \"Performed\"}");
            parsed_code_lines.push(new_line);
        } else {
            parsed_code_lines.push(code_line);
        }
    }

    parsed_code_lines
}

pub fn fix_type_int(code_lines: Vec<String>) -> Vec<String> {
    let mut parsed_code_lines = vec![];

    for code_line in code_lines {
        if code_line.contains("type\":")
            && code_line.contains("int")
            && !code_line.contains("integer")
        {
            let new_line = code_line.replace("int", "integer");
            parsed_code_lines.push(new_line);
        } else {
            parsed_code_lines.push(code_line);
        }
    }

    parsed_code_lines
}

pub fn fix_type_str(code_lines: Vec<String>) -> Vec<String> {
    let mut parsed_code_lines = vec![];

    for code_line in code_lines {
        if code_line.contains("type\":")
            && code_line.contains("str")
            && !code_line.contains("string")
        {
            let new_line = code_line.replace("str", "string");
            parsed_code_lines.push(new_line);
        } else {
            parsed_code_lines.push(code_line);
        }
    }

    parsed_code_lines
}

pub fn fix_urls(code_lines: Vec<String>) -> Vec<String> {
    let mut parsed_code_lines = vec![];

    for code_line in code_lines {
        if code_line.contains("route") && code_line.contains("/v1") {
            let new_line = code_line.replace("/v1", "");
            parsed_code_lines.push(new_line);
        } else {
            parsed_code_lines.push(code_line);
        }
    }

    parsed_code_lines
}
