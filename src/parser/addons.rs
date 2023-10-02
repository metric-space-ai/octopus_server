use crate::{entity::AiService, get_pwd, Result, SERVICES_DIR};

pub async fn add_argparse(code_lines: Vec<String>) -> Result<Vec<String>> {
    let mut argparse_present = false;

    for code_line in &code_lines {
        if code_line.contains("argparse.ArgumentParser") {
            argparse_present = true;
        }
    }

    if !argparse_present {
        let mut parsed_code_lines = code_lines;

        parsed_code_lines.push(String::new());
        parsed_code_lines.push("import argparse".to_string());
        parsed_code_lines
            .push("parser = argparse.ArgumentParser(description=\"AI Service\")".to_string());
        parsed_code_lines.push("parser.add_argument(\"--host\", type=str, default=\"127.0.0.1\", help=\"set the host for service\")".to_string());
        parsed_code_lines.push("parser.add_argument(\"--port\", type=int, default=\"5000\", help=\"set the port for the service\")".to_string());
        parsed_code_lines.push("args = parser.parse_args()".to_string());

        return Ok(parsed_code_lines);
    }

    Ok(code_lines)
}

pub async fn add_daemon(
    ai_service: &AiService,
    app_threaded: bool,
    code_lines: Vec<String>,
) -> Result<Vec<String>> {
    let mut daemon_present = false;

    for code_line in &code_lines {
        if code_line.contains("daemon.DaemonContext") {
            daemon_present = true;
        }
    }

    if !daemon_present {
        let pwd = get_pwd().await?;

        let mut parsed_code_lines = code_lines;

        parsed_code_lines.push(String::new());
        parsed_code_lines.push("import daemon".to_string());
        parsed_code_lines.push(format!(
            "with daemon.DaemonContext(working_directory=\"{pwd}/{SERVICES_DIR}/{}/\", files_preserve = [fh.stream]):",
            ai_service.id
        ));
        if app_threaded {
            parsed_code_lines
                .push("    app.run(host = args.host, port = args.port, threaded=True)".to_string());
        } else {
            parsed_code_lines.push(
                "    app.run(host = args.host, port = args.port, threaded=False)".to_string(),
            );
        }

        return Ok(parsed_code_lines);
    }

    Ok(code_lines)
}

pub async fn add_handle_exception(code_lines: Vec<String>) -> Result<Vec<String>> {
    let mut handle_exception_present = false;

    for code_line in &code_lines {
        if code_line.contains("app.errorhandler") && code_line.contains("Exception") {
            handle_exception_present = true;
        }
    }

    if !handle_exception_present {
        let mut parsed_code_lines = vec![];

        for code_line in code_lines {
            if code_line.contains("app.route") && code_line.contains("health-check") {
                parsed_code_lines.push("@app.errorhandler(Exception)".to_string());
                parsed_code_lines.push("def handle_exception(e):".to_string());
                parsed_code_lines.push("    return jsonify(error=str(e)), 500".to_string());
                parsed_code_lines.push(String::new());
                parsed_code_lines.push(code_line);
            } else {
                parsed_code_lines.push(code_line);
            }
        }

        return Ok(parsed_code_lines);
    }

    Ok(code_lines)
}

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
                parsed_code_lines.push(String::new());
                parsed_code_lines.push(code_line);
            } else {
                parsed_code_lines.push(code_line);
            }
        }

        return Ok(parsed_code_lines);
    }

    Ok(code_lines)
}

pub async fn add_logging(
    ai_service: &AiService,
    mut code_lines: Vec<String>,
) -> Result<Vec<String>> {
    let mut logging_present = false;

    for code_line in &code_lines {
        if code_line.contains("logging.basicConfig") {
            logging_present = true;
        }
    }

    if !logging_present {
        let pwd = get_pwd().await?;

        let mut parsed_code_lines = vec![];

        parsed_code_lines.push("import logging".to_string());

        parsed_code_lines.push("logger = logging.getLogger()".to_string());
        parsed_code_lines.push("logger.setLevel(logging.INFO)".to_string());
        parsed_code_lines.push(format!(
            "fh = logging.FileHandler(\"{pwd}/{SERVICES_DIR}/{}/{}.log\")",
            ai_service.id, ai_service.id
        ));
        parsed_code_lines.push("logger.addHandler(fh)".to_string());

        parsed_code_lines.push(String::new());

        parsed_code_lines.append(&mut code_lines);

        return Ok(parsed_code_lines);
    }

    Ok(code_lines)
}
