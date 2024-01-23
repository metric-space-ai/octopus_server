use crate::{
    context::Context,
    entity::{ChatMessage, WaspApp},
    error::AppError,
    get_pwd,
    process_manager::{try_get_pid, try_kill_process, Process, ProcessState, ProcessType},
    Result, WASP_APPS_DIR,
};
use chrono::{Duration as ChronoDuration, Utc};
use port_selector::{select_free_port, Selector};
use std::{
    fs::{create_dir, remove_dir_all, remove_file, File},
    io::Write,
    path::Path,
    process::Command,
    sync::Arc,
};
use tokio::time::{sleep, Duration};
use uuid::Uuid;

pub async fn create_environment(
    context: &Arc<Context>,
    chat_message: &ChatMessage,
    mut process: Process,
    wasp_app: &WaspApp,
) -> Result<Process> {
    let pwd = get_pwd()?;

    let chat_message_id = chat_message.id;
    let full_wasp_app_dir_path = format!("{pwd}/{WASP_APPS_DIR}/{chat_message_id}");
    let dir_exists = Path::new(&full_wasp_app_dir_path).is_dir();
    if !dir_exists {
        create_dir(full_wasp_app_dir_path.clone())?;
    }

    let reserved_ports = context.process_manager.list_reserved_ports()?;

    let mut wasp_app_client_port = None;
    let mut wasp_app_server_port = None;

    while wasp_app_client_port.is_none() {
        let selector = Selector {
            check_tcp: true,
            check_udp: true,
            port_range: (20000, 65535),
            max_random_times: 100,
        };
        let port = select_free_port(selector);

        if let Some(port) = port {
            let selected_port = port.into();

            if !reserved_ports.contains(&selected_port) {
                wasp_app_client_port = Some(selected_port);
            }
        }
    }

    while wasp_app_server_port.is_none() {
        let selector = Selector {
            check_tcp: true,
            check_udp: true,
            port_range: (20000, 65535),
            max_random_times: 100,
        };
        let port = select_free_port(selector);

        if let Some(port) = port {
            let selected_port = port.into();

            if !reserved_ports.contains(&selected_port) {
                wasp_app_server_port = Some(selected_port);
            }
        }
    }

    let path = format!("{full_wasp_app_dir_path}/{chat_message_id}.zip");
    let mut file = File::create(path.clone())?;
    file.write_all(&wasp_app.code)?;

    let file = std::fs::File::open(path)?;

    let mut archive = zip::ZipArchive::new(file)?;
    let mut shortest_parent = String::new();

    for i in 0..archive.len() {
        let file = archive.by_index(i)?;
        let outpath = match file.enclosed_name() {
            Some(path) => path.to_owned(),
            None => continue,
        };

        let parent = outpath.parent();
        if let Some(parent) = parent {
            let parent = parent.to_str().ok_or(AppError::Parsing)?.to_string();
            if shortest_parent.is_empty()
                || (!shortest_parent.is_empty() && shortest_parent.len() > parent.len())
            {
                shortest_parent = parent;
            }
        }
    }

    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let outpath = match file.enclosed_name() {
            Some(path) => path.to_owned(),
            None => continue,
        };

        if (*file.name()).ends_with('/') {
            let path = outpath
                .to_str()
                .ok_or(AppError::Parsing)?
                .to_string()
                .strip_prefix(&shortest_parent)
                .ok_or(AppError::Parsing)?
                .to_string();
            let path = format!("{full_wasp_app_dir_path}/{path}");

            std::fs::create_dir_all(&path)?;
        } else {
            if let Some(parent) = outpath.parent() {
                let path = parent
                    .to_str()
                    .ok_or(AppError::Parsing)?
                    .to_string()
                    .strip_prefix(&shortest_parent)
                    .ok_or(AppError::Parsing)?
                    .to_string();
                let path = format!("{full_wasp_app_dir_path}/{path}");
                let dir_exists = Path::new(&path).is_dir();

                if !dir_exists {
                    std::fs::create_dir_all(path)?;
                }
            }

            let path = outpath
                .to_str()
                .ok_or(AppError::Parsing)?
                .to_string()
                .strip_prefix(&shortest_parent)
                .ok_or(AppError::Parsing)?
                .to_string();
            let path = format!("{full_wasp_app_dir_path}/{path}");
            let mut outfile = std::fs::File::create(&path)?;
            std::io::copy(&mut file, &mut outfile)?;
        }
    }

    let name = format!("wasp_{chat_message_id}");
    let name = name.replace('-', "_");
    context.octopus_database.create_database(&name).await?;
    let wasp_database_url = format!("{}/{name}", context.get_config().await?.wasp_database_url);

    let path = format!("{full_wasp_app_dir_path}/{chat_message_id}.sh");
    let mut file = File::create(path)?;
    file.write_fmt(format_args!("#!/bin/bash\n"))?;
    file.write_fmt(format_args!("cd {full_wasp_app_dir_path}\n"))?;

    if let Some(wasp_app_client_port) = wasp_app_client_port {
        file.write_fmt(format_args!("sed -i \"s/    port: 3000,/    port: {wasp_app_client_port},/g\" {full_wasp_app_dir_path}/src/client/vite.config.ts\n"))?;
    }
    /*
        file.write_fmt(format_args!("wasp build\n"))?;
        file.write_fmt(format_args!("cd .wasp/build/\n"))?;
    */
    file.write_fmt(format_args!(
        "DATABASE_URL=\"{wasp_database_url}\" wasp db migrate-dev --name \"initial\"\n"
    ))?;
    if let Some(wasp_app_client_port) = wasp_app_client_port {
        file.write_fmt(format_args!("sed -i \"s/    port: 3000,/    port: {wasp_app_client_port},/g\" {full_wasp_app_dir_path}/.wasp/out/web-app/vite.config.ts\n"))?;
    }

    let mut parameters = String::new();

    let octopus_api_url = context.get_config().await?.get_parameter_octopus_api_url();

    if let Some(octopus_api_url) = octopus_api_url {
        parameters.push_str(&format!("OCTOPUS_API_URL={octopus_api_url} "));
    }

    let expired_at = Utc::now() + ChronoDuration::days(365);
    let mut transaction = context.octopus_database.transaction_begin().await?;

    let session = context
        .octopus_database
        .insert_session(&mut transaction, chat_message.user_id, "", expired_at)
        .await?;

    context
        .octopus_database
        .transaction_commit(transaction)
        .await?;

    parameters.push_str(&format!("OCTOPUS_TOKEN={} ", session.id));

    let openai_api_key = context.get_config().await?.get_parameter_openai_api_key();

    if let Some(openai_api_key) = openai_api_key {
        parameters.push_str(&format!("OPENAI_API_KEY={openai_api_key} "));
    }

    if let Some(wasp_app_server_port) = wasp_app_server_port {
        file.write_fmt(format_args!("{parameters} PORT={wasp_app_server_port} DATABASE_URL=\"{wasp_database_url}\" REACT_APP_API_URL=http://127.0.0.1:{wasp_app_server_port} wasp start\n"))?;
    }

    process.client_port = wasp_app_client_port;
    process.server_port = wasp_app_server_port;
    process.state = ProcessState::EnvironmentPrepared;

    Ok(process)
}

pub fn delete_environment(chat_message: &ChatMessage) -> Result<bool> {
    let pwd = get_pwd()?;
    let path = format!("{pwd}/{WASP_APPS_DIR}/{}", chat_message.id);
    let dir_exists = Path::new(&path).is_dir();
    if dir_exists {
        let path = format!("{pwd}/{WASP_APPS_DIR}/{}/.wasp", chat_message.id);
        let dir_exists = Path::new(&path).is_dir();

        if dir_exists {
            remove_dir_all(path)?;
        }

        let path = format!("{pwd}/{WASP_APPS_DIR}/{}/src", chat_message.id);
        let dir_exists = Path::new(&path).is_dir();

        if dir_exists {
            remove_dir_all(path)?;
        }

        let path = format!("{pwd}/{WASP_APPS_DIR}/{}/.gitignore", chat_message.id);
        let file_exists = Path::new(&path).is_file();

        if file_exists {
            remove_file(path)?;
        }

        let path = format!("{pwd}/{WASP_APPS_DIR}/{}/.wasproot", chat_message.id);
        let file_exists = Path::new(&path).is_file();

        if file_exists {
            remove_file(path)?;
        }

        let path = format!(
            "{pwd}/{WASP_APPS_DIR}/{}/{}.sh",
            chat_message.id, chat_message.id
        );
        let file_exists = Path::new(&path).is_file();

        if file_exists {
            remove_file(path)?;
        }

        let path = format!(
            "{pwd}/{WASP_APPS_DIR}/{}/{}.zip",
            chat_message.id, chat_message.id
        );
        let file_exists = Path::new(&path).is_file();

        if file_exists {
            remove_file(path)?;
        }

        let path = format!("{pwd}/{WASP_APPS_DIR}/{}/README.md", chat_message.id);
        let file_exists = Path::new(&path).is_file();

        if file_exists {
            remove_file(path)?;
        }

        let path = format!("{pwd}/{WASP_APPS_DIR}/{}/main.wasp", chat_message.id);
        let file_exists = Path::new(&path).is_file();

        if file_exists {
            remove_file(path)?;
        }
    }

    Ok(true)
}

pub async fn install(
    context: &Arc<Context>,
    chat_message: &ChatMessage,
    wasp_app: WaspApp,
) -> Result<WaspApp> {
    let process = Process {
        id: chat_message.id,
        client_port: None,
        failed_connection_attempts: 0,
        last_used_at: None,
        pid: None,
        server_port: None,
        state: ProcessState::Initial,
        r#type: ProcessType::WaspApp,
    };

    let process = context.process_manager.insert_process(&process)?;

    if let Some(process) = process {
        let process = create_environment(context, chat_message, process, &wasp_app).await?;

        if process.state == ProcessState::EnvironmentPrepared {
            context.process_manager.insert_process(&process)?;
        }
    }

    Ok(wasp_app)
}

pub async fn install_and_run(
    context: Arc<Context>,
    chat_message: ChatMessage,
    wasp_app: WaspApp,
) -> Result<WaspApp> {
    if !context.get_config().await?.test_mode {
        let chat_message = stop_and_remove(context.clone(), chat_message).await?;
        let wasp_app = install(&context.clone(), &chat_message, wasp_app).await?;
        let wasp_app = run(context, &chat_message, wasp_app).await?;

        return Ok(wasp_app);
    }

    Ok(wasp_app)
}

pub async fn manage_running(context: Arc<Context>, process: Process) -> Result<()> {
    if process.state == ProcessState::Running {
        if let Some(last_used_at) = process.last_used_at {
            let now = Utc::now();
            let duration = now - last_used_at;

            if duration.num_hours() >= 12 {
                let chat_message = context
                    .octopus_database
                    .try_get_chat_message_by_id(process.id)
                    .await?;

                if let Some(chat_message) = chat_message {
                    stop(context, chat_message).await?;
                }
            }
        }
    }

    Ok(())
}

pub async fn run(
    context: Arc<Context>,
    chat_message: &ChatMessage,
    wasp_app: WaspApp,
) -> Result<WaspApp> {
    let process = context.process_manager.get_process(chat_message.id)?;

    if let Some(mut process) = process {
        if process.state == ProcessState::EnvironmentPrepared {
            let pid = try_start(chat_message.id).await?;

            if let Some(_pid) = pid {
                process.pid = pid;
                process.state = ProcessState::Running;

                let process = context.process_manager.insert_process(&process)?;

                if let Some(_process) = process {
                    return Ok(wasp_app);
                }
            }
        }
    }

    Ok(wasp_app)
}

pub async fn stop(context: Arc<Context>, chat_message: ChatMessage) -> Result<ChatMessage> {
    let pid = try_get_pid(&format!("{}.sh", chat_message.id))?;

    if let Some(pid) = pid {
        try_kill_process(pid).await?;
    }

    context.process_manager.remove_process(chat_message.id)?;

    Ok(chat_message)
}

pub async fn stop_and_remove(
    context: Arc<Context>,
    chat_message: ChatMessage,
) -> Result<ChatMessage> {
    let chat_message = stop(context, chat_message).await?;

    delete_environment(&chat_message)?;

    Ok(chat_message)
}

pub async fn try_start(chat_message_id: Uuid) -> Result<Option<i32>> {
    let working_dir = get_pwd()?;

    Command::new("/bin/bash")
        .arg(format!(
            "{working_dir}/{WASP_APPS_DIR}/{chat_message_id}/{chat_message_id}.sh"
        ))
        .arg("&>>")
        .arg(format!(
            "{working_dir}/{WASP_APPS_DIR}/{chat_message_id}/{chat_message_id}.log"
        ))
        .spawn()?;

    let mut failed_pid_get_attempts = 0;
    let pid = None;

    loop {
        let pid_tmp = try_get_pid(&format!("{chat_message_id}.sh"))?;

        if let Some(pid_tmp) = pid_tmp {
            return Ok(Some(pid_tmp));
        }

        failed_pid_get_attempts += 1;

        if failed_pid_get_attempts > 40 {
            break;
        }

        sleep(Duration::from_secs(30)).await;
    }

    Ok(pid)
}
