use crate::{
    Result, WASP_APPS_DIR,
    context::Context,
    entity::{ChatMessage, WaspApp, WaspAppInstanceType},
    error::AppError,
    get_pwd,
    process_manager::{
        Process, ProcessState, ProcessType, try_get_pid, try_kill_cgroup, try_kill_process,
    },
};
use chrono::{Duration as ChronoDuration, Utc};
use port_selector::{Selector, select_free_port};
use std::{
    fs::{File, OpenOptions, create_dir, remove_dir_all, remove_file},
    io::Write,
    path::Path,
    process::Command,
    sync::Arc,
};
use tokio::time::{Duration, sleep};
use uuid::Uuid;

pub async fn create_environment(
    context: Arc<Context>,
    chat_message_id: Uuid,
    id: &str,
    mut process: Process,
    user_id: Uuid,
    wasp_app: &WaspApp,
) -> Result<Process> {
    let pwd = get_pwd()?;

    let full_wasp_app_dir_path = format!("{pwd}/{WASP_APPS_DIR}/{id}");
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

    let path = format!("{full_wasp_app_dir_path}/{id}.zip");
    let mut file = File::create(path.clone())?;
    file.write_all(&wasp_app.code)?;

    let file = std::fs::File::open(path)?;

    let mut archive = zip::ZipArchive::new(file)?;
    let mut shortest_parent = String::new();

    for i in 0..archive.len() {
        let file = archive.by_index(i)?;
        let outpath = match file.enclosed_name() {
            Some(path) => path.clone(),
            None => continue,
        };

        let parent = outpath.parent();
        if let Some(parent) = parent {
            let parent = parent.to_str().ok_or(AppError::Parsing)?.to_string();

            if !(parent.starts_with("src") || parent.starts_with("__MACOSX"))
                && (shortest_parent.is_empty()
                    || (!shortest_parent.is_empty() && shortest_parent.len() > parent.len()))
            {
                shortest_parent = parent;
            }
        }
    }

    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let outpath = match file.enclosed_name() {
            Some(path) => path.clone(),
            None => continue,
        };

        if (*file.name()).ends_with('/') {
            let path = outpath.to_str().ok_or(AppError::Parsing)?.to_string();

            if !path.starts_with("__MACOSX") {
                let path = if path.starts_with(&shortest_parent) {
                    path.strip_prefix(&shortest_parent)
                        .ok_or(AppError::Parsing)?
                        .to_string()
                } else {
                    path
                };
                let path = format!("{full_wasp_app_dir_path}/{path}");

                std::fs::create_dir_all(&path)?;
            }
        } else {
            if let Some(parent) = outpath.parent() {
                let path = parent.to_str().ok_or(AppError::Parsing)?.to_string();

                if !path.starts_with("__MACOSX") {
                    let path = if path.starts_with(&shortest_parent) {
                        path.strip_prefix(&shortest_parent)
                            .ok_or(AppError::Parsing)?
                            .to_string()
                    } else {
                        path
                    };

                    let path = format!("{full_wasp_app_dir_path}/{path}");
                    let dir_exists = Path::new(&path).is_dir();

                    if !dir_exists {
                        std::fs::create_dir_all(path)?;
                    }
                }
            }

            let path = outpath.to_str().ok_or(AppError::Parsing)?.to_string();

            if !path.starts_with("__MACOSX") {
                let path = if path.starts_with(&shortest_parent) {
                    path.strip_prefix(&shortest_parent)
                        .ok_or(AppError::Parsing)?
                        .to_string()
                } else {
                    path
                };

                let path = format!("{full_wasp_app_dir_path}/{path}");
                let mut outfile = std::fs::File::create(&path)?;
                std::io::copy(&mut file, &mut outfile)?;
            }
        }
    }

    let name = format!("wasp_{id}");
    let name = name.replace('-', "_");
    context.octopus_database.create_database(&name).await?;
    let wasp_database_url = format!("{}/{name}", context.get_config().await?.wasp_database_url);

    let path = format!("{full_wasp_app_dir_path}/{id}.sh");
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

    parameters.push_str(&format!(
        "PG_BOSS_NEW_OPTIONS=\"{{\\\"connectionString\\\":\\\"{wasp_database_url}\\\"}}\" "
    ));

    let octopus_api_url = context.get_config().await?.get_parameter_octopus_api_url();

    if let Some(octopus_api_url) = octopus_api_url {
        parameters.push_str(&format!("OCTOPUS_API_URL={octopus_api_url} "));
        parameters.push_str(&format!("REACT_APP_OCTOPUS_API_URL={octopus_api_url} "));
    }

    let expired_at = Utc::now() + ChronoDuration::try_days(365).ok_or(AppError::FromTime)?;
    let mut transaction = context.octopus_database.transaction_begin().await?;

    let session = context
        .octopus_database
        .insert_session(&mut transaction, user_id, "", expired_at)
        .await?;

    context
        .octopus_database
        .transaction_commit(transaction)
        .await?;

    parameters.push_str(&format!("OCTOPUS_TOKEN={} ", session.id));
    parameters.push_str(&format!("REACT_APP_OCTOPUS_TOKEN={} ", session.id));

    let ollama_host = context.get_config().await?.ollama_host;

    if let Some(ollama_host) = ollama_host {
        parameters.push_str(&format!("OLLAMA_HOST={ollama_host} "));
    }

    let main_llm_openai_api_key = context
        .get_config()
        .await?
        .get_parameter_main_llm_openai_api_key();

    if let Some(main_llm_openai_api_key) = main_llm_openai_api_key {
        parameters.push_str(&format!(
            "REACT_APP_OPENAI_API_KEY={main_llm_openai_api_key} "
        ));
    }

    if let Some(wasp_app_server_port) = wasp_app_server_port {
        file.write_fmt(format_args!("{parameters} PORT={wasp_app_server_port} DATABASE_URL=\"{wasp_database_url}\" REACT_APP_API_URL=http://127.0.0.1:{wasp_app_server_port} wasp start\n"))?;
    }

    parameters.push_str(&format!("REACT_APP_CHAT_MESSAGE_ID={chat_message_id} "));

    process.client_port = wasp_app_client_port;
    process.server_port = wasp_app_server_port;
    process.state = ProcessState::EnvironmentPrepared;

    Ok(process)
}

pub fn delete_environment(id: &str) -> Result<bool> {
    let pwd = get_pwd()?;
    let full_wasp_app_dir_path = format!("{pwd}/{WASP_APPS_DIR}/{id}");
    let dir_exists = Path::new(&full_wasp_app_dir_path).is_dir();
    if dir_exists {
        let path = format!("{full_wasp_app_dir_path}/.wasp");
        let dir_exists = Path::new(&path).is_dir();

        if dir_exists {
            remove_dir_all(path)?;
        }

        let path = format!("{full_wasp_app_dir_path}/src");
        let dir_exists = Path::new(&path).is_dir();

        if dir_exists {
            remove_dir_all(path)?;
        }

        let path = format!("{full_wasp_app_dir_path}/.gitignore");
        let file_exists = Path::new(&path).is_file();

        if file_exists {
            remove_file(path)?;
        }

        let path = format!("{full_wasp_app_dir_path}/.wasproot");
        let file_exists = Path::new(&path).is_file();

        if file_exists {
            remove_file(path)?;
        }

        let path = format!("{full_wasp_app_dir_path}/{id}.sh");
        let file_exists = Path::new(&path).is_file();

        if file_exists {
            remove_file(path)?;
        }

        let path = format!("{full_wasp_app_dir_path}/{id}.zip");
        let file_exists = Path::new(&path).is_file();

        if file_exists {
            remove_file(path)?;
        }

        let path = format!("{full_wasp_app_dir_path}/README.md");
        let file_exists = Path::new(&path).is_file();

        if file_exists {
            remove_file(path)?;
        }

        let path = format!("{full_wasp_app_dir_path}/main.wasp");
        let file_exists = Path::new(&path).is_file();

        if file_exists {
            remove_file(path)?;
        }
    }

    Ok(true)
}

pub async fn install(
    context: &Arc<Context>,
    chat_message_id: Uuid,
    id: &str,
    user_id: Uuid,
    wasp_app: WaspApp,
) -> Result<WaspApp> {
    let process = Process {
        id: id.to_string(),
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
        let process = create_environment(
            context.clone(),
            chat_message_id,
            id,
            process,
            user_id,
            &wasp_app,
        )
        .await?;

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
        let id = match wasp_app.instance_type {
            WaspAppInstanceType::Private => chat_message.id.to_string(),
            WaspAppInstanceType::Shared => wasp_app.id.to_string(),
            WaspAppInstanceType::User => format!("{}-{}", chat_message.user_id, wasp_app.id),
        };
        stop_and_remove(context.clone(), &id).await?;
        let wasp_app = install(
            &context.clone(),
            chat_message.id,
            &id,
            chat_message.user_id,
            wasp_app,
        )
        .await?;
        run(context, &id).await?;

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
                let chat_message_id = Uuid::parse_str(&process.id)?;
                let chat_message = context
                    .octopus_database
                    .try_get_chat_message_by_id(chat_message_id)
                    .await?;

                if let Some(chat_message) = chat_message {
                    stop(context, &chat_message.id.to_string()).await?;
                }
            }
        }
    }

    Ok(())
}

pub async fn run(context: Arc<Context>, id: &str) -> Result<&str> {
    let process = context.process_manager.get_process(id)?;

    if let Some(mut process) = process {
        if process.state == ProcessState::EnvironmentPrepared {
            let pid = try_start(id).await?;

            if let Some(_pid) = pid {
                process.pid = pid;
                process.state = ProcessState::Running;

                let process = context.process_manager.insert_process(&process)?;

                if let Some(_process) = process {
                    return Ok(id);
                }
            }
        }
    }

    Ok(id)
}

pub async fn stop(context: Arc<Context>, id: &str) -> Result<&str> {
    let pid = try_get_pid(&format!("{id}.sh"))?;

    if let Some(pid) = pid {
        try_kill_process(pid).await?;
    }

    try_kill_cgroup(id).await?;

    context.process_manager.remove_process(id)?;

    Ok(id)
}

pub async fn stop_and_remove(context: Arc<Context>, id: &str) -> Result<&str> {
    let id = stop(context, id).await?;

    delete_environment(id)?;

    Ok(id)
}

pub async fn try_start(id: &str) -> Result<Option<i32>> {
    let working_dir = get_pwd()?;
    let full_wasp_app_dir_path = format!("{working_dir}/{WASP_APPS_DIR}/{id}");

    let path = format!("/sys/fs/cgroup/{id}");
    let dir_exists = Path::new(&path).is_dir();

    if dir_exists {
        Command::new("/usr/bin/cgdelete")
            .arg(format!("cpu:{id}"))
            .output()?;
    }

    Command::new("/usr/bin/cgcreate")
        .arg("-g")
        .arg(format!("cpu:{id}"))
        .output()?;

    let stderr_file = OpenOptions::new()
        .append(true)
        .create(true)
        .write(true)
        .open(format!("{full_wasp_app_dir_path}/{id}.log"))?;

    let stdout_file = OpenOptions::new()
        .append(true)
        .create(true)
        .write(true)
        .open(format!("{full_wasp_app_dir_path}/{id}.log"))?;

    Command::new("/usr/bin/cgexec")
        .arg("-g")
        .arg(format!("cpu:{id}"))
        .arg("/bin/bash")
        .arg(format!("{full_wasp_app_dir_path}/{id}.sh"))
        .stderr(stderr_file)
        .stdout(stdout_file)
        .spawn()?;

    let mut failed_pid_get_attempts = 0;
    let pid = None;

    loop {
        let pid_tmp = try_get_pid(&format!("{id}.sh"))?;

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
