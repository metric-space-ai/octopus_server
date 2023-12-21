use crate::{
    context::Context,
    entity::{ChatMessage, WaspApp},
    error::AppError,
    get_pwd,
    process_manager::{try_get_pid, Process, ProcessState, ProcessType},
    Result, WASP_APPS_DIR,
};
use port_selector::{select_free_port, Selector};
use std::{
    fs::{create_dir, File},
    io::Write,
    path::Path,
    process::Command,
    sync::Arc,
};
use tokio::time::{sleep, Duration};
use uuid::Uuid;

pub fn create_environment(
    context: Arc<Context>,
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
            let selected_port = i32::try_from(port)?;

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
            let selected_port = i32::try_from(port)?;

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
            let mut outfile = std::fs::File::create(&path).unwrap();
            std::io::copy(&mut file, &mut outfile).unwrap();
        }
    }

    let path = format!("{full_wasp_app_dir_path}/{chat_message_id}.sh");
    let mut file = File::create(path)?;
    file.write_fmt(format_args!("#!/bin/bash\n"))?;
    file.write_fmt(format_args!("cd {full_wasp_app_dir_path}\n"))?;
    file.write_fmt(format_args!("wasp db migrate-dev\n"))?;
    if let Some(wasp_app_client_port) = wasp_app_client_port {
        file.write_fmt(format_args!("sed -i \"s/    port: 3000,/    port: {wasp_app_client_port},/g\" {full_wasp_app_dir_path}/.wasp/out/web-app/vite.config.ts\n"))?;
    }
    if let Some(wasp_app_server_port) = wasp_app_server_port {
        file.write_fmt(format_args!("PORT={wasp_app_server_port} wasp start\n"))?;
    }

    process.client_port = wasp_app_client_port;
    process.server_port = wasp_app_server_port;
    process.state = ProcessState::EnvironmentPrepared;

    Ok(process)
}

pub async fn install(
    context: Arc<Context>,
    chat_message: &ChatMessage,
    wasp_app: WaspApp,
) -> Result<WaspApp> {
    let process = Process {
        id: chat_message.id,
        client_port: None,
        failed_connection_attempts: 0,
        pid: None,
        server_port: None,
        state: ProcessState::Initial,
        r#type: ProcessType::WaspApp,
    };

    let process = context.process_manager.insert_process(process)?;

    if let Some(process) = process {
        let process = create_environment(context.clone(), chat_message, process, &wasp_app)?;

        if process.state == ProcessState::EnvironmentPrepared {
            context.process_manager.insert_process(process)?;
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
        let wasp_app = install(context.clone(), &chat_message, wasp_app).await?;
        let wasp_app = run(context, &chat_message, wasp_app).await?;

        return Ok(wasp_app);
    }

    Ok(wasp_app)
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

                let process = context.process_manager.insert_process(process)?;

                if let Some(_process) = process {
                    return Ok(wasp_app);
                }
            }
        }
    }

    Ok(wasp_app)
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
