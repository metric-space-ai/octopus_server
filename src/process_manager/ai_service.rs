use crate::{
    ai,
    context::Context,
    entity::{
        AiService, AiServiceHealthCheckStatus, AiServiceRequiredPythonVersion,
        AiServiceSetupStatus, AiServiceStatus, ROLE_COMPANY_ADMIN_USER,
    },
    error::AppError,
    get_pwd, parser,
    process_manager::{
        try_get_pid, try_kill_cgroup, try_kill_process, Process, ProcessState, ProcessType,
    },
    Result, SERVICES_DIR,
};
use chrono::{Duration as ChronoDuration, Utc};
use std::{
    fs::{create_dir, remove_dir_all, File, OpenOptions},
    io::Write,
    path::Path,
    process::Command,
    sync::Arc,
};
use tokio::time::{sleep, Duration};
use uuid::Uuid;

pub async fn create_environment(ai_service: &AiService, context: Arc<Context>) -> Result<bool> {
    let pwd = get_pwd()?;

    let ai_service_id = ai_service.id;
    let ai_service_port = ai_service.port;
    let full_service_dir_path = format!("{pwd}/{SERVICES_DIR}/{ai_service_id}");
    let dir_exists = Path::new(&full_service_dir_path).is_dir();
    if !dir_exists {
        create_dir(full_service_dir_path.clone())?;
    }

    let path = format!("{full_service_dir_path}/{ai_service_id}.py");
    let mut file = File::create(path)?;
    if let Some(processed_function_body) = &ai_service.processed_function_body {
        file.write_all(processed_function_body.as_bytes())?;
    }

    let path = format!("{full_service_dir_path}/{ai_service_id}.sh");
    let mut file = File::create(path)?;
    file.write_fmt(format_args!("#!/bin/bash\n"))?;
    file.write_fmt(format_args!("cd {full_service_dir_path}\n"))?;
    file.write_fmt(format_args!(". $HOME/.bashrc\n"))?;
    file.write_fmt(format_args!(". /opt/conda/etc/profile.d/conda.sh\n"))?;
    file.write_fmt(format_args!(
        "if [ ! -d \"{full_service_dir_path}/bin\" ]\n"
    ))?;
    file.write_fmt(format_args!("then\n"))?;

    let python = match ai_service.required_python_version {
        AiServiceRequiredPythonVersion::Cp310 => "3.10",
        AiServiceRequiredPythonVersion::Cp311 => "3.11",
        AiServiceRequiredPythonVersion::Cp312 => "3.12",
    };

    file.write_fmt(format_args!(
        "conda create --yes --prefix {full_service_dir_path} python={python}\n"
    ))?;

    file.write_fmt(format_args!("fi\n"))?;
    file.write_fmt(format_args!("conda activate {full_service_dir_path}\n"))?;

    let mut parameters = String::new();

    let hugging_face_token_access = context
        .get_config()
        .await?
        .get_parameter_hugging_face_token_access();

    if let Some(hugging_face_token_access) = hugging_face_token_access {
        parameters.push_str(&format!(
            "HUGGING_FACE_TOKEN_ACCESS={hugging_face_token_access} "
        ));
    }

    let nextcloud_subdir = context.get_config().await?.nextcloud_subdir;

    parameters.push_str(&format!("NC_SUBDIR={nextcloud_subdir} "));

    let nextcloud_url = context.get_config().await?.get_parameter_nextcloud_url();

    if let Some(nextcloud_url) = nextcloud_url {
        parameters.push_str(&format!("NC_URL={nextcloud_url} "));
    }

    let nextcloud_username = context
        .get_config()
        .await?
        .get_parameter_nextcloud_username();

    if let Some(nextcloud_username) = nextcloud_username {
        parameters.push_str(&format!("NC_USERNAME={nextcloud_username} "));
    }

    let nextcloud_password = context
        .get_config()
        .await?
        .get_parameter_nextcloud_password();

    if let Some(nextcloud_password) = nextcloud_password {
        parameters.push_str(&format!("NC_PASSWORD={nextcloud_password} "));
    }

    let ollama_host = context.get_config().await?.ollama_host;

    if let Some(ollama_host) = ollama_host {
        parameters.push_str(&format!("OLLAMA_HOST={ollama_host} "));
    }

    let openai_api_key = context.get_config().await?.get_parameter_openai_api_key();

    if let Some(openai_api_key) = openai_api_key {
        parameters.push_str(&format!("OPENAI_API_KEY={openai_api_key} "));
    }

    let scrapingbee_api_key = context
        .get_config()
        .await?
        .get_parameter_scrapingbee_api_key();

    if let Some(scrapingbee_api_key) = scrapingbee_api_key {
        parameters.push_str(&format!("SCRAPINGBEE_API_KEY={scrapingbee_api_key} "));
    }

    let company = context.octopus_database.try_get_company_primary().await?;

    if let Some(company) = company {
        let user = context
            .octopus_database
            .try_get_user_by_company_id_and_role(company.id, ROLE_COMPANY_ADMIN_USER)
            .await?;

        if let Some(user) = user {
            let expired_at =
                Utc::now() + ChronoDuration::try_days(365).ok_or(AppError::FromTime)?;
            let mut transaction = context.octopus_database.transaction_begin().await?;

            let session = context
                .octopus_database
                .insert_session(&mut transaction, user.id, "", expired_at)
                .await?;

            context
                .octopus_database
                .transaction_commit(transaction)
                .await?;

            parameters.push_str(&format!("OCTOPUS_TOKEN={} ", session.id));
        }
    }

    file.write_fmt(format_args!("{parameters} nohup python3 {full_service_dir_path}/{ai_service_id}.py --host=0.0.0.0 --port={ai_service_port} &\n"))?;

    Ok(true)
}

pub fn delete_environment(ai_service: &AiService) -> Result<bool> {
    let pwd = get_pwd()?;
    let path = format!("{pwd}/{SERVICES_DIR}/{}", ai_service.id);
    let dir_exists = Path::new(&path).is_dir();
    if dir_exists {
        remove_dir_all(path)?;
    }

    Ok(true)
}

pub async fn install(ai_service: AiService, context: Arc<Context>) -> Result<AiService> {
    let mut transaction = context.octopus_database.transaction_begin().await?;

    let ai_service = context
        .octopus_database
        .update_ai_service_status(
            &mut transaction,
            ai_service.id,
            0,
            AiServiceStatus::InstallationStarted,
        )
        .await?;

    context
        .octopus_database
        .transaction_commit(transaction)
        .await?;

    let process = Process {
        id: ai_service.id.to_string(),
        client_port: None,
        failed_connection_attempts: 0,
        last_used_at: None,
        pid: None,
        server_port: Some(ai_service.port),
        state: ProcessState::Initial,
        r#type: ProcessType::AiService,
    };

    let process = context.process_manager.insert_process(&process)?;

    if let Some(mut process) = process {
        let environment_created = create_environment(&ai_service, context.clone()).await?;

        if environment_created {
            process.state = ProcessState::EnvironmentPrepared;

            let process = context.process_manager.insert_process(&process)?;

            if let Some(_process) = process {
                let mut transaction = context.octopus_database.transaction_begin().await?;

                let ai_service = context
                    .octopus_database
                    .update_ai_service_status(
                        &mut transaction,
                        ai_service.id,
                        100,
                        AiServiceStatus::InstallationFinished,
                    )
                    .await?;

                context
                    .octopus_database
                    .transaction_commit(transaction)
                    .await?;

                return Ok(ai_service);
            }
        }
    }

    Ok(ai_service)
}

pub async fn install_and_run(ai_service: AiService, context: Arc<Context>) -> Result<AiService> {
    if !context.get_config().await?.test_mode {
        let ai_service = stop(ai_service, context.clone()).await?;
        let ai_service = parser::ai_service_replace_device_map(ai_service, context.clone()).await?;
        let ai_service = install(ai_service, context.clone()).await?;
        let ai_service = run(ai_service, context).await?;

        return Ok(ai_service);
    }

    Ok(ai_service)
}

pub async fn manage_running(context: Arc<Context>, mut process: Process) -> Result<()> {
    match process.state {
        ProcessState::HealthCheckProblem => {
            if let Some(server_port) = process.server_port {
                let ai_service_id = Uuid::parse_str(&process.id)?;
                let ai_service = ai::service::service_health_check(
                    ai_service_id,
                    context.clone(),
                    server_port,
                    40,
                )
                .await?;

                if ai_service.health_check_status == AiServiceHealthCheckStatus::Ok {
                    let pid = try_get_pid(&format!("{}.py", ai_service.id))?;

                    if let Some(pid) = pid {
                        let process = Process {
                            id: process.id,
                            client_port: process.client_port,
                            failed_connection_attempts: 0,
                            last_used_at: process.last_used_at,
                            pid: Some(pid),
                            server_port: process.server_port,
                            state: ProcessState::Running,
                            r#type: process.r#type,
                        };

                        context.process_manager.insert_process(&process)?;
                    }
                } else {
                    let process = Process {
                        id: process.id,
                        client_port: process.client_port,
                        failed_connection_attempts: process.failed_connection_attempts + 1,
                        last_used_at: process.last_used_at,
                        pid: process.pid,
                        server_port: process.server_port,
                        state: ProcessState::HealthCheckProblem,
                        r#type: process.r#type,
                    };

                    context.process_manager.insert_process(&process)?;
                }

                if process.failed_connection_attempts > 30 {
                    try_restart(ai_service, context.clone()).await?;
                }
            }
        }
        ProcessState::Running => {
            if let Some(server_port) = process.server_port {
                let ai_service_id = Uuid::parse_str(&process.id)?;
                let ai_service = ai::service::service_health_check(
                    ai_service_id,
                    context.clone(),
                    server_port,
                    40,
                )
                .await?;

                if ai_service.health_check_status != AiServiceHealthCheckStatus::Ok {
                    process.state = ProcessState::HealthCheckProblem;
                    context.process_manager.insert_process(&process)?;
                }
            }
        }
        _ => {}
    }

    Ok(())
}

pub async fn run(ai_service: AiService, context: Arc<Context>) -> Result<AiService> {
    if ai_service.status == AiServiceStatus::Restarting
        || ai_service.status == AiServiceStatus::Setup
        || ai_service.status == AiServiceStatus::Stopped
    {
        let environment_created = create_environment(&ai_service, context.clone()).await?;

        if environment_created {
            let process = Process {
                id: ai_service.id.to_string(),
                client_port: None,
                failed_connection_attempts: 0,
                last_used_at: None,
                pid: None,
                server_port: Some(ai_service.port),
                state: ProcessState::EnvironmentPrepared,
                r#type: ProcessType::AiService,
            };

            context.process_manager.insert_process(&process)?;
        }
    }
    if ai_service.status == AiServiceStatus::InstallationFinished
        || ai_service.status == AiServiceStatus::Restarting
        || ai_service.status == AiServiceStatus::Running
        || ai_service.status == AiServiceStatus::Setup
        || ai_service.status == AiServiceStatus::Stopped
    {
        let process = context
            .process_manager
            .get_process(&ai_service.id.to_string())?;

        if let Some(mut process) = process {
            if process.state == ProcessState::EnvironmentPrepared {
                let pid = try_start(&ai_service.id.to_string()).await?;

                if let Some(_pid) = pid {
                    process.pid = pid;

                    let process = context.process_manager.insert_process(&process)?;

                    if let Some(mut process) = process {
                        let mut transaction = context.octopus_database.transaction_begin().await?;

                        let ai_service = context
                            .octopus_database
                            .update_ai_service_is_enabled(&mut transaction, ai_service.id, true)
                            .await?;

                        context
                            .octopus_database
                            .transaction_commit(transaction)
                            .await?;

                        let ai_service =
                            ai::service::service_prepare(ai_service.clone(), context.clone())
                                .await?;

                        if ai_service.health_check_status == AiServiceHealthCheckStatus::Ok
                            && ai_service.setup_status == AiServiceSetupStatus::Performed
                        {
                            process.state = ProcessState::Running;

                            let process = context.process_manager.insert_process(&process)?;

                            if let Some(_process) = process {
                                let mut transaction =
                                    context.octopus_database.transaction_begin().await?;

                                let ai_service = context
                                    .octopus_database
                                    .update_ai_service_status(
                                        &mut transaction,
                                        ai_service.id,
                                        100,
                                        AiServiceStatus::Running,
                                    )
                                    .await?;

                                context
                                    .octopus_database
                                    .update_ai_functions_is_enabled(
                                        &mut transaction,
                                        ai_service.id,
                                        true,
                                    )
                                    .await?;

                                context
                                    .octopus_database
                                    .transaction_commit(transaction)
                                    .await?;

                                return Ok(ai_service);
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(ai_service)
}

pub async fn start_or_manage_running(context: Arc<Context>) -> Result<()> {
    let ai_services = context.octopus_database.get_ai_services().await?;
    //let mut ai_services_parallel = vec![];
    let mut ai_services_sequential = vec![];

    let mut transaction = context.octopus_database.transaction_begin().await?;

    for ai_service in ai_services {
        if ai_service.is_enabled
            && (ai_service.status == AiServiceStatus::Restarting
                || ai_service.status == AiServiceStatus::Running
                || ai_service.status == AiServiceStatus::Setup)
        {
            let ai_service = context
                .octopus_database
                .update_ai_service_is_enabled_and_status(
                    &mut transaction,
                    ai_service.id,
                    true,
                    100,
                    AiServiceStatus::Restarting,
                )
                .await?;

            if let Some(ref _processed_function_body) = ai_service.processed_function_body {
                ai_services_sequential.push(ai_service);
                /*
                if processed_function_body.contains("apt-get") {
                    ai_services_sequential.push(ai_service);
                } else {
                    ai_services_parallel.push(ai_service);
                }
                */
            }
        }
    }

    context
        .octopus_database
        .transaction_commit(transaction)
        .await?;
    /*
    for ai_service in ai_services_parallel {
        let cloned_context = context.clone();
        let cloned_ai_service = ai_service.clone();
        tokio::spawn(async move {
            let result =
                start_or_manage_running_ai_service(cloned_ai_service, cloned_context).await;

            if let Err(e) = result {
                tracing::error!("Error: {:?}", e);
            }
        });
    }
    */
    for ai_service in ai_services_sequential {
        start_or_manage_running_ai_service(ai_service, context.clone()).await?;
    }

    Ok(())
}

pub async fn start_or_manage_running_ai_service(
    ai_service: AiService,
    context: Arc<Context>,
) -> Result<()> {
    let pid = try_get_pid(&format!("{}.py", ai_service.id))?;

    match pid {
        None => {
            let ai_service =
                parser::ai_service_replace_device_map(ai_service, context.clone()).await?;

            let environment_created = create_environment(&ai_service, context.clone()).await?;

            if environment_created {
                let process = Process {
                    id: ai_service.id.to_string(),
                    client_port: None,
                    failed_connection_attempts: 0,
                    last_used_at: None,
                    pid: None,
                    server_port: Some(ai_service.port),
                    state: ProcessState::EnvironmentPrepared,
                    r#type: ProcessType::AiService,
                };

                let process = context.process_manager.insert_process(&process)?;

                if let Some(_process) = process {
                    run(ai_service, context.clone()).await?;
                }
            }
        }
        Some(pid) => {
            let process = Process {
                id: ai_service.id.to_string(),
                client_port: None,
                failed_connection_attempts: 0,
                last_used_at: None,
                pid: Some(pid),
                server_port: Some(ai_service.port),
                state: ProcessState::Running,
                r#type: ProcessType::AiService,
            };

            context.process_manager.insert_process(&process)?;
        }
    }

    Ok(())
}

pub async fn stop(ai_service: AiService, context: Arc<Context>) -> Result<AiService> {
    let pid = try_get_pid(&format!("{}.py", ai_service.id))?;

    if let Some(pid) = pid {
        try_kill_process(pid).await?;
    }

    try_kill_cgroup(&ai_service.id.to_string()).await?;

    context
        .process_manager
        .remove_process(&ai_service.id.to_string())?;

    Ok(ai_service)
}

pub async fn stop_and_remove(ai_service: AiService, context: Arc<Context>) -> Result<AiService> {
    let ai_service = stop(ai_service, context).await?;

    delete_environment(&ai_service)?;

    Ok(ai_service)
}

pub async fn try_restart(ai_service: AiService, context: Arc<Context>) -> Result<AiService> {
    let ai_service = stop(ai_service, context.clone()).await?;

    let process = Process {
        id: ai_service.id.to_string(),
        client_port: None,
        failed_connection_attempts: 0,
        last_used_at: None,
        pid: None,
        server_port: Some(ai_service.port),
        state: ProcessState::EnvironmentPrepared,
        r#type: ProcessType::AiService,
    };

    let process = context.process_manager.insert_process(&process)?;

    if let Some(_process) = process {
        let ai_service = run(ai_service, context.clone()).await?;

        return Ok(ai_service);
    }

    Ok(ai_service)
}

pub async fn try_start(ai_service_id: &str) -> Result<Option<i32>> {
    let working_dir = get_pwd()?;

    let path = format!("/sys/fs/cgroup/{ai_service_id}");
    let dir_exists = Path::new(&path).is_dir();

    if dir_exists {
        Command::new("/usr/bin/cgdelete")
            .arg(format!("cpu:{ai_service_id}"))
            .output()?;
    }

    Command::new("/usr/bin/cgcreate")
        .arg("-g")
        .arg(format!("cpu:{ai_service_id}"))
        .output()?;

    let stderr_file = OpenOptions::new()
        .append(true)
        .create(true)
        .write(true)
        .open(format!(
            "{working_dir}/{SERVICES_DIR}/{ai_service_id}/{ai_service_id}.log"
        ))?;

    let stdout_file = OpenOptions::new()
        .append(true)
        .create(true)
        .write(true)
        .open(format!(
            "{working_dir}/{SERVICES_DIR}/{ai_service_id}/{ai_service_id}.log"
        ))?;

    Command::new("/usr/bin/cgexec")
        .arg("-g")
        .arg(format!("cpu:{ai_service_id}"))
        .arg("/bin/bash")
        .arg(format!(
            "{working_dir}/{SERVICES_DIR}/{ai_service_id}/{ai_service_id}.sh"
        ))
        .stderr(stderr_file)
        .stdout(stdout_file)
        .spawn()?;

    let mut failed_pid_get_attempts = 0;
    let pid = None;

    loop {
        let pid_tmp = try_get_pid(&format!("{ai_service_id}.py"))?;

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
