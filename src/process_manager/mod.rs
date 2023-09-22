use crate::{
    ai,
    context::Context,
    entity::{AiService, AiServiceHealthCheckStatus, AiServiceSetupStatus, AiServiceStatus},
    error::AppError,
    Result, SERVICES_DIR,
};
use std::{
    collections::HashMap,
    fs::{create_dir, File},
    io::Write,
    path::Path,
    process::{Command, Stdio},
    sync::{Arc, RwLock},
};
use tokio::time::{sleep, Duration};
use tracing::{error, info};
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct Process {
    pub id: Uuid,
    pub failed_connection_attempts: i32,
    pub pid: Option<i32>,
    pub port: i32,
    pub state: ProcessState,
}

#[derive(Debug)]
pub struct ProcessManager {
    pub processes: RwLock<HashMap<Uuid, Process>>,
}

impl ProcessManager {
    pub fn new() -> Self {
        Self {
            processes: RwLock::new(HashMap::new()),
        }
    }

    pub fn get(&self, id: Uuid) -> Result<Option<Process>> {
        let processes = self
            .processes
            .read()
            .map_err(|_| AppError::ProcessManagerLock)?;

        let process = processes.get(&id);

        match process {
            None => Ok(None),
            Some(process) => Ok(Some(process.clone())),
        }
    }

    pub fn insert(&self, process: Process) -> Result<Option<Process>> {
        let mut processes = self
            .processes
            .write()
            .map_err(|_| AppError::ProcessManagerLock)?;

        let id = process.id;
        processes.insert(id, process);
        let process = processes.get(&id);

        match process {
            None => Ok(None),
            Some(process) => Ok(Some(process.clone())),
        }
    }

    pub fn list(&self) -> Result<Vec<Process>> {
        let mut processes_list = vec![];
        let processes = self
            .processes
            .read()
            .map_err(|_| AppError::ProcessManagerLock)?;
        for process in (*processes).values() {
            processes_list.push(process.clone());
        }

        Ok(processes_list)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProcessState {
    Initial,
    EnvironmentPrepared,
    HealthCheckProblem,
    Running,
}

pub async fn create_environment_for_ai_service(ai_service: &AiService) -> Result<bool> {
    let path = format!("{SERVICES_DIR}/{}", ai_service.id);
    let dir_exists = Path::new(&path).is_dir();
    if !dir_exists {
        create_dir(path)?;
    }

    let path = format!("{SERVICES_DIR}/{}/{}.py", ai_service.id, ai_service.id);
    let mut file = File::create(path)?;
    if let Some(processed_function_body) = &ai_service.processed_function_body {
        file.write_all(processed_function_body.as_bytes())?;
    }

    Ok(true)
}

pub async fn install_ai_service(ai_service: AiService, context: Arc<Context>) -> Result<AiService> {
    let ai_service = context
        .octopus_database
        .update_ai_service_status(ai_service.id, 0, AiServiceStatus::InstallationStarted)
        .await?;

    let process = Process {
        id: ai_service.id,
        failed_connection_attempts: 0,
        pid: None,
        port: ai_service.port,
        state: ProcessState::Initial,
    };

    let process = context.process_manager.insert(process)?;

    if let Some(mut process) = process {
        let environment_created = create_environment_for_ai_service(&ai_service).await?;

        if environment_created {
            process.state = ProcessState::EnvironmentPrepared;

            let process = context.process_manager.insert(process)?;

            if let Some(_process) = process {
                let ai_service = context
                    .octopus_database
                    .update_ai_service_status(
                        ai_service.id,
                        100,
                        AiServiceStatus::InstallationFinished,
                    )
                    .await?;

                return Ok(ai_service);
            }
        }
    }

    Ok(ai_service)
}

pub async fn install_and_run_ai_service(
    ai_service: AiService,
    context: Arc<Context>,
) -> Result<AiService> {
    let ai_service = install_ai_service(ai_service, context.clone()).await?;
    let ai_service = run_ai_service(ai_service, context).await?;

    Ok(ai_service)
}

pub async fn run_ai_service(ai_service: AiService, context: Arc<Context>) -> Result<AiService> {
    if ai_service.status == AiServiceStatus::InstallationFinished {
        let process = context.process_manager.get(ai_service.id)?;

        if let Some(mut process) = process {
            if process.state == ProcessState::EnvironmentPrepared {
                let pid = try_start_ai_service(ai_service.id, ai_service.port).await?;

                if let Some(_pid) = pid {
                    process.pid = pid;

                    let process = context.process_manager.insert(process)?;

                    if let Some(mut process) = process {
                        let ai_service = context
                            .octopus_database
                            .update_ai_service_is_enabled(ai_service.id, true)
                            .await?;

                        let ai_service =
                            ai::service_prepare(ai_service.clone(), context.clone()).await?;

                        if ai_service.health_check_status == AiServiceHealthCheckStatus::Ok
                            && ai_service.setup_status == AiServiceSetupStatus::Performed
                        {
                            process.state = ProcessState::Running;

                            let process = context.process_manager.insert(process)?;

                            if let Some(_process) = process {
                                let ai_service = context
                                    .octopus_database
                                    .update_ai_service_status(
                                        ai_service.id,
                                        100,
                                        AiServiceStatus::Running,
                                    )
                                    .await?;

                                context
                                    .octopus_database
                                    .update_ai_functions_is_enabled(ai_service.id, true)
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

pub async fn start(context: Arc<Context>) -> Result<()> {
    let ai_services = context.octopus_database.get_ai_services().await?;

    for ai_service in ai_services {
        if ai_service.is_enabled && ai_service.setup_status == AiServiceSetupStatus::Performed {
            let pid = try_get_pid(&ai_service.id.to_string()).await?;

            match pid {
                None => {
                    let environment_created =
                        create_environment_for_ai_service(&ai_service).await?;

                    if environment_created {
                        let pid = try_start_ai_service(ai_service.id, ai_service.port).await?;

                        if let Some(pid) = pid {
                            let process = Process {
                                id: ai_service.id,
                                failed_connection_attempts: 0,
                                pid: Some(pid),
                                port: ai_service.port,
                                state: ProcessState::Running,
                            };

                            context.process_manager.insert(process)?;
                        }
                    }
                }
                Some(pid) => {
                    let process = Process {
                        id: ai_service.id,
                        failed_connection_attempts: 0,
                        pid: Some(pid),
                        port: ai_service.port,
                        state: ProcessState::Running,
                    };

                    context.process_manager.insert(process)?;
                }
            }
        }
    }

    loop {
        let res = context.process_manager.list();

        match res {
            Err(e) => error!("Error: {:?}", e),
            Ok(processes) => {
                info!("{:?}", processes);
                for mut process in processes {
                    match process.state {
                        ProcessState::HealthCheckProblem => {
                            let ai_service =
                                ai::service_health_check(process.id, context.clone(), process.port)
                                    .await?;

                            if ai_service.health_check_status == AiServiceHealthCheckStatus::Ok {
                                let pid = try_get_pid(&ai_service.id.to_string()).await?;

                                if let Some(pid) = pid {
                                    let process = Process {
                                        id: process.id,
                                        failed_connection_attempts: 0,
                                        pid: Some(pid),
                                        port: process.port,
                                        state: ProcessState::Running,
                                    };

                                    context.process_manager.insert(process)?;
                                }
                            } else {
                                let process = Process {
                                    id: process.id,
                                    failed_connection_attempts: process.failed_connection_attempts
                                        + 1,
                                    pid: process.pid,
                                    port: process.port,
                                    state: ProcessState::HealthCheckProblem,
                                };

                                context.process_manager.insert(process)?;
                            }

                            if process.failed_connection_attempts > 30 {
                                let pid = try_restart_ai_service(process.id, process.port).await?;
                                if let Some(pid) = pid {
                                    let process = Process {
                                        id: process.id,
                                        failed_connection_attempts: 0,
                                        pid: Some(pid),
                                        port: process.port,
                                        state: ProcessState::Running,
                                    };

                                    context.process_manager.insert(process)?;
                                }
                            }
                        }
                        ProcessState::Running => {
                            let ai_service =
                                ai::service_health_check(process.id, context.clone(), process.port)
                                    .await?;

                            if ai_service.health_check_status != AiServiceHealthCheckStatus::Ok {
                                process.state = ProcessState::HealthCheckProblem;
                                context.process_manager.insert(process)?;
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        sleep(Duration::from_secs(60)).await;
    }
}

pub async fn try_get_pid(process: &str) -> Result<Option<i32>> {
    let mut pid = None;
    let ps_output = Command::new("ps").arg("ax").output()?;

    let ps_output = String::from_utf8(ps_output.stdout.clone())?;

    for line in ps_output.lines() {
        if line.contains(process) {
            for token in line.split_whitespace() {
                let parsed_token = token.parse::<i32>();

                if let Ok(parsed_token) = parsed_token {
                    pid = Some(parsed_token);
                }
            }
        }
    }

    Ok(pid)
}

pub async fn try_restart_ai_service(ai_service_id: Uuid, port: i32) -> Result<Option<i32>> {
    let pid = try_get_pid(&ai_service_id.to_string()).await?;

    if let Some(pid) = pid {
        try_stop_ai_service(pid).await?;
    }

    let pid = try_start_ai_service(ai_service_id, port).await?;

    Ok(pid)
}

pub async fn try_start_ai_service(ai_service_id: Uuid, port: i32) -> Result<Option<i32>> {
    Command::new("/usr/bin/python3")
        .arg(format!("{SERVICES_DIR}/{ai_service_id}/{ai_service_id}.py"))
        .arg("--host=0.0.0.0")
        .arg(format!("--port={port}"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;

    sleep(Duration::from_secs(2)).await;
    let pid = try_get_pid(&ai_service_id.to_string()).await?;

    Ok(pid)
}

pub async fn try_stop_ai_service(pid: i32) -> Result<()> {
    Command::new("kill").arg(format!("{pid}")).output()?;

    Ok(())
}
