use crate::{
    context::Context,
    entity::{AiService, AiServiceStatus},
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
//use tokio::process::Command;
use tokio::time::{sleep, Duration};
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct Process {
    pub id: Uuid,
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
        for (_proces_id, process) in processes.iter() {
            processes_list.push(process.clone());
        }

        Ok(processes_list)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProcessState {
    Initial,
    EnvironmentPrepared,
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
        .update_ai_service_status(ai_service.id, AiServiceStatus::InstallationStarted)
        .await?;

    let process = Process {
        id: ai_service.id,
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
                    .update_ai_service_status(ai_service.id, AiServiceStatus::InstallationFinished)
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
                Command::new("/usr/bin/python3")
                    .arg(format!(
                        "{}/{}/{}.py",
                        SERVICES_DIR, ai_service.id, ai_service.id
                    ))
                    .arg("--host=0.0.0.0")
                    .arg(format!("--port={}", ai_service.port))
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .spawn()?;

                sleep(Duration::from_secs(2)).await;
                let pid = try_get_pid_for(&ai_service.id.to_string()).await?;

                if let Some(_pid) = pid {
                    process.pid = pid;

                    let process = context.process_manager.insert(process)?;

                    if let Some(_process) = process {
                        let ai_service = context
                            .octopus_database
                            .update_ai_service_status(ai_service.id, AiServiceStatus::Running)
                            .await?;

                        return Ok(ai_service);
                    }
                }
            }
        }
    }

    Ok(ai_service)
}

pub async fn try_get_pid_for(process: &str) -> Result<Option<i32>> {
    let mut pid = None;
    let ps_output = Command::new("ps").arg("ax").output()?;

    let ps_output = String::from_utf8(ps_output.stdout.to_vec())?;

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
