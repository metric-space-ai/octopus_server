use crate::{Result, context::Context, error::AppError};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs::OpenOptions,
    io::Write,
    path::Path,
    process::Command,
    sync::{Arc, RwLock},
};
use tokio::time::{Duration, sleep};
use tracing::error;
use utoipa::ToSchema;

pub mod ai_service;
pub mod wasp_app;
pub mod wasp_generator;

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
pub struct Process {
    pub id: String,
    pub client_port: Option<i32>,
    pub failed_connection_attempts: i32,
    pub last_used_at: Option<DateTime<Utc>>,
    pub pid: Option<i32>,
    pub server_port: Option<i32>,
    #[schema(no_recursion)]
    pub state: ProcessState,
    #[schema(no_recursion)]
    pub r#type: ProcessType,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub enum ProcessState {
    Initial,
    EnvironmentPrepared,
    HealthCheckProblem,
    Running,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub enum ProcessType {
    AiService,
    WaspApp,
    WaspGenerator,
}

#[derive(Debug)]
pub struct ProcessManager {
    pub processes: RwLock<HashMap<String, Process>>,
    pub reserved_ports: RwLock<Vec<i32>>,
}

impl ProcessManager {
    pub fn new() -> Self {
        Self {
            processes: RwLock::new(HashMap::new()),
            reserved_ports: RwLock::new(vec![]),
        }
    }

    pub fn get_process(&self, id: &str) -> Result<Option<Process>> {
        let processes = self
            .processes
            .read()
            .map_err(|_| AppError::ProcessManagerLock)?;

        let process = processes.get(id);

        match process {
            None => Ok(None),
            Some(process) => Ok(Some(process.clone())),
        }
    }

    pub fn insert_process(&self, process: &Process) -> Result<Option<Process>> {
        let mut processes = self
            .processes
            .write()
            .map_err(|_| AppError::ProcessManagerLock)?;

        let id = process.id.clone();
        processes.insert(id.clone(), process.clone());
        let process = processes.get(&id);

        match process {
            None => Ok(None),
            Some(process) => {
                if let Some(client_port) = process.client_port {
                    self.insert_reserved_port(client_port)?;
                }

                if let Some(server_port) = process.server_port {
                    self.insert_reserved_port(server_port)?;
                }

                Ok(Some(process.clone()))
            }
        }
    }

    pub fn insert_reserved_port(&self, port: i32) -> Result<Option<i32>> {
        let mut reserved_ports = self
            .reserved_ports
            .write()
            .map_err(|_| AppError::ProcessManagerLock)?;

        reserved_ports.push(port);
        reserved_ports.dedup();
        let reserved_port = reserved_ports.clone().into_iter().find(|x| x == &port);

        match reserved_port {
            None => Ok(None),
            Some(reserved_port) => Ok(Some(reserved_port)),
        }
    }

    pub fn list_processes(&self) -> Result<Vec<Process>> {
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

    pub fn list_reserved_ports(&self) -> Result<Vec<i32>> {
        let reserved_ports = self
            .reserved_ports
            .read()
            .map_err(|_| AppError::ProcessManagerLock)?;

        Ok(reserved_ports.clone())
    }

    pub fn remove_process(&self, id: &str) -> Result<bool> {
        let mut processes = self
            .processes
            .write()
            .map_err(|_| AppError::ProcessManagerLock)?;

        let process = processes.remove(id);

        match process {
            None => Ok(false),
            Some(process) => {
                if let Some(client_port) = process.client_port {
                    self.remove_reserved_port(client_port)?;
                }

                if let Some(server_port) = process.server_port {
                    self.remove_reserved_port(server_port)?;
                }

                Ok(true)
            }
        }
    }

    pub fn remove_reserved_port(&self, port: i32) -> Result<bool> {
        let mut reserved_ports = self
            .reserved_ports
            .write()
            .map_err(|_| AppError::ProcessManagerLock)?;

        let reserved_port_index = reserved_ports.clone().into_iter().position(|x| x == port);
        if let Some(reserved_port_index) = reserved_port_index {
            reserved_ports.remove(reserved_port_index);

            return Ok(true);
        }

        Ok(false)
    }
}

pub async fn start(context: Arc<Context>) -> Result<()> {
    ai_service::start_or_manage_running(context.clone()).await?;

    loop {
        let res = context.process_manager.list_processes();

        match res {
            Err(e) => error!("Error: {:?}", e),
            Ok(processes) => {
                for process in processes {
                    match process.r#type {
                        ProcessType::AiService => {
                            ai_service::manage_running(context.clone(), process).await?;
                        }
                        ProcessType::WaspApp => {
                            wasp_app::manage_running(context.clone(), process).await?;
                        }
                        ProcessType::WaspGenerator => {
                            wasp_generator::manage_running(context.clone(), process).await?;
                        }
                    }
                }
            }
        }

        let zombie_pids = try_get_zombie_pids()?;

        for zombie_pid in zombie_pids {
            try_kill_process(zombie_pid).await?;
        }

        sleep(Duration::from_secs(60)).await;
    }
}

pub fn try_get_pid(process: &str) -> Result<Option<i32>> {
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

pub fn try_get_zombie_pids() -> Result<Vec<i32>> {
    let mut pids = vec![];
    let ps_output = Command::new("ps").arg("ax").output()?;

    let ps_output = String::from_utf8(ps_output.stdout.clone())?;

    for line in ps_output.lines() {
        if (line.contains("bash") || line.contains("python3"))
            && line.contains("defunct")
            && line.contains('Z')
        {
            for token in line.split_whitespace() {
                let parsed_token = token.parse::<i32>();

                if let Ok(parsed_token) = parsed_token {
                    pids.push(parsed_token);
                }
            }
        }
    }

    Ok(pids)
}

pub async fn try_kill_cgroup(id: &str) -> Result<()> {
    let path = format!("/sys/fs/cgroup/{id}/cgroup.freeze");
    let file_exists = Path::new(&path).is_file();

    if file_exists {
        let mut file = OpenOptions::new().write(true).open(path)?;

        file.write_all("1".as_bytes())?;

        sleep(Duration::from_secs(2)).await;
    }

    let path = format!("/sys/fs/cgroup/{id}/cgroup.kill");
    let file_exists = Path::new(&path).is_file();

    if file_exists {
        let mut file = OpenOptions::new().write(true).open(path)?;

        file.write_all("1".as_bytes())?;

        sleep(Duration::from_secs(2)).await;
    }

    Command::new("/usr/bin/cgdelete")
        .arg("-g")
        .arg(format!("cpu:{id}"))
        .output()?;

    Ok(())
}

pub async fn try_kill_process(pid: i32) -> Result<()> {
    Command::new("kill")
        .arg("-9")
        .arg(format!("{pid}"))
        .output()?;

    sleep(Duration::from_secs(2)).await;

    Ok(())
}

pub fn try_update_last_used_at(context: &Arc<Context>, process_id: &str) -> Result<()> {
    let process = context.process_manager.get_process(process_id)?;

    if let Some(mut process) = process {
        process.last_used_at = Some(Utc::now());

        context.process_manager.insert_process(&process)?;
    }

    Ok(())
}
