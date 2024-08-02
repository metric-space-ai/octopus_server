use crate::{config::Config, database::OctopusDatabase, process_manager::ProcessManager, Result};
use tokio::sync::RwLock;
use tokio_cron_scheduler::JobScheduler;

pub struct Context {
    pub config: RwLock<Config>,
    pub job_scheduler: JobScheduler,
    pub octopus_database: OctopusDatabase,
    pub process_manager: ProcessManager,
}

impl Context {
    pub fn new(
        config: Config,
        job_scheduler: JobScheduler,
        octopus_database: OctopusDatabase,
        process_manager: ProcessManager,
    ) -> Self {
        Self {
            config: RwLock::new(config),
            job_scheduler,
            octopus_database,
            process_manager,
        }
    }

    pub async fn get_config(&self) -> Result<Config> {
        let config = self.config.read().await;

        Ok(config.clone())
    }

    pub async fn set_config(&self, new_config: Config) -> Result<Config> {
        let mut config = self.config.write().await;
        config.parameters = new_config.parameters;

        Ok(config.clone())
    }
}
