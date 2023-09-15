use crate::{config::Config, database::OctopusDatabase, process_manager::ProcessManager};

pub struct Context {
    pub config: Config,
    pub octopus_database: OctopusDatabase,
    pub process_manager: ProcessManager,
}

impl Context {
    pub fn new(
        config: Config,
        octopus_database: OctopusDatabase,
        process_manager: ProcessManager,
    ) -> Self {
        Self {
            config,
            octopus_database,
            process_manager,
        }
    }
}
