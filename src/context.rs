use crate::{config::Config, database::OctopusDatabase};

pub struct Context {
    pub config: Config,
    pub octopus_database: OctopusDatabase,
}

impl Context {
    pub fn new(config: Config, octopus_database: OctopusDatabase) -> Self {
        Self {
            config,
            octopus_database,
        }
    }
}
