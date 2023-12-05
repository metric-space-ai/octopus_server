use crate::{
    api, config, context::Context, database::OctopusDatabase, process_manager::ProcessManager,
    Args, Result,
};
use axum::Router;
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;

pub struct App {
    pub context: Arc<Context>,
    pub router: Router,
}

pub async fn get_app(args: Args) -> Result<App> {
    let context = get_context(args).await?;

    let app = App {
        context: context.clone(),
        router: api::router(context),
    };

    Ok(app)
}

pub async fn get_context(args: Args) -> Result<Arc<Context>> {
    let mut config = config::load(args)?;
    let pool = PgPoolOptions::new().connect(&config.database_url).await?;
    let octopus_database = OctopusDatabase::new(pool);
    let parameters = octopus_database.get_parameters().await?;
    config.set_parameters(parameters);
    let process_manager = ProcessManager::new();
    let context = Arc::new(Context::new(config, octopus_database, process_manager));

    Ok(context)
}
