use crate::{
    api, config, context::Context, database::OctopusDatabase, process_manager::ProcessManager,
    Args, Result,
};
use axum::Router;
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;
use tokio::time::Duration;

pub struct App {
    pub context: Arc<Context>,
    pub router: Router,
    pub ws_router: Router,
}

#[allow(clippy::module_name_repetitions)]
pub async fn get_app(args: Args) -> Result<App> {
    let context = get_context(args).await?;

    let app = App {
        context: context.clone(),
        router: api::router(context.clone())?,
        ws_router: api::ws_router(context)?,
    };

    Ok(app)
}

pub async fn get_context(args: Args) -> Result<Arc<Context>> {
    let mut config = config::load(args)?;
    let pool = PgPoolOptions::new()
        .acquire_timeout(Duration::from_secs(180))
        .connect(&config.database_url)
        .await?;
    let octopus_database = OctopusDatabase::new(pool);
    let parameters = octopus_database.get_parameters().await?;
    config.set_parameters(parameters);
    let process_manager = ProcessManager::new();
    let context = Arc::new(Context::new(config, octopus_database, process_manager));

    Ok(context)
}

#[cfg(test)]
pub mod tests {
    use crate::{app, app::App, Args};

    pub async fn get_test_app() -> App {
        let args = Args {
            database_url: Some(String::from(
                "postgres://admin:admin@db/octopus_server_test",
            )),
            port: None,
            test_mode: Some(true),
            wasp_database_url: Some(String::from("postgres://admin:admin@db")),
            ws_port: None,
        };

        app::get_app(args).await.unwrap()
    }
}
