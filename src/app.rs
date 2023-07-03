use crate::{api, config, context::Context, database::OctopusDatabase, Args, Result};
use axum::Router;
use sqlx::postgres::PgPoolOptions;
use std::{sync::Arc, time::Duration};

pub struct App {
    pub context: Arc<Context>,
    pub router: Router,
}

pub async fn get_app(args: Args) -> Result<App> {
    let context = get_context(args).await?;

    let app = App {
        context: context.clone(),
        router: api::router(context).await,
    };

    Ok(app)
}

pub async fn get_context(args: Args) -> Result<Arc<Context>> {
    let config = config::load(args)?;
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .acquire_timeout(Duration::from_secs(3))
        .connect(&config.database_url)
        .await?;
    let octopus_database = OctopusDatabase::new(pool);
    let context = Arc::new(Context::new(config, octopus_database));

    Ok(context)
}
