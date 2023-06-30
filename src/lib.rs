use clap::Parser;
use sqlx::postgres::{PgPool, PgPoolOptions};
use std::{error::Error, net::SocketAddr, sync::Arc, time::Duration};
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod api;
mod config;
mod error;

type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// OpenAI API key
    #[arg(short, long)]
    pub openai_api_key: Option<String>,

    /// Port
    #[arg(short, long)]
    pub port: Option<u16>,
}

pub async fn run() -> Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                "octopus_server=error,runtime=error,tokio=error,tower_http=error".into()
            }),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let args = Args::parse();
    let config = Arc::new(config::load(args)?);
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .acquire_timeout(Duration::from_secs(3))
        .connect(&config.database_url)
        .await?;

    let router = api::router(config.clone()).await;

    let addr = SocketAddr::from(([0, 0, 0, 0], config.port));
    info!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(router.into_make_service())
        .await?;

    Ok(())
}
