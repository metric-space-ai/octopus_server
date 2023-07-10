use clap::Parser;
use std::{error::Error, net::SocketAddr};
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod ai_request;
mod api;
mod app;
mod config;
mod context;
mod database;
mod entity;
mod error;
mod session;

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

    let app = app::get_app(args).await?;

    let addr = SocketAddr::from(([0, 0, 0, 0], app.context.config.port));
    info!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.router.into_make_service())
        .await?;

    Ok(())
}
