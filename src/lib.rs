use clap::Parser;
use std::{error::Error, net::SocketAddr};
use tokio::{
    task,
    time::{sleep, Duration},
};
use tracing::{error, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod ai;
mod api;
mod app;
mod config;
mod context;
mod database;
mod email_service;
mod entity;
mod error;
mod parser;
mod process_manager;
mod server_resources;
mod session;

type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;

pub const DOMAIN: &str = "https://api.octopus-ai.app/";
pub const PUBLIC_DIR: &str = "public";
pub const SERVICES_DIR: &str = "services";

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// Database url
    #[arg(short, long)]
    pub database_url: Option<String>,

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

    let cloned_context = app.context.clone();
    task::spawn(async move {
        loop {
            let res = cloned_context.process_manager.list();

            match res {
                Err(e) => error!("Error: {:?}", e),
                Ok(processes) => info!("{:?}", processes),
            }

            sleep(Duration::from_millis(1000)).await;
        }
    });

    let addr = SocketAddr::from(([0, 0, 0, 0], app.context.config.port));
    info!("listening on {}", addr);

    axum::Server::bind(&addr)
        .serve(app.router.into_make_service())
        .await?;

    Ok(())
}
