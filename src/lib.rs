use crate::error::AppError;
use clap::Parser;
use std::{error::Error, fs::File, net::SocketAddr, process::Command};
use tokio::task;
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
mod multipart;
mod parser;
mod process_manager;
mod scraper;
mod server_resources;
mod session;
mod wasp_app;

type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;

pub const PUBLIC_DIR: &str = "public";
pub const SERVICES_DIR: &str = "services";
pub const WASP_APPS_DIR: &str = "wasp_apps";
pub const WASP_GENERATOR_DIR: &str = "wasp_generator";

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// Database url
    #[arg(short, long)]
    pub database_url: Option<String>,

    /// Port
    #[arg(short, long)]
    pub port: Option<u16>,

    /// Test mode
    #[arg(short, long)]
    pub test_mode: Option<bool>,

    /// WASP database url
    #[arg(long)]
    pub wasp_database_url: Option<String>,

    /// WebSocket port
    #[arg(long)]
    pub ws_port: Option<u16>,
}

pub async fn run() -> Result<()> {
    let log_file = File::create("octopus_server.log")?;
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                "octopus_server=error,runtime=error,tokio=error,tower_http=error".into()
            }),
        )
        .with(tracing_subscriber::fmt::layer().with_writer(log_file))
        .init();

    let args = Args::parse();

    let app = app::get_app(args).await?;

    let cloned_context = app.context.clone();
    task::spawn(async move {
        let mut running = false;
        loop {
            if !running {
                running = true;
                let result = process_manager::start(cloned_context.clone());

                if let Err(e) = result.await {
                    error!("Error: {:?}", e);
                    running = false;
                }
            }
        }
    });

    let listener =
        tokio::net::TcpListener::bind(format!("0.0.0.0:{}", app.context.get_config().await?.port))
            .await?;
    let ws_listener = tokio::net::TcpListener::bind(format!(
        "0.0.0.0:{}",
        app.context.get_config().await?.ws_port
    ))
    .await?;

    info!("listening on {}", listener.local_addr()?);
    info!("listening on {}", ws_listener.local_addr()?);

    tokio::spawn(async move {
        let result = axum::serve(
            ws_listener,
            app.ws_router
                .into_make_service_with_connect_info::<SocketAddr>(),
        );

        if let Err(e) = result.await {
            error!("Error: {:?}", e);
        }
    });
    axum::serve(listener, app.router).await?;

    Ok(())
}

pub fn get_pwd() -> Result<String> {
    let pwd_output = Command::new("pwd").output()?;
    let pwd_output = String::from_utf8(pwd_output.stdout.clone())?;
    let pwd = if pwd_output.ends_with('\n') {
        pwd_output
            .strip_suffix('\n')
            .ok_or(AppError::Parsing)?
            .to_string()
    } else {
        pwd_output
    };

    Ok(pwd)
}
