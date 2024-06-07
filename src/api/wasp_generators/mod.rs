use crate::{
    context::Context,
    entity::{WaspAppInstanceType, WaspGeneratorStatus, ROLE_COMPANY_ADMIN_USER},
    error::AppError,
    get_pwd, process_manager,
    session::{require_authenticated, ExtractedSession},
    wasp_app::{self, generator},
    WASP_GENERATOR_DIR,
};
use axum::{
    body::Body,
    extract::{Path, Request, State, WebSocketUpgrade},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use rev_buf_reader::RevBufReader;
use serde::Deserialize;
use std::{fs::File, io::BufRead, path, sync::Arc};
use tracing::debug;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;
use validator::Validate;

#[derive(Deserialize, IntoParams)]
pub struct BackendProxyParams {
    id: Uuid,
    pass: Option<String>,
}

#[derive(Deserialize, IntoParams)]
pub struct FrontendProxyParams {
    id: Uuid,
    pass: Option<String>,
}

#[derive(Deserialize, IntoParams)]
pub struct LogsParams {
    id: Uuid,
    limit: Option<usize>,
}

#[derive(Debug, Deserialize, ToSchema, Validate)]
pub struct WaspGeneratorDeployPost {
    pub instance_type: WaspAppInstanceType,
}

#[derive(Debug, Deserialize, ToSchema, Validate)]
pub struct WaspGeneratorPost {
    pub api_access_secret: Option<String>,
    pub api_access_url: Option<String>,
    pub description: String,
    pub name: String,
    pub version: Option<i32>,
}

#[derive(Debug, Deserialize, ToSchema, Validate)]
pub struct WaspGeneratorPut {
    pub api_access_secret: Option<String>,
    pub api_access_url: Option<String>,
    pub description: String,
    pub name: String,
    pub version: Option<i32>,
}

#[axum_macros::debug_handler]
#[utoipa::path(
    post,
    path = "/api/v1/wasp-generators",
    request_body = WaspGeneratorPost,
    responses(
        (status = 201, description = "Wasp generator created.", body = WaspGenerator),
        (status = 400, description = "Bad request.", body = ResponseError),
        (status = 403, description = "Forbidden.", body = ResponseError),
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn create(
    State(context): State<Arc<Context>>,
    extracted_session: ExtractedSession,
    Json(input): Json<WaspGeneratorPost>,
) -> Result<impl IntoResponse, AppError> {
    let session = require_authenticated(extracted_session).await?;

    let session_user = context
        .octopus_database
        .try_get_user_by_id(session.user_id)
        .await?
        .ok_or(AppError::Forbidden)?;

    input.validate()?;

    let formatted_name = input.name.clone().replace(' ', "_").to_lowercase();

    let mut transaction = context.octopus_database.transaction_begin().await?;

    let wasp_generator = context
        .octopus_database
        .insert_wasp_generator(
            &mut transaction,
            session_user.id,
            input.api_access_secret,
            input.api_access_url,
            &input.description,
            &formatted_name,
            input.version.unwrap_or(1),
        )
        .await?;

    context
        .octopus_database
        .transaction_commit(transaction)
        .await?;

    Ok((StatusCode::CREATED, Json(wasp_generator)).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    delete,
    path = "/api/v1/wasp-generators/:id",
    responses(
        (status = 204, description = "Wasp generator deleted."),
        (status = 403, description = "Forbidden.", body = ResponseError),
        (status = 404, description = "Wasp generator not found.", body = ResponseError),
    ),
    params(
        ("id" = String, Path, description = "Wasp generator id")
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn delete(
    State(context): State<Arc<Context>>,
    extracted_session: ExtractedSession,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let session = require_authenticated(extracted_session).await?;

    let session_user = context
        .octopus_database
        .try_get_user_by_id(session.user_id)
        .await?
        .ok_or(AppError::Forbidden)?;

    let wasp_generator = context
        .octopus_database
        .try_get_wasp_generator_by_id(id)
        .await?
        .ok_or(AppError::NotFound)?;

    let user = context
        .octopus_database
        .try_get_user_by_id(wasp_generator.user_id)
        .await?
        .ok_or(AppError::NotFound)?;

    if session_user.id != wasp_generator.user_id
        && (!session_user
            .roles
            .contains(&ROLE_COMPANY_ADMIN_USER.to_string())
            || session_user.company_id != user.company_id)
    {
        return Err(AppError::Forbidden);
    }

    let mut transaction = context.octopus_database.transaction_begin().await?;

    context
        .octopus_database
        .try_delete_wasp_generator_by_id(&mut transaction, wasp_generator.id)
        .await?
        .ok_or(AppError::NotFound)?;

    context
        .octopus_database
        .transaction_commit(transaction)
        .await?;

    Ok((StatusCode::NO_CONTENT, ()).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    post,
    path = "/api/v1/wasp-generators/:id/deploy",
    request_body = WaspGeneratorDeployPost,
    responses(
        (status = 200, description = "Wasp generator deploy request.", body = WaspGenerator),
        (status = 400, description = "Bad request.", body = ResponseError),
        (status = 403, description = "Forbidden.", body = ResponseError),
        (status = 404, description = "Wasp generator not found.", body = ResponseError),
    ),
    params(
        ("id" = String, Path, description = "Wasp generator id")
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn deploy(
    State(context): State<Arc<Context>>,
    extracted_session: ExtractedSession,
    Path(id): Path<Uuid>,
    Json(input): Json<WaspGeneratorDeployPost>,
) -> Result<impl IntoResponse, AppError> {
    let session = require_authenticated(extracted_session).await?;

    let session_user = context
        .octopus_database
        .try_get_user_by_id(session.user_id)
        .await?
        .ok_or(AppError::Forbidden)?;

    input.validate()?;

    let wasp_generator = context
        .octopus_database
        .try_get_wasp_generator_by_id(id)
        .await?
        .ok_or(AppError::NotFound)?;

    if wasp_generator.status != WaspGeneratorStatus::Generated {
        return Err(AppError::Conflict);
    }

    let user = context
        .octopus_database
        .try_get_user_by_id(wasp_generator.user_id)
        .await?
        .ok_or(AppError::NotFound)?;

    if session_user.id != wasp_generator.user_id
        && (!session_user
            .roles
            .contains(&ROLE_COMPANY_ADMIN_USER.to_string())
            || session_user.company_id != user.company_id)
    {
        return Err(AppError::Forbidden);
    }

    let mut transaction = context.octopus_database.transaction_begin().await?;

    let wasp_app = match wasp_generator.wasp_app_id {
        None => {
            context
                .octopus_database
                .insert_wasp_app_from_wasp_generator(
                    &mut transaction,
                    &wasp_generator.code.ok_or(AppError::Conflict)?,
                    &wasp_generator.description,
                    &wasp_generator.name,
                    input.instance_type,
                    true,
                    &wasp_generator.name,
                    wasp_generator.id,
                )
                .await?
        }
        Some(wasp_app_id) => {
            context
                .octopus_database
                .update_wasp_app_from_wasp_generator(
                    &mut transaction,
                    wasp_app_id,
                    &wasp_generator.code.ok_or(AppError::Conflict)?,
                    &wasp_generator.description,
                    &wasp_generator.name,
                    input.instance_type,
                    true,
                    &wasp_generator.name,
                    wasp_generator.id,
                )
                .await?
        }
    };

    let wasp_generator = context
        .octopus_database
        .update_wasp_generator_wasp_app_id(&mut transaction, wasp_generator.id, wasp_app.id)
        .await?;

    context
        .octopus_database
        .transaction_commit(transaction)
        .await?;

    Ok((StatusCode::CREATED, Json(wasp_generator)).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    post,
    path = "/api/v1/wasp-generators/:id/generate",
    responses(
        (status = 200, description = "Wasp generator generate request.", body = WaspGenerator),
        (status = 400, description = "Bad request.", body = ResponseError),
        (status = 403, description = "Forbidden.", body = ResponseError),
        (status = 404, description = "Wasp generator not found.", body = ResponseError),
    ),
    params(
        ("id" = String, Path, description = "Wasp generator id")
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn generate(
    State(context): State<Arc<Context>>,
    extracted_session: ExtractedSession,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let session = require_authenticated(extracted_session).await?;

    let session_user = context
        .octopus_database
        .try_get_user_by_id(session.user_id)
        .await?
        .ok_or(AppError::Forbidden)?;

    let wasp_generator = context
        .octopus_database
        .try_get_wasp_generator_by_id(id)
        .await?
        .ok_or(AppError::NotFound)?;

    let user = context
        .octopus_database
        .try_get_user_by_id(wasp_generator.user_id)
        .await?
        .ok_or(AppError::NotFound)?;

    if session_user.id != wasp_generator.user_id
        && (!session_user
            .roles
            .contains(&ROLE_COMPANY_ADMIN_USER.to_string())
            || session_user.company_id != user.company_id)
    {
        return Err(AppError::Forbidden);
    }

    let mut transaction = context.octopus_database.transaction_begin().await?;

    let wasp_generator = context
        .octopus_database
        .update_wasp_generator_status(
            &mut transaction,
            wasp_generator.id,
            WaspGeneratorStatus::Generating,
        )
        .await?;

    context
        .octopus_database
        .transaction_commit(transaction)
        .await?;

    let cloned_context = context.clone();
    let cloned_wasp_generator = wasp_generator.clone();
    tokio::spawn(async move {
        let wasp_generator = generator::generate(cloned_context, cloned_wasp_generator).await;

        if let Err(e) = wasp_generator {
            debug!("Error: {:?}", e);
        }
    });

    Ok((StatusCode::CREATED, Json(wasp_generator)).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    get,
    path = "/api/v1/wasp-generators",
    responses(
        (status = 200, description = "List of Wasp generators.", body = [WaspGenerator]),
        (status = 401, description = "Unauthorized request.", body = ResponseError),
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn list(
    State(context): State<Arc<Context>>,
    extracted_session: ExtractedSession,
) -> Result<impl IntoResponse, AppError> {
    let session = require_authenticated(extracted_session).await?;

    let session_user = context
        .octopus_database
        .try_get_user_by_id(session.user_id)
        .await?
        .ok_or(AppError::Forbidden)?;

    let wasp_generators = context
        .octopus_database
        .get_wasp_generators_by_user_id(session_user.id)
        .await?;

    Ok((StatusCode::OK, Json(wasp_generators)).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    get,
    path = "/api/v1/wasp-generators/:id/logs",
    responses(
        (status = 200, description = "Wasp app logs.", body = String),
        (status = 401, description = "Unauthorized request.", body = ResponseError),
        (status = 404, description = "Wasp app not found.", body = ResponseError),
    ),
    params(
        ("id" = String, Path, description = "Wasp app id"),
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn logs(
    State(context): State<Arc<Context>>,
    extracted_session: ExtractedSession,
    Path(LogsParams { id, limit }): Path<LogsParams>,
) -> Result<impl IntoResponse, AppError> {
    require_authenticated(extracted_session).await?;

    let wasp_generator = context
        .octopus_database
        .try_get_wasp_generator_by_id(id)
        .await?
        .ok_or(AppError::NotFound)?;

    let app_id = wasp_generator.id;

    let limit = limit.unwrap_or(50);

    let pwd = get_pwd()?;

    let path = format!("{pwd}/{WASP_GENERATOR_DIR}/{app_id}/{app_id}.log");

    let file_exists = path::Path::new(&path).is_file();

    let logs = if file_exists {
        let file = File::open(path)?;
        let buf = RevBufReader::new(file);
        let mut reversed = vec![];
        let mut result = String::new();
        let iterator = buf
            .lines()
            .take(limit)
            .map(|l| l.expect("Could not parse line"));

        for item in iterator {
            reversed.push(item);
        }

        for item in reversed.iter().rev() {
            result.push_str(&format!("{item}\n"));
        }

        result
    } else {
        String::new()
    };

    Ok((StatusCode::OK, logs).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    get,
    path = "/api/v1/wasp-generators/:id/proxy-backend/:pass",
    responses(
        (status = 200, description = "Wasp generator backend proxy.", body = String),
        (status = 401, description = "Unauthorized request.", body = ResponseError),
        (status = 404, description = "Wasp generator not found.", body = ResponseError),
    ),
    params(
        ("id" = String, Path, description = "Wasp generator id"),
        ("pass" = String, Path, description = "Parameters that are passed to proxified service"),
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn proxy_backend(
    State(context): State<Arc<Context>>,
    Path(BackendProxyParams { id, pass }): Path<BackendProxyParams>,
    request: Request<Body>,
) -> Result<impl IntoResponse, AppError> {
    let wasp_generator = context
        .octopus_database
        .try_get_wasp_generator_by_id(id)
        .await?
        .ok_or(AppError::NotFound)?;

    let app_id = wasp_generator.id.to_string();

    let pid = process_manager::try_get_pid(&format!("{app_id}.sh"))?;
    let process = context.process_manager.get_process(&app_id)?;
    let uri = request.uri().to_string();

    let uri_append = if uri.contains('?') {
        uri.split('?').last()
    } else {
        None
    };

    if pid.is_none() || process.is_none() {
        process_manager::wasp_generator::install_and_run(context.clone(), wasp_generator.clone())
            .await?;

        let process = context.process_manager.get_process(&app_id)?;

        if let Some(process) = process {
            if let Some(server_port) = process.server_port {
                let response = wasp_app::request(
                    context.clone(),
                    None,
                    pass,
                    server_port,
                    "proxy-backend",
                    request,
                    server_port,
                    uri_append,
                    false,
                    None,
                    Some(id),
                )
                .await?;

                process_manager::try_update_last_used_at(&context, &app_id)?;

                return Ok(response);
            }
        }
    } else if let Some(process) = process {
        if let Some(server_port) = process.server_port {
            let response = wasp_app::request(
                context.clone(),
                None,
                pass,
                server_port,
                "proxy-backend",
                request,
                server_port,
                uri_append,
                true,
                None,
                Some(id),
            )
            .await?;

            process_manager::try_update_last_used_at(&context, &app_id)?;

            return Ok(response);
        }
    }

    Ok((StatusCode::OK, Json("{}")).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    get,
    path = "/ws/api/v1/wasp-generators/:id/proxy-backend",
    responses(
        (status = 200, description = "Wasp generator backend WebSocket proxy.", body = String),
        (status = 401, description = "Unauthorized request.", body = ResponseError),
        (status = 404, description = "Wasp generator not found.", body = ResponseError),
    ),
    params(
        ("id" = String, Path, description = "Wasp generator id"),
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn proxy_backend_web_socket(
    State(context): State<Arc<Context>>,
    Path(id): Path<Uuid>,
    web_socket_upgrade: WebSocketUpgrade,
) -> Result<impl IntoResponse, AppError> {
    let wasp_generator = context
        .octopus_database
        .try_get_wasp_generator_by_id(id)
        .await?
        .ok_or(AppError::NotFound)?;

    let app_id = wasp_generator.id.to_string();

    let pid = process_manager::try_get_pid(&format!("{app_id}.sh"))?;
    let process = context.process_manager.get_process(&app_id)?;

    if pid.is_none() || process.is_none() {
        process_manager::wasp_generator::install_and_run(context.clone(), wasp_generator.clone())
            .await?;

        let process = context.process_manager.get_process(&app_id)?;

        if let Some(process) = process {
            if let Some(client_port) = process.client_port {
                let result = web_socket_upgrade
                    .on_upgrade(move |web_socket| wasp_app::request_ws(client_port, web_socket));

                return Ok((StatusCode::SWITCHING_PROTOCOLS, result).into_response());
            }
        }
    } else if let Some(process) = process {
        if let Some(client_port) = process.client_port {
            let result = web_socket_upgrade
                .on_upgrade(move |web_socket| wasp_app::request_ws(client_port, web_socket));

            return Ok((StatusCode::SWITCHING_PROTOCOLS, result).into_response());
        }
    }

    Ok((StatusCode::OK, Json("{}")).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    get,
    path = "/api/v1/wasp-generators/:id/proxy-frontend/:pass",
    responses(
        (status = 200, description = "Wasp generator frontend proxy.", body = String),
        (status = 401, description = "Unauthorized request.", body = ResponseError),
        (status = 404, description = "Wasp generator not found.", body = ResponseError),
    ),
    params(
        ("id" = String, Path, description = "Wasp generator id"),
        ("pass" = String, Path, description = "Parameters that are passed to proxified service"),
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn proxy_frontend(
    State(context): State<Arc<Context>>,
    Path(FrontendProxyParams { id, pass }): Path<FrontendProxyParams>,
    request: Request<Body>,
) -> Result<impl IntoResponse, AppError> {
    let wasp_generator = context
        .octopus_database
        .try_get_wasp_generator_by_id(id)
        .await?
        .ok_or(AppError::NotFound)?;

    let app_id = wasp_generator.id.to_string();

    let pid = process_manager::try_get_pid(&format!("{app_id}.sh"))?;
    let process = context.process_manager.get_process(&app_id)?;
    let uri = request.uri().to_string();

    let uri_append = if uri.contains('?') {
        uri.split('?').last()
    } else {
        None
    };

    if pid.is_none() || process.is_none() {
        process_manager::wasp_generator::install_and_run(context.clone(), wasp_generator.clone())
            .await?;

        let process = context.process_manager.get_process(&app_id)?;

        if let Some(process) = process {
            if let (Some(client_port), Some(server_port)) =
                (process.client_port, process.server_port)
            {
                let response = wasp_app::request(
                    context.clone(),
                    None,
                    pass,
                    client_port,
                    "proxy-frontend",
                    request,
                    server_port,
                    uri_append,
                    false,
                    None,
                    Some(id),
                )
                .await?;

                process_manager::try_update_last_used_at(&context, &app_id)?;

                return Ok(response);
            }
        }
    } else if let Some(process) = process {
        if let (Some(client_port), Some(server_port)) = (process.client_port, process.server_port) {
            let response = wasp_app::request(
                context.clone(),
                None,
                pass,
                client_port,
                "proxy-frontend",
                request,
                server_port,
                uri_append,
                true,
                None,
                Some(id),
            )
            .await?;

            process_manager::try_update_last_used_at(&context, &app_id)?;

            return Ok(response);
        }
    }

    Ok((StatusCode::OK, Json("{}")).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    get,
    path = "/api/v1/wasp-generators/:id",
    responses(
        (status = 200, description = "Wasp generator read.", body = WaspGenerator),
        (status = 401, description = "Unauthorized request.", body = ResponseError),
        (status = 404, description = "Wasp generator not found.", body = ResponseError),
    ),
    params(
        ("id" = String, Path, description = "Wasp generator id")
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn read(
    State(context): State<Arc<Context>>,
    extracted_session: ExtractedSession,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let session = require_authenticated(extracted_session).await?;

    let session_user = context
        .octopus_database
        .try_get_user_by_id(session.user_id)
        .await?
        .ok_or(AppError::Forbidden)?;

    let wasp_generator = context
        .octopus_database
        .try_get_wasp_generator_by_id(id)
        .await?
        .ok_or(AppError::NotFound)?;

    let user = context
        .octopus_database
        .try_get_user_by_id(wasp_generator.user_id)
        .await?
        .ok_or(AppError::NotFound)?;

    if session_user.id != wasp_generator.user_id
        && (!session_user
            .roles
            .contains(&ROLE_COMPANY_ADMIN_USER.to_string())
            || session_user.company_id != user.company_id)
    {
        return Err(AppError::Forbidden);
    }

    Ok((StatusCode::OK, Json(wasp_generator)).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    put,
    path = "/api/v1/wasp-generators/:id",
    request_body = WaspGeneratorPut,
    responses(
        (status = 200, description = "Wasp generator updated.", body = WaspGenerator),
        (status = 400, description = "Bad request.", body = ResponseError),
        (status = 403, description = "Forbidden.", body = ResponseError),
        (status = 404, description = "Wasp generator not found.", body = ResponseError),
    ),
    params(
        ("id" = String, Path, description = "Wasp generator id")
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn update(
    State(context): State<Arc<Context>>,
    extracted_session: ExtractedSession,
    Path(id): Path<Uuid>,
    Json(input): Json<WaspGeneratorPut>,
) -> Result<impl IntoResponse, AppError> {
    let session = require_authenticated(extracted_session).await?;

    let session_user = context
        .octopus_database
        .try_get_user_by_id(session.user_id)
        .await?
        .ok_or(AppError::Forbidden)?;

    input.validate()?;

    let wasp_generator = context
        .octopus_database
        .try_get_wasp_generator_by_id(id)
        .await?
        .ok_or(AppError::NotFound)?;

    let user = context
        .octopus_database
        .try_get_user_by_id(wasp_generator.user_id)
        .await?
        .ok_or(AppError::NotFound)?;

    if session_user.id != wasp_generator.user_id
        && (!session_user
            .roles
            .contains(&ROLE_COMPANY_ADMIN_USER.to_string())
            || session_user.company_id != user.company_id)
    {
        return Err(AppError::Forbidden);
    }

    let formatted_name = input.name.clone().replace(' ', "_").to_lowercase();

    let mut transaction = context.octopus_database.transaction_begin().await?;

    let wasp_generator = context
        .octopus_database
        .update_wasp_generator(
            &mut transaction,
            wasp_generator.id,
            input.api_access_secret,
            input.api_access_url,
            &input.description,
            &formatted_name,
            WaspGeneratorStatus::Changed,
            input.version.unwrap_or(1),
        )
        .await?;

    context
        .octopus_database
        .transaction_commit(transaction)
        .await?;

    Ok((StatusCode::OK, Json(wasp_generator)).into_response())
}
