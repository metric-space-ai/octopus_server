use crate::{
    ai::code_tools::open_ai_wasp_app_advanced_meta_extraction,
    context::Context,
    entity::{WaspAppInstanceType, ROLE_COMPANY_ADMIN_USER},
    error::AppError,
    get_pwd, process_manager,
    session::{require_authenticated, ExtractedSession},
    wasp_app, WASP_APPS_DIR,
};
use axum::{
    body::Body,
    extract::{Multipart, Path, Request, State, WebSocketUpgrade},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use rev_buf_reader::RevBufReader;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_512};
use std::{
    fs::{read_to_string, File},
    io::{BufRead, Write},
    path,
    str::FromStr,
    sync::Arc,
};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;
use validator::Validate;

#[derive(Deserialize, Serialize, ToSchema)]
pub struct AutoLoginUser {
    id: Uuid,
    email: String,
    password: String,
}

#[derive(Deserialize, IntoParams)]
pub struct BackendProxyParams {
    id: Uuid,
    chat_message_id: Uuid,
    pass: Option<String>,
}

#[derive(Deserialize, IntoParams)]
pub struct BackendWebSocketProxyParams {
    id: Uuid,
    chat_message_id: Uuid,
}

#[derive(Deserialize, IntoParams)]
pub struct FrontendProxyParams {
    id: Uuid,
    chat_message_id: Uuid,
    pass: Option<String>,
}

#[derive(Deserialize, IntoParams)]
pub struct LogsParams {
    id: Uuid,
    chat_message_id: Uuid,
    limit: Option<usize>,
}

#[derive(Debug, Deserialize, ToSchema, Validate)]
pub struct WaspAppAllowedUsersPut {
    pub allowed_user_ids: Vec<Uuid>,
}

#[axum_macros::debug_handler]
#[utoipa::path(
    put,
    path = "/api/v1/wasp-apps/:id/allowed-users",
    request_body = WaspAppAllowedUsersPut,
    responses(
        (status = 200, description = "Wasp app updated.", body = WaspApp),
        (status = 401, description = "Unauthorized request.", body = ResponseError),
        (status = 403, description = "Forbidden.", body = ResponseError),
        (status = 404, description = "Wasp app not found.", body = ResponseError),
    ),
    params(
        ("id" = String, Path, description = "Wasp app id")
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn allowed_users(
    State(context): State<Arc<Context>>,
    extracted_session: ExtractedSession,
    Path(id): Path<Uuid>,
    Json(input): Json<WaspAppAllowedUsersPut>,
) -> Result<impl IntoResponse, AppError> {
    let session = require_authenticated(extracted_session).await?;

    let session_user = context
        .octopus_database
        .try_get_user_by_id(session.user_id)
        .await?
        .ok_or(AppError::Forbidden)?;

    if !session_user
        .roles
        .contains(&ROLE_COMPANY_ADMIN_USER.to_string())
    {
        return Err(AppError::Forbidden);
    }

    input.validate()?;

    let wasp_app = context
        .octopus_database
        .try_get_wasp_app_by_id(id)
        .await?
        .ok_or(AppError::NotFound)?;

    let allowed_user_ids = if input.allowed_user_ids.is_empty() {
        None
    } else {
        Some(input.allowed_user_ids)
    };

    let mut transaction = context.octopus_database.transaction_begin().await?;

    let wasp_app = context
        .octopus_database
        .update_wasp_app_allowed_user_ids(&mut transaction, wasp_app.id, allowed_user_ids)
        .await?;

    context
        .octopus_database
        .transaction_commit(transaction)
        .await?;

    Ok((StatusCode::OK, Json(wasp_app)).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    get,
    path = "/api/v1/wasp-apps/auto-login",
    responses(
        (status = 200, description = "Wasp app auto login.", body = AutoLoginUser),
        (status = 401, description = "Unauthorized request.", body = ResponseError),
        (status = 403, description = "Forbidden.", body = ResponseError),
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn auto_login(
    State(context): State<Arc<Context>>,
    extracted_session: ExtractedSession,
) -> Result<impl IntoResponse, AppError> {
    let session = require_authenticated(extracted_session).await?;

    let session_user = context
        .octopus_database
        .try_get_user_by_id(session.user_id)
        .await?
        .ok_or(AppError::Forbidden)?;

    let password = format!("{}-{}", session_user.id, session_user.created_at);

    let mut hasher = Sha3_512::new();
    hasher.update(password);
    let hash = hex::encode(hasher.finalize_reset());

    let auto_login_user = AutoLoginUser {
        id: session_user.id,
        email: session_user.email,
        password: hash,
    };

    Ok((StatusCode::OK, Json(auto_login_user)).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    post,
    path = "/api/v1/wasp-apps",
    responses(
        (status = 201, description = "Wasp app created.", body = WaspApp),
        (status = 400, description = "Bad request.", body = ResponseError),
        (status = 401, description = "Unauthorized request.", body = ResponseError),
        (status = 403, description = "Forbidden.", body = ResponseError),
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn create(
    State(context): State<Arc<Context>>,
    extracted_session: ExtractedSession,
    mut multipart: Multipart,
) -> Result<impl IntoResponse, AppError> {
    let session = require_authenticated(extracted_session).await?;

    let session_user = context
        .octopus_database
        .try_get_user_by_id(session.user_id)
        .await?
        .ok_or(AppError::Forbidden)?;

    if !session_user
        .roles
        .contains(&ROLE_COMPANY_ADMIN_USER.to_string())
    {
        return Err(AppError::Forbidden);
    }

    let mut code = None;
    let mut description = None;
    let mut instance_type = WaspAppInstanceType::Shared;
    let mut is_enabled = true;
    let mut name = None;

    while let Some(field) = multipart.next_field().await? {
        let field_name = (field.name().ok_or(AppError::Parsing)?).to_string();

        if field_name == "description" {
            description = Some((field.text().await?).to_string());
        } else if field_name == "name" {
            name = Some((field.text().await?).to_string());
        } else if field_name == "instance_type" {
            let value = (field.text().await?).to_string();
            instance_type = WaspAppInstanceType::from_str(&value)?;
        } else if field_name == "is_enabled" {
            is_enabled = (field.text().await?).parse::<bool>().unwrap_or(true);
        } else {
            let content_type = (field.content_type().ok_or(AppError::File)?).to_string();

            if content_type == "application/zip"
                || content_type == "application/x-zip"
                || content_type == "application/x-zip-compressed"
            {
                code = Some(field.bytes().await?.clone().to_vec());
            }
        }
    }

    if let (Some(code), Some(description), Some(name)) = (code, description, name) {
        let formatted_name = name.clone().replace(' ', "_").to_lowercase();

        let mut transaction = context.octopus_database.transaction_begin().await?;

        let wasp_app = context
            .octopus_database
            .insert_wasp_app(
                &mut transaction,
                &code,
                &description,
                &formatted_name,
                instance_type,
                is_enabled,
                &name,
            )
            .await?;

        context
            .octopus_database
            .transaction_commit(transaction)
            .await?;

        return Ok((StatusCode::CREATED, Json(wasp_app)).into_response());
    }

    Err(AppError::BadRequest)
}

#[axum_macros::debug_handler]
#[utoipa::path(
    delete,
    path = "/api/v1/wasp-apps/:id",
    responses(
        (status = 204, description = "Wasp app deleted."),
        (status = 401, description = "Unauthorized request.", body = ResponseError),
        (status = 403, description = "Forbidden.", body = ResponseError),
        (status = 404, description = "Wasp app not found.", body = ResponseError),
    ),
    params(
        ("id" = String, Path, description = "Wasp app id")
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

    if !session_user
        .roles
        .contains(&ROLE_COMPANY_ADMIN_USER.to_string())
    {
        return Err(AppError::Forbidden);
    }

    let mut transaction = context.octopus_database.transaction_begin().await?;

    context
        .octopus_database
        .try_delete_wasp_app_by_id(&mut transaction, id)
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
    path = "/api/v1/wasp-apps/extract-meta",
    responses(
        (status = 201, description = "Extract meta info from Wasp app.", body = WaspAppMeta),
        (status = 400, description = "Bad request.", body = ResponseError),
        (status = 401, description = "Unauthorized request.", body = ResponseError),
        (status = 403, description = "Forbidden.", body = ResponseError),
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn extract_meta(
    State(context): State<Arc<Context>>,
    extracted_session: ExtractedSession,
    mut multipart: Multipart,
) -> Result<impl IntoResponse, AppError> {
    let session = require_authenticated(extracted_session).await?;

    let session_user = context
        .octopus_database
        .try_get_user_by_id(session.user_id)
        .await?
        .ok_or(AppError::Forbidden)?;

    if !session_user
        .roles
        .contains(&ROLE_COMPANY_ADMIN_USER.to_string())
    {
        return Err(AppError::Forbidden);
    }

    let mut code = None;

    while let Some(field) = multipart.next_field().await? {
        let content_type = (field.content_type().ok_or(AppError::File)?).to_string();

        if content_type == "application/zip"
            || content_type == "application/x-zip"
            || content_type == "application/x-zip-compressed"
        {
            code = Some(field.bytes().await?.clone().to_vec());
        }
    }

    if let Some(code) = code {
        let mut tmpfile = tempfile::tempfile()?;
        tmpfile.write_all(&code)?;

        let mut archive = zip::ZipArchive::new(tmpfile)?;

        let mut code = None;

        for i in 0..archive.len() {
            let mut file = archive.by_index(i)?;
            if (*file.name()).contains("main.wasp") {
                let mut wasptmpfile = tempfile::NamedTempFile::new()?;
                std::io::copy(&mut file, &mut wasptmpfile)?;

                let content = read_to_string(wasptmpfile.into_temp_path())?;
                code = Some(content);
            }
        }

        if let Some(code) = code {
            let wasp_app_meta = open_ai_wasp_app_advanced_meta_extraction(&code, context).await?;

            return Ok((StatusCode::CREATED, Json(wasp_app_meta)).into_response());
        }
    }

    Err(AppError::BadRequest)
}

#[axum_macros::debug_handler]
#[utoipa::path(
    get,
    path = "/api/v1/wasp-apps",
    responses(
        (status = 200, description = "List of Wasp apps.", body = [WaspApp]),
        (status = 401, description = "Unauthorized request.", body = ResponseError),
        (status = 403, description = "Forbidden.", body = ResponseError),
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

    context
        .octopus_database
        .try_get_user_by_id(session.user_id)
        .await?
        .ok_or(AppError::Forbidden)?;

    let wasp_apps = context.octopus_database.get_wasp_apps().await?;

    Ok((StatusCode::OK, Json(wasp_apps)).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    get,
    path = "/api/v1/wasp-apps/:id/:chat_message_id/logs",
    responses(
        (status = 200, description = "Wasp app logs.", body = String),
        (status = 401, description = "Unauthorized request.", body = ResponseError),
        (status = 403, description = "Forbidden.", body = ResponseError),
        (status = 404, description = "Wasp app not found.", body = ResponseError),
    ),
    params(
        ("id" = String, Path, description = "Wasp app id"),
        ("chat_message_id" = String, Path, description = "Chat message id"),
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn logs(
    State(context): State<Arc<Context>>,
    extracted_session: ExtractedSession,
    Path(LogsParams {
        id,
        chat_message_id,
        limit,
    }): Path<LogsParams>,
) -> Result<impl IntoResponse, AppError> {
    let session = require_authenticated(extracted_session).await?;

    let session_user = context
        .octopus_database
        .try_get_user_by_id(session.user_id)
        .await?
        .ok_or(AppError::Forbidden)?;

    if !session_user
        .roles
        .contains(&ROLE_COMPANY_ADMIN_USER.to_string())
    {
        return Err(AppError::Forbidden);
    }

    let wasp_app = context
        .octopus_database
        .try_get_wasp_app_by_id(id)
        .await?
        .ok_or(AppError::NotFound)?;

    if !wasp_app.is_enabled {
        return Err(AppError::NotFound);
    }

    let chat_message = context
        .octopus_database
        .try_get_chat_message_by_id(chat_message_id)
        .await?
        .ok_or(AppError::NotFound)?;

    if chat_message.wasp_app_id != Some(wasp_app.id) {
        return Err(AppError::NotFound);
    }

    let app_id = match wasp_app.instance_type {
        WaspAppInstanceType::Private => chat_message.id.to_string(),
        WaspAppInstanceType::Shared => wasp_app.id.to_string(),
        WaspAppInstanceType::User => format!("{}-{}", chat_message.user_id, wasp_app.id),
    };

    let limit = limit.unwrap_or(50);

    let pwd = get_pwd()?;

    let path = format!("{pwd}/{WASP_APPS_DIR}/{app_id}/{app_id}.log");

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
    path = "/api/v1/wasp-apps/:id/:chat_message_id/proxy-backend/:pass",
    responses(
        (status = 200, description = "Wasp app backend proxy.", body = String),
        (status = 404, description = "Wasp app not found.", body = ResponseError),
    ),
    params(
        ("id" = String, Path, description = "Wasp app id"),
        ("chat_message_id" = String, Path, description = "Chat message id"),
        ("pass" = String, Path, description = "Parameters that are passed to proxified service"),
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn proxy_backend(
    State(context): State<Arc<Context>>,
    Path(BackendProxyParams {
        id,
        chat_message_id,
        pass,
    }): Path<BackendProxyParams>,
    request: Request<Body>,
) -> Result<impl IntoResponse, AppError> {
    let wasp_app = context
        .octopus_database
        .try_get_wasp_app_by_id(id)
        .await?
        .ok_or(AppError::NotFound)?;

    if !wasp_app.is_enabled {
        return Err(AppError::NotFound);
    }

    let chat_message = context
        .octopus_database
        .try_get_chat_message_by_id(chat_message_id)
        .await?
        .ok_or(AppError::NotFound)?;

    if chat_message.wasp_app_id != Some(wasp_app.id) {
        return Err(AppError::NotFound);
    }

    let app_id = match wasp_app.instance_type {
        WaspAppInstanceType::Private => chat_message.id.to_string(),
        WaspAppInstanceType::Shared => wasp_app.id.to_string(),
        WaspAppInstanceType::User => format!("{}-{}", chat_message.user_id, wasp_app.id),
    };

    let pid = process_manager::try_get_pid(&format!("{app_id}.sh"))?;
    let process = context.process_manager.get_process(&app_id)?;
    let uri = request.uri().to_string();

    let uri_append = if uri.contains('?') {
        uri.split('?').last()
    } else {
        None
    };

    if pid.is_none() || process.is_none() {
        process_manager::wasp_app::install_and_run(
            context.clone(),
            chat_message.clone(),
            wasp_app.clone(),
        )
        .await?;

        let process = context.process_manager.get_process(&app_id)?;

        if let Some(process) = process {
            if let Some(server_port) = process.server_port {
                let response = wasp_app::request(
                    context.clone(),
                    Some(chat_message_id),
                    pass,
                    server_port,
                    "proxy-backend",
                    request,
                    server_port,
                    uri_append,
                    false,
                    Some(id),
                    None,
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
                Some(chat_message_id),
                pass,
                server_port,
                "proxy-backend",
                request,
                server_port,
                uri_append,
                true,
                Some(id),
                None,
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
    path = "/ws/api/v1/wasp-apps/:id/:chat_message_id/proxy-backend",
    responses(
        (status = 200, description = "Wasp app backend WebSocket proxy.", body = String),
        (status = 404, description = "Wasp app not found.", body = ResponseError),
    ),
    params(
        ("id" = String, Path, description = "Wasp app id"),
        ("chat_message_id" = String, Path, description = "Chat message id"),
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn proxy_backend_web_socket(
    State(context): State<Arc<Context>>,
    Path(BackendWebSocketProxyParams {
        id,
        chat_message_id,
    }): Path<BackendWebSocketProxyParams>,
    web_socket_upgrade: WebSocketUpgrade,
) -> Result<impl IntoResponse, AppError> {
    let wasp_app = context
        .octopus_database
        .try_get_wasp_app_by_id(id)
        .await?
        .ok_or(AppError::NotFound)?;

    if !wasp_app.is_enabled {
        return Err(AppError::NotFound);
    }

    let chat_message = context
        .octopus_database
        .try_get_chat_message_by_id(chat_message_id)
        .await?
        .ok_or(AppError::NotFound)?;

    if chat_message.wasp_app_id != Some(wasp_app.id) {
        return Err(AppError::NotFound);
    }

    let app_id = match wasp_app.instance_type {
        WaspAppInstanceType::Private => chat_message.id.to_string(),
        WaspAppInstanceType::Shared => wasp_app.id.to_string(),
        WaspAppInstanceType::User => format!("{}-{}", chat_message.user_id, wasp_app.id),
    };

    let pid = process_manager::try_get_pid(&format!("{app_id}.sh"))?;
    let process = context.process_manager.get_process(&app_id)?;

    if pid.is_none() || process.is_none() {
        process_manager::wasp_app::install_and_run(
            context.clone(),
            chat_message.clone(),
            wasp_app.clone(),
        )
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
    path = "/api/v1/wasp-apps/:id/:chat_message_id/proxy-frontend/:pass",
    responses(
        (status = 200, description = "Wasp app frontend proxy.", body = String),
        (status = 404, description = "Wasp app not found.", body = ResponseError),
    ),
    params(
        ("id" = String, Path, description = "Wasp app id"),
        ("chat_message_id" = String, Path, description = "Chat message id"),
        ("pass" = String, Path, description = "Parameters that are passed to proxified service"),
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn proxy_frontend(
    State(context): State<Arc<Context>>,
    Path(FrontendProxyParams {
        id,
        chat_message_id,
        pass,
    }): Path<FrontendProxyParams>,
    request: Request<Body>,
) -> Result<impl IntoResponse, AppError> {
    let wasp_app = context
        .octopus_database
        .try_get_wasp_app_by_id(id)
        .await?
        .ok_or(AppError::NotFound)?;

    if !wasp_app.is_enabled {
        return Err(AppError::NotFound);
    }

    let chat_message = context
        .octopus_database
        .try_get_chat_message_by_id(chat_message_id)
        .await?
        .ok_or(AppError::NotFound)?;

    if chat_message.wasp_app_id != Some(wasp_app.id) {
        return Err(AppError::NotFound);
    }

    let app_id = match wasp_app.instance_type {
        WaspAppInstanceType::Private => chat_message.id.to_string(),
        WaspAppInstanceType::Shared => wasp_app.id.to_string(),
        WaspAppInstanceType::User => format!("{}-{}", chat_message.user_id, wasp_app.id),
    };

    let pid = process_manager::try_get_pid(&format!("{app_id}.sh"))?;
    let process = context.process_manager.get_process(&app_id)?;
    let uri = request.uri().to_string();

    let uri_append = if uri.contains('?') {
        uri.split('?').last()
    } else {
        None
    };

    if pid.is_none() || process.is_none() {
        process_manager::wasp_app::install_and_run(
            context.clone(),
            chat_message.clone(),
            wasp_app.clone(),
        )
        .await?;

        let process = context.process_manager.get_process(&app_id)?;

        if let Some(process) = process {
            if let (Some(client_port), Some(server_port)) =
                (process.client_port, process.server_port)
            {
                let response = wasp_app::request(
                    context.clone(),
                    Some(chat_message_id),
                    pass,
                    client_port,
                    "proxy-frontend",
                    request,
                    server_port,
                    uri_append,
                    false,
                    Some(id),
                    None,
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
                Some(chat_message_id),
                pass,
                client_port,
                "proxy-frontend",
                request,
                server_port,
                uri_append,
                true,
                Some(id),
                None,
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
    path = "/api/v1/wasp-apps/:id",
    responses(
        (status = 200, description = "Wasp app read.", body = WaspApp),
        (status = 401, description = "Unauthorized request.", body = ResponseError),
        (status = 403, description = "Forbidden.", body = ResponseError),
        (status = 404, description = "Wasp app not found.", body = ResponseError),
    ),
    params(
        ("id" = String, Path, description = "Wasp app id")
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

    context
        .octopus_database
        .try_get_user_by_id(session.user_id)
        .await?
        .ok_or(AppError::Forbidden)?;

    let wasp_app = context
        .octopus_database
        .try_get_wasp_app_by_id(id)
        .await?
        .ok_or(AppError::NotFound)?;

    if !wasp_app.is_enabled {
        return Err(AppError::NotFound);
    }

    Ok((StatusCode::OK, Json(wasp_app)).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    put,
    path = "/api/v1/wasp-apps/:id",
    responses(
        (status = 200, description = "Wasp app updated.", body = WaspApp),
        (status = 400, description = "Bad request.", body = ResponseError),
        (status = 401, description = "Unauthorized request.", body = ResponseError),
        (status = 403, description = "Forbidden.", body = ResponseError),
        (status = 404, description = "Wasp app not found.", body = ResponseError),
    ),
    params(
        ("id" = String, Path, description = "Wasp app id")
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn update(
    State(context): State<Arc<Context>>,
    extracted_session: ExtractedSession,
    Path(id): Path<Uuid>,
    mut multipart: Multipart,
) -> Result<impl IntoResponse, AppError> {
    let session = require_authenticated(extracted_session).await?;

    let session_user = context
        .octopus_database
        .try_get_user_by_id(session.user_id)
        .await?
        .ok_or(AppError::Forbidden)?;

    if !session_user
        .roles
        .contains(&ROLE_COMPANY_ADMIN_USER.to_string())
    {
        return Err(AppError::Forbidden);
    }

    context
        .octopus_database
        .try_get_wasp_app_id_by_id(id)
        .await?
        .ok_or(AppError::NotFound)?;

    let mut code = None;
    let mut description = None;
    let mut instance_type = WaspAppInstanceType::Shared;
    let mut is_enabled = true;
    let mut name = None;

    while let Some(field) = multipart.next_field().await? {
        let field_name = (field.name().ok_or(AppError::Parsing)?).to_string();

        if field_name == "description" {
            description = Some((field.text().await?).to_string());
        } else if field_name == "name" {
            name = Some((field.text().await?).to_string());
        } else if field_name == "instance_type" {
            let value = (field.text().await?).to_string();
            instance_type = WaspAppInstanceType::from_str(&value)?;
        } else if field_name == "is_enabled" {
            is_enabled = (field.text().await?).parse::<bool>().unwrap_or(true);
        } else {
            let content_type = (field.content_type().ok_or(AppError::File)?).to_string();

            if content_type == "application/zip"
                || content_type == "application/x-zip"
                || content_type == "application/x-zip-compressed"
            {
                code = Some(field.bytes().await?.clone().to_vec());
            }
        }
    }

    if let (Some(code), Some(description), Some(name)) =
        (code.clone(), description.clone(), name.clone())
    {
        let formatted_name = name.clone().replace(' ', "_").to_lowercase();

        let mut transaction = context.octopus_database.transaction_begin().await?;

        let wasp_app = context
            .octopus_database
            .update_wasp_app(
                &mut transaction,
                id,
                &code,
                &description,
                &formatted_name,
                instance_type,
                is_enabled,
                &name,
            )
            .await?;

        context
            .octopus_database
            .transaction_commit(transaction)
            .await?;

        Ok((StatusCode::OK, Json(wasp_app)).into_response())
    } else if let (None, Some(description), Some(name)) = (code, description, name) {
        let formatted_name = name.clone().replace(' ', "_").to_lowercase();

        let mut transaction = context.octopus_database.transaction_begin().await?;

        let wasp_app = context
            .octopus_database
            .update_wasp_app_info(
                &mut transaction,
                id,
                &description,
                &formatted_name,
                instance_type,
                is_enabled,
                &name,
            )
            .await?;

        context
            .octopus_database
            .transaction_commit(transaction)
            .await?;

        Ok((StatusCode::OK, Json(wasp_app)).into_response())
    } else {
        Err(AppError::BadRequest)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        api,
        api::wasp_apps::AutoLoginUser,
        app,
        context::Context,
        entity::{ChatMessageStatus, WaspAppInstanceType},
        multipart,
    };
    use axum::{
        body::Body,
        http::{self, Request, StatusCode},
        Router,
    };
    use chrono::{DateTime, Utc};
    use http_body_util::BodyExt;
    use serde::{Deserialize, Serialize};
    use sqlx::{Postgres, Transaction};
    use std::{collections::HashMap, sync::Arc};
    use tower::ServiceExt;
    use uuid::Uuid;

    #[derive(Clone, Debug, Deserialize, Serialize)]
    pub struct WaspApp {
        pub id: Uuid,
        pub allowed_user_ids: Option<Vec<Uuid>>,
        pub description: String,
        pub formatted_name: String,
        pub instance_type: WaspAppInstanceType,
        pub is_enabled: bool,
        pub name: String,
        pub created_at: DateTime<Utc>,
        pub deleted_at: Option<DateTime<Utc>>,
        pub updated_at: DateTime<Utc>,
    }

    pub async fn wasp_apps_cleanup(
        context: Arc<Context>,
        transaction: &mut Transaction<'_, Postgres>,
        wasp_app_id: Uuid,
    ) {
        let _ = context
            .octopus_database
            .try_delete_wasp_app_by_id(transaction, wasp_app_id)
            .await;
    }

    pub async fn wasp_apps_create(router: Router, session_id: Uuid) -> WaspApp {
        let body =
            multipart::tests::file_data("application/zip", "test.zip", "data/test/test.zip", false)
                .unwrap();

        let mut fields = HashMap::new();
        fields.insert("description", "test wasp application");
        fields.insert("name", "test");
        fields.insert("is_enabled", "true");
        fields.insert("instance_type", "Private");

        let body = multipart::tests::text_field_data(&body, fields, true);

        let value = format!(
            "{}; boundary={}",
            mime::MULTIPART_FORM_DATA,
            multipart::tests::BOUNDARY
        );

        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/api/v1/wasp-apps")
            .header(http::header::CONTENT_TYPE, value)
            .header("X-Auth-Token".to_string(), session_id.to_string())
            .body(body)
            .unwrap();

        let response = router.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = BodyExt::collect(response.into_body())
            .await
            .unwrap()
            .to_bytes()
            .to_vec();
        let body: WaspApp = serde_json::from_slice(&body).unwrap();

        assert!(body.is_enabled);

        body
    }

    #[tokio::test]
    async fn allowed_users_200() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let wasp_app = wasp_apps_create(router.clone(), session_id).await;
        let wasp_app_id = wasp_app.id;

        let allowed_user_ids = vec![user_id];

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::PUT)
                    .uri(format!("/api/v1/wasp-apps/{wasp_app_id}/allowed-users"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "allowed_user_ids": &allowed_user_ids,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = BodyExt::collect(response.into_body())
            .await
            .unwrap()
            .to_bytes()
            .to_vec();
        let body: WaspApp = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.allowed_user_ids, Some(allowed_user_ids));

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        wasp_apps_cleanup(app.context.clone(), &mut transaction, wasp_app_id).await;

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id],
            &[user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn allowed_users_401() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let wasp_app = wasp_apps_create(router.clone(), session_id).await;
        let wasp_app_id = wasp_app.id;

        let allowed_user_ids = vec![user_id];

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::PUT)
                    .uri(format!("/api/v1/wasp-apps/{wasp_app_id}/allowed-users"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "allowed_user_ids": &allowed_user_ids,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        wasp_apps_cleanup(app.context.clone(), &mut transaction, wasp_app_id).await;

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id],
            &[user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn allowed_users_403() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let wasp_app = wasp_apps_create(router.clone(), session_id).await;
        let wasp_app_id = wasp_app.id;

        let (email, is_enabled, job_title, name, password, roles) =
            api::users::tests::get_user_create_params();
        let user = api::users::tests::user_create(
            router.clone(),
            session_id,
            &email,
            is_enabled,
            &job_title,
            &name,
            &password,
            &roles,
        )
        .await;
        let second_user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, second_user_id)
                .await;
        let session_id = session_response.id;

        let allowed_user_ids = vec![user_id];

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::PUT)
                    .uri(format!("/api/v1/wasp-apps/{wasp_app_id}/allowed-users"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "allowed_user_ids": &allowed_user_ids,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        wasp_apps_cleanup(app.context.clone(), &mut transaction, wasp_app_id).await;

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id],
            &[user_id, second_user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn allowed_users_403_deleted_user() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let wasp_app = wasp_apps_create(router.clone(), session_id).await;
        let wasp_app_id = wasp_app.id;

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(app.context.clone(), &mut transaction, &[], &[user_id])
            .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;

        let allowed_user_ids = vec![user_id];

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::PUT)
                    .uri(format!("/api/v1/wasp-apps/{wasp_app_id}/allowed-users"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "allowed_user_ids": &allowed_user_ids,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        wasp_apps_cleanup(app.context.clone(), &mut transaction, wasp_app_id).await;

        api::setup::tests::setup_cleanup(app.context.clone(), &mut transaction, &[company_id], &[])
            .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn allowed_users_404() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let wasp_app_id = "33847746-0030-4964-a496-f75d04499160";

        let allowed_user_ids = vec![user_id];

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::PUT)
                    .uri(format!("/api/v1/wasp-apps/{wasp_app_id}/allowed-users"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "allowed_user_ids": &allowed_user_ids,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id],
            &[user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn auto_login_200() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("/api/v1/wasp-apps/auto-login"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = BodyExt::collect(response.into_body())
            .await
            .unwrap()
            .to_bytes()
            .to_vec();
        let _body: AutoLoginUser = serde_json::from_slice(&body).unwrap();

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id],
            &[user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn auto_login_401() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let wasp_app = wasp_apps_create(router.clone(), session_id).await;
        let wasp_app_id = wasp_app.id;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("/api/v1/wasp-apps/auto-login"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        wasp_apps_cleanup(app.context.clone(), &mut transaction, wasp_app_id).await;

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id],
            &[user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn auto_login_403_deleted_user() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let wasp_app = wasp_apps_create(router.clone(), session_id).await;
        let wasp_app_id = wasp_app.id;

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(app.context.clone(), &mut transaction, &[], &[user_id])
            .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("/api/v1/wasp-apps/auto-login"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        wasp_apps_cleanup(app.context.clone(), &mut transaction, wasp_app_id).await;

        api::setup::tests::setup_cleanup(app.context.clone(), &mut transaction, &[company_id], &[])
            .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn create_201() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let wasp_app = wasp_apps_create(router, session_id).await;
        let wasp_app_id = wasp_app.id;

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        wasp_apps_cleanup(app.context.clone(), &mut transaction, wasp_app_id).await;

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id],
            &[user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn create_400() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/api/v1/wasp-apps")
            .header(
                http::header::CONTENT_TYPE,
                mime::MULTIPART_FORM_DATA.as_ref(),
            )
            .header("X-Auth-Token".to_string(), session_id.to_string())
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id],
            &[user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn create_401() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let admin_session_id = session_response.id;

        let (email, is_enabled, job_title, name, password, roles) =
            api::users::tests::get_user_create_params();
        let user = api::users::tests::user_create(
            router.clone(),
            admin_session_id,
            &email,
            is_enabled,
            &job_title,
            &name,
            &password,
            &roles,
        )
        .await;
        let second_user_id = user.id;

        let body =
            multipart::tests::file_data("application/zip", "test.zip", "data/test/test.zip", false)
                .unwrap();

        let mut fields = HashMap::new();
        fields.insert("description", "test wasp application");
        fields.insert("name", "test");
        fields.insert("is_enabled", "true");
        fields.insert("instance_type", "Private");

        let body = multipart::tests::text_field_data(&body, fields, true);

        let value = format!(
            "{}; boundary={}",
            mime::MULTIPART_FORM_DATA,
            multipart::tests::BOUNDARY
        );

        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/api/v1/wasp-apps")
            .header(http::header::CONTENT_TYPE, value)
            .body(body)
            .unwrap();

        let response = router.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id],
            &[user_id, second_user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn create_403() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let admin_session_id = session_response.id;

        let (email, is_enabled, job_title, name, password, roles) =
            api::users::tests::get_user_create_params();
        let user = api::users::tests::user_create(
            router.clone(),
            admin_session_id,
            &email,
            is_enabled,
            &job_title,
            &name,
            &password,
            &roles,
        )
        .await;
        let second_user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, second_user_id)
                .await;
        let session_id = session_response.id;

        let body =
            multipart::tests::file_data("application/zip", "test.zip", "data/test/test.zip", false)
                .unwrap();

        let mut fields = HashMap::new();
        fields.insert("description", "test wasp application");
        fields.insert("name", "test");
        fields.insert("is_enabled", "true");
        fields.insert("instance_type", "Private");

        let body = multipart::tests::text_field_data(&body, fields, true);

        let value = format!(
            "{}; boundary={}",
            mime::MULTIPART_FORM_DATA,
            multipart::tests::BOUNDARY
        );

        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/api/v1/wasp-apps")
            .header(http::header::CONTENT_TYPE, value)
            .header("X-Auth-Token".to_string(), session_id.to_string())
            .body(body)
            .unwrap();

        let response = router.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id],
            &[user_id, second_user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn create_403_deleted_user() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(app.context.clone(), &mut transaction, &[], &[user_id])
            .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;

        let body =
            multipart::tests::file_data("application/zip", "test.zip", "data/test/test.zip", false)
                .unwrap();

        let mut fields = HashMap::new();
        fields.insert("description", "test wasp application");
        fields.insert("name", "test");
        fields.insert("is_enabled", "true");
        fields.insert("instance_type", "Private");

        let body = multipart::tests::text_field_data(&body, fields, true);

        let value = format!(
            "{}; boundary={}",
            mime::MULTIPART_FORM_DATA,
            multipart::tests::BOUNDARY
        );

        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/api/v1/wasp-apps")
            .header(http::header::CONTENT_TYPE, value)
            .header("X-Auth-Token".to_string(), session_id.to_string())
            .body(body)
            .unwrap();

        let response = router.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(app.context.clone(), &mut transaction, &[company_id], &[])
            .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn delete_204() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let wasp_app = wasp_apps_create(router.clone(), session_id).await;
        let wasp_app_id = wasp_app.id;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::DELETE)
                    .uri(format!("/api/v1/wasp-apps/{wasp_app_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id],
            &[user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn delete_401() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let wasp_app = wasp_apps_create(router.clone(), session_id).await;
        let wasp_app_id = wasp_app.id;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::DELETE)
                    .uri(format!("/api/v1/wasp-apps/{wasp_app_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        wasp_apps_cleanup(app.context.clone(), &mut transaction, wasp_app_id).await;

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id],
            &[user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn delete_403() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let wasp_app = wasp_apps_create(router.clone(), session_id).await;
        let wasp_app_id = wasp_app.id;

        let (email, is_enabled, job_title, name, password, roles) =
            api::users::tests::get_user_create_params();
        let user = api::users::tests::user_create(
            router.clone(),
            session_id,
            &email,
            is_enabled,
            &job_title,
            &name,
            &password,
            &roles,
        )
        .await;
        let second_user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, second_user_id)
                .await;
        let session_id = session_response.id;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::DELETE)
                    .uri(format!("/api/v1/wasp-apps/{wasp_app_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        wasp_apps_cleanup(app.context.clone(), &mut transaction, wasp_app_id).await;

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id],
            &[user_id, second_user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn delete_403_deleted_user() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let wasp_app = wasp_apps_create(router.clone(), session_id).await;
        let wasp_app_id = wasp_app.id;

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(app.context.clone(), &mut transaction, &[], &[user_id])
            .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::DELETE)
                    .uri(format!("/api/v1/wasp-apps/{wasp_app_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        wasp_apps_cleanup(app.context.clone(), &mut transaction, wasp_app_id).await;

        api::setup::tests::setup_cleanup(app.context.clone(), &mut transaction, &[company_id], &[])
            .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn delete_404() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let wasp_app_id = "33847746-0030-4964-a496-f75d04499160";

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::DELETE)
                    .uri(format!("/api/v1/wasp-apps/{wasp_app_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id],
            &[user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn extract_meta_400() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/api/v1/wasp-apps/extract-meta")
            .header(
                http::header::CONTENT_TYPE,
                mime::MULTIPART_FORM_DATA.as_ref(),
            )
            .header("X-Auth-Token".to_string(), session_id.to_string())
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id],
            &[user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn extract_meta_401() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let admin_session_id = session_response.id;

        let (email, is_enabled, job_title, name, password, roles) =
            api::users::tests::get_user_create_params();
        let user = api::users::tests::user_create(
            router.clone(),
            admin_session_id,
            &email,
            is_enabled,
            &job_title,
            &name,
            &password,
            &roles,
        )
        .await;
        let second_user_id = user.id;

        let body =
            multipart::tests::file_data("application/zip", "test.zip", "data/test/test.zip", true)
                .unwrap();

        let value = format!(
            "{}; boundary={}",
            mime::MULTIPART_FORM_DATA,
            multipart::tests::BOUNDARY
        );

        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/api/v1/wasp-apps/extract-meta")
            .header(http::header::CONTENT_TYPE, value)
            .body(body)
            .unwrap();

        let response = router.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id],
            &[user_id, second_user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn extract_meta_403() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let admin_session_id = session_response.id;

        let (email, is_enabled, job_title, name, password, roles) =
            api::users::tests::get_user_create_params();
        let user = api::users::tests::user_create(
            router.clone(),
            admin_session_id,
            &email,
            is_enabled,
            &job_title,
            &name,
            &password,
            &roles,
        )
        .await;
        let second_user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, second_user_id)
                .await;
        let session_id = session_response.id;

        let body =
            multipart::tests::file_data("application/zip", "test.zip", "data/test/test.zip", true)
                .unwrap();

        let value = format!(
            "{}; boundary={}",
            mime::MULTIPART_FORM_DATA,
            multipart::tests::BOUNDARY
        );

        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/api/v1/wasp-apps/extract-meta")
            .header(http::header::CONTENT_TYPE, value)
            .header("X-Auth-Token".to_string(), session_id.to_string())
            .body(body)
            .unwrap();

        let response = router.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id],
            &[user_id, second_user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn extract_meta_403_deleted_user() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(app.context.clone(), &mut transaction, &[], &[user_id])
            .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;

        let body =
            multipart::tests::file_data("application/zip", "test.zip", "data/test/test.zip", true)
                .unwrap();

        let value = format!(
            "{}; boundary={}",
            mime::MULTIPART_FORM_DATA,
            multipart::tests::BOUNDARY
        );

        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/api/v1/wasp-apps/extract-meta")
            .header(http::header::CONTENT_TYPE, value)
            .header("X-Auth-Token".to_string(), session_id.to_string())
            .body(body)
            .unwrap();

        let response = router.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(app.context.clone(), &mut transaction, &[company_id], &[])
            .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn list_200() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let wasp_app = wasp_apps_create(router.clone(), session_id).await;
        let wasp_app_id = wasp_app.id;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri("/api/v1/wasp-apps".to_string())
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = BodyExt::collect(response.into_body())
            .await
            .unwrap()
            .to_bytes()
            .to_vec();
        let body: Vec<WaspApp> = serde_json::from_slice(&body).unwrap();

        assert!(!body.is_empty());

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        wasp_apps_cleanup(app.context.clone(), &mut transaction, wasp_app_id).await;

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id],
            &[user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn list_401() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let wasp_app = wasp_apps_create(router.clone(), session_id).await;
        let wasp_app_id = wasp_app.id;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri("/api/v1/wasp-apps".to_string())
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        wasp_apps_cleanup(app.context.clone(), &mut transaction, wasp_app_id).await;

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id],
            &[user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn list_403_deleted_user() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let wasp_app = wasp_apps_create(router.clone(), session_id).await;
        let wasp_app_id = wasp_app.id;

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(app.context.clone(), &mut transaction, &[], &[user_id])
            .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri("/api/v1/wasp-apps".to_string())
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        wasp_apps_cleanup(app.context.clone(), &mut transaction, wasp_app_id).await;

        api::setup::tests::setup_cleanup(app.context.clone(), &mut transaction, &[company_id], &[])
            .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn logs_200() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let (name, r#type) = api::workspaces::tests::get_workspace_create_params_public();
        let message = api::chat_messages::tests::get_chat_message_create_params();
        let (chat_id, chat_message_id, workspace_id) =
            api::chat_messages::tests::chat_message_with_deps_create(
                router.clone(),
                session_id,
                user_id,
                &message,
                &name,
                &r#type,
            )
            .await;

        let wasp_app = wasp_apps_create(router.clone(), session_id).await;
        let wasp_app_id = wasp_app.id;

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        app.context
            .octopus_database
            .update_wasp_app_is_enabled(&mut transaction, wasp_app_id, true)
            .await
            .unwrap();

        app.context
            .octopus_database
            .update_chat_message_wasp_app_id(
                &mut transaction,
                chat_message_id,
                100,
                wasp_app_id,
                ChatMessageStatus::Answered,
            )
            .await
            .unwrap();

        api::tests::transaction_commit(app.context.clone(), transaction).await;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!(
                        "/api/v1/wasp-apps/{wasp_app_id}/{chat_message_id}/logs"
                    ))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = BodyExt::collect(response.into_body())
            .await
            .unwrap()
            .to_bytes()
            .to_vec();
        let body = String::from_utf8(body).unwrap();

        assert_eq!(body, "".to_string());

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        wasp_apps_cleanup(app.context.clone(), &mut transaction, wasp_app_id).await;

        api::chat_messages::tests::chat_message_with_deps_cleanup(
            app.context.clone(),
            &mut transaction,
            chat_id,
            chat_message_id,
            workspace_id,
        )
        .await;

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id],
            &[user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn logs_401() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let (name, r#type) = api::workspaces::tests::get_workspace_create_params_public();
        let message = api::chat_messages::tests::get_chat_message_create_params();
        let (chat_id, chat_message_id, workspace_id) =
            api::chat_messages::tests::chat_message_with_deps_create(
                router.clone(),
                session_id,
                user_id,
                &message,
                &name,
                &r#type,
            )
            .await;

        let wasp_app = wasp_apps_create(router.clone(), session_id).await;
        let wasp_app_id = wasp_app.id;

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        app.context
            .octopus_database
            .update_wasp_app_is_enabled(&mut transaction, wasp_app_id, true)
            .await
            .unwrap();

        app.context
            .octopus_database
            .update_chat_message_wasp_app_id(
                &mut transaction,
                chat_message_id,
                100,
                wasp_app_id,
                ChatMessageStatus::Answered,
            )
            .await
            .unwrap();

        api::tests::transaction_commit(app.context.clone(), transaction).await;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!(
                        "/api/v1/wasp-apps/{wasp_app_id}/{chat_message_id}/logs"
                    ))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        wasp_apps_cleanup(app.context.clone(), &mut transaction, wasp_app_id).await;

        api::chat_messages::tests::chat_message_with_deps_cleanup(
            app.context.clone(),
            &mut transaction,
            chat_id,
            chat_message_id,
            workspace_id,
        )
        .await;

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id],
            &[user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn logs_403() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let (name, r#type) = api::workspaces::tests::get_workspace_create_params_public();
        let message = api::chat_messages::tests::get_chat_message_create_params();
        let (chat_id, chat_message_id, workspace_id) =
            api::chat_messages::tests::chat_message_with_deps_create(
                router.clone(),
                session_id,
                user_id,
                &message,
                &name,
                &r#type,
            )
            .await;

        let wasp_app = wasp_apps_create(router.clone(), session_id).await;
        let wasp_app_id = wasp_app.id;

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        app.context
            .octopus_database
            .update_wasp_app_is_enabled(&mut transaction, wasp_app_id, true)
            .await
            .unwrap();

        app.context
            .octopus_database
            .update_chat_message_wasp_app_id(
                &mut transaction,
                chat_message_id,
                100,
                wasp_app_id,
                ChatMessageStatus::Answered,
            )
            .await
            .unwrap();

        api::tests::transaction_commit(app.context.clone(), transaction).await;

        let (email, is_enabled, job_title, name, password, roles) =
            api::users::tests::get_user_create_params();
        let user = api::users::tests::user_create(
            router.clone(),
            session_id,
            &email,
            is_enabled,
            &job_title,
            &name,
            &password,
            &roles,
        )
        .await;
        let second_user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, second_user_id)
                .await;
        let session_id = session_response.id;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!(
                        "/api/v1/wasp-apps/{wasp_app_id}/{chat_message_id}/logs"
                    ))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        wasp_apps_cleanup(app.context.clone(), &mut transaction, wasp_app_id).await;

        api::chat_messages::tests::chat_message_with_deps_cleanup(
            app.context.clone(),
            &mut transaction,
            chat_id,
            chat_message_id,
            workspace_id,
        )
        .await;

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id],
            &[user_id, second_user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn logs_403_deleted_user() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let (name, r#type) = api::workspaces::tests::get_workspace_create_params_public();
        let message = api::chat_messages::tests::get_chat_message_create_params();
        let (chat_id, chat_message_id, workspace_id) =
            api::chat_messages::tests::chat_message_with_deps_create(
                router.clone(),
                session_id,
                user_id,
                &message,
                &name,
                &r#type,
            )
            .await;

        let wasp_app = wasp_apps_create(router.clone(), session_id).await;
        let wasp_app_id = wasp_app.id;

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        app.context
            .octopus_database
            .update_wasp_app_is_enabled(&mut transaction, wasp_app_id, true)
            .await
            .unwrap();

        app.context
            .octopus_database
            .update_chat_message_wasp_app_id(
                &mut transaction,
                chat_message_id,
                100,
                wasp_app_id,
                ChatMessageStatus::Answered,
            )
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(app.context.clone(), &mut transaction, &[], &[user_id])
            .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!(
                        "/api/v1/wasp-apps/{wasp_app_id}/{chat_message_id}/logs"
                    ))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        wasp_apps_cleanup(app.context.clone(), &mut transaction, wasp_app_id).await;

        api::chat_messages::tests::chat_message_with_deps_cleanup(
            app.context.clone(),
            &mut transaction,
            chat_id,
            chat_message_id,
            workspace_id,
        )
        .await;

        api::setup::tests::setup_cleanup(app.context.clone(), &mut transaction, &[company_id], &[])
            .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn logs_404() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let wasp_app_id = "33847746-0030-4964-a496-f75d04499160";

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("/api/v1/wasp-apps/{wasp_app_id}/logs"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id],
            &[user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn read_200() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let wasp_app = wasp_apps_create(router.clone(), session_id).await;
        let wasp_app_id = wasp_app.id;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("/api/v1/wasp-apps/{wasp_app_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = BodyExt::collect(response.into_body())
            .await
            .unwrap()
            .to_bytes()
            .to_vec();
        let body: WaspApp = serde_json::from_slice(&body).unwrap();

        assert!(body.is_enabled);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        wasp_apps_cleanup(app.context.clone(), &mut transaction, wasp_app_id).await;

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id],
            &[user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn read_401() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let wasp_app = wasp_apps_create(router.clone(), session_id).await;
        let wasp_app_id = wasp_app.id;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("/api/v1/wasp-apps/{wasp_app_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        wasp_apps_cleanup(app.context.clone(), &mut transaction, wasp_app_id).await;

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id],
            &[user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn read_403_deleted_user() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let wasp_app = wasp_apps_create(router.clone(), session_id).await;
        let wasp_app_id = wasp_app.id;

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(app.context.clone(), &mut transaction, &[], &[user_id])
            .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("/api/v1/wasp-apps/{wasp_app_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        wasp_apps_cleanup(app.context.clone(), &mut transaction, wasp_app_id).await;

        api::setup::tests::setup_cleanup(app.context.clone(), &mut transaction, &[company_id], &[])
            .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn read_404() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let wasp_app_id = "33847746-0030-4964-a496-f75d04499160";

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("/api/v1/wasp-apps/{wasp_app_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id],
            &[user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn update_200() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let wasp_app = wasp_apps_create(router.clone(), session_id).await;
        let wasp_app_id = wasp_app.id;

        let body =
            multipart::tests::file_data("application/zip", "test.zip", "data/test/test.zip", false)
                .unwrap();

        let mut fields = HashMap::new();
        fields.insert("description", "test wasp application 2");
        fields.insert("name", "test 2");
        fields.insert("is_enabled", "true");
        fields.insert("instance_type", "Private");

        let body = multipart::tests::text_field_data(&body, fields, true);

        let value = format!(
            "{}; boundary={}",
            mime::MULTIPART_FORM_DATA,
            multipart::tests::BOUNDARY
        );

        let request = Request::builder()
            .method(http::Method::PUT)
            .uri(format!("/api/v1/wasp-apps/{wasp_app_id}"))
            .header(http::header::CONTENT_TYPE, value)
            .header("X-Auth-Token".to_string(), session_id.to_string())
            .body(body)
            .unwrap();

        let response = router.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = BodyExt::collect(response.into_body())
            .await
            .unwrap()
            .to_bytes()
            .to_vec();
        let body: WaspApp = serde_json::from_slice(&body).unwrap();

        assert!(body.is_enabled);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        wasp_apps_cleanup(app.context.clone(), &mut transaction, wasp_app_id).await;

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id],
            &[user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn update_200_no_code() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let wasp_app = wasp_apps_create(router.clone(), session_id).await;
        let wasp_app_id = wasp_app.id;

        let body =
            multipart::tests::file_data("text/html", "test.html", "data/test/test.html", false)
                .unwrap();

        let mut fields = HashMap::new();
        fields.insert("description", "test wasp application 2");
        fields.insert("name", "test 2");
        fields.insert("is_enabled", "true");
        fields.insert("instance_type", "Private");

        let body = multipart::tests::text_field_data(&body, fields, true);

        let value = format!(
            "{}; boundary={}",
            mime::MULTIPART_FORM_DATA,
            multipart::tests::BOUNDARY
        );

        let request = Request::builder()
            .method(http::Method::PUT)
            .uri(format!("/api/v1/wasp-apps/{wasp_app_id}"))
            .header(http::header::CONTENT_TYPE, value)
            .header("X-Auth-Token".to_string(), session_id.to_string())
            .body(body)
            .unwrap();

        let response = router.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = BodyExt::collect(response.into_body())
            .await
            .unwrap()
            .to_bytes()
            .to_vec();
        let body: WaspApp = serde_json::from_slice(&body).unwrap();

        assert!(body.is_enabled);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        wasp_apps_cleanup(app.context.clone(), &mut transaction, wasp_app_id).await;

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id],
            &[user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn update_400() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let wasp_app = wasp_apps_create(router.clone(), session_id).await;
        let wasp_app_id = wasp_app.id;

        let request = Request::builder()
            .method(http::Method::PUT)
            .uri(format!("/api/v1/wasp-apps/{wasp_app_id}"))
            .header(
                http::header::CONTENT_TYPE,
                mime::MULTIPART_FORM_DATA.as_ref(),
            )
            .header("X-Auth-Token".to_string(), session_id.to_string())
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        wasp_apps_cleanup(app.context.clone(), &mut transaction, wasp_app_id).await;

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id],
            &[user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn update_401() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let wasp_app = wasp_apps_create(router.clone(), session_id).await;
        let wasp_app_id = wasp_app.id;

        let body =
            multipart::tests::file_data("application/zip", "test.zip", "data/test/test.zip", false)
                .unwrap();

        let mut fields = HashMap::new();
        fields.insert("description", "test wasp application 2");
        fields.insert("name", "test 2");
        fields.insert("is_enabled", "true");
        fields.insert("instance_type", "Private");

        let body = multipart::tests::text_field_data(&body, fields, true);

        let value = format!(
            "{}; boundary={}",
            mime::MULTIPART_FORM_DATA,
            multipart::tests::BOUNDARY
        );

        let request = Request::builder()
            .method(http::Method::PUT)
            .uri(format!("/api/v1/wasp-apps/{wasp_app_id}"))
            .header(http::header::CONTENT_TYPE, value)
            .body(body)
            .unwrap();

        let response = router.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        wasp_apps_cleanup(app.context.clone(), &mut transaction, wasp_app_id).await;

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id],
            &[user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn update_403() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let wasp_app = wasp_apps_create(router.clone(), session_id).await;
        let wasp_app_id = wasp_app.id;

        let (email, is_enabled, job_title, name, password, roles) =
            api::users::tests::get_user_create_params();
        let user = api::users::tests::user_create(
            router.clone(),
            session_id,
            &email,
            is_enabled,
            &job_title,
            &name,
            &password,
            &roles,
        )
        .await;
        let second_user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, second_user_id)
                .await;
        let session_id = session_response.id;

        let body =
            multipart::tests::file_data("application/zip", "test.zip", "data/test/test.zip", false)
                .unwrap();

        let mut fields = HashMap::new();
        fields.insert("description", "test wasp application 2");
        fields.insert("name", "test 2");
        fields.insert("is_enabled", "true");
        fields.insert("instance_type", "Private");

        let body = multipart::tests::text_field_data(&body, fields, true);

        let value = format!(
            "{}; boundary={}",
            mime::MULTIPART_FORM_DATA,
            multipart::tests::BOUNDARY
        );

        let request = Request::builder()
            .method(http::Method::PUT)
            .uri(format!("/api/v1/wasp-apps/{wasp_app_id}"))
            .header(http::header::CONTENT_TYPE, value)
            .header("X-Auth-Token".to_string(), session_id.to_string())
            .body(body)
            .unwrap();

        let response = router.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        wasp_apps_cleanup(app.context.clone(), &mut transaction, wasp_app_id).await;

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id],
            &[user_id, second_user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn update_403_deleted_user() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let wasp_app = wasp_apps_create(router.clone(), session_id).await;
        let wasp_app_id = wasp_app.id;

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(app.context.clone(), &mut transaction, &[], &[user_id])
            .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;

        let body =
            multipart::tests::file_data("application/zip", "test.zip", "data/test/test.zip", false)
                .unwrap();

        let mut fields = HashMap::new();
        fields.insert("description", "test wasp application 2");
        fields.insert("name", "test 2");
        fields.insert("is_enabled", "true");
        fields.insert("instance_type", "Private");

        let body = multipart::tests::text_field_data(&body, fields, true);

        let value = format!(
            "{}; boundary={}",
            mime::MULTIPART_FORM_DATA,
            multipart::tests::BOUNDARY
        );

        let request = Request::builder()
            .method(http::Method::PUT)
            .uri(format!("/api/v1/wasp-apps/{wasp_app_id}"))
            .header(http::header::CONTENT_TYPE, value)
            .header("X-Auth-Token".to_string(), session_id.to_string())
            .body(body)
            .unwrap();

        let response = router.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        wasp_apps_cleanup(app.context.clone(), &mut transaction, wasp_app_id).await;

        api::setup::tests::setup_cleanup(app.context.clone(), &mut transaction, &[company_id], &[])
            .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn update_404() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, user_id).await;
        let session_id = session_response.id;

        let wasp_app_id = "33847746-0030-4964-a496-f75d04499160";

        let body =
            multipart::tests::file_data("application/zip", "test.zip", "data/test/test.zip", false)
                .unwrap();

        let mut fields = HashMap::new();
        fields.insert("description", "test wasp application 2");
        fields.insert("name", "test 2");
        fields.insert("is_enabled", "true");
        fields.insert("instance_type", "Private");

        let body = multipart::tests::text_field_data(&body, fields, true);

        let value = format!(
            "{}; boundary={}",
            mime::MULTIPART_FORM_DATA,
            multipart::tests::BOUNDARY
        );

        let request = Request::builder()
            .method(http::Method::PUT)
            .uri(format!("/api/v1/wasp-apps/{wasp_app_id}"))
            .header(http::header::CONTENT_TYPE, value)
            .header("X-Auth-Token".to_string(), session_id.to_string())
            .body(body)
            .unwrap();

        let response = router.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id],
            &[user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }
}
