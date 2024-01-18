use crate::{
    ai::function_call::{
        AiFunctionErrorResponse, AiFunctionFileResponse, AiFunctionResponse, AiFunctionTextResponse,
    },
    api::{
        ai_functions::{AiFunctionDirectCallPost, AiFunctionPut},
        ai_services::{
            AiServiceAllowedUsersPut, AiServiceConfigurationPut, AiServiceOperation,
            AiServiceOperationPost, AiServiceOperationResponse, AiServicePriorityPut,
        },
        auth::{
            change_password, change_password::ChangePasswordPut, login, login::LoginPost, logout,
            register, register::RegisterPost,
        },
        chat_messages::{ChatMessageFlagPut, ChatMessagePost, ChatMessagePut},
        chats::ChatPut,
        example_prompt_categories::{ExamplePromptCategoryPost, ExamplePromptCategoryPut},
        example_prompts::{ExamplePromptPost, ExamplePromptPut},
        inspection_disablings::InspectionDisablingPost,
        parameters::{ParameterPost, ParameterPut},
        password_resets::{PasswordResetPost, PasswordResetPut},
        profiles::ProfilePut,
        setup::{SetupInfoResponse, SetupPost},
        users::{UserInvitationPost, UserPost, UserPut},
        version::VersionInfoResponse,
        workspaces::{WorkspacePost, WorkspacePut},
    },
    context::Context,
    entity::{
        AiFunction, AiFunctionRequestContentType, AiFunctionResponseContentType, AiService,
        AiServiceHealthCheckStatus, AiServiceRequiredPythonVersion, AiServiceSetupStatus,
        AiServiceStatus, Chat, ChatActivity, ChatAudit, ChatMessage, ChatMessageExtended,
        ChatMessageFile, ChatMessagePicture, ChatMessageStatus, ChatPicture, ExamplePrompt,
        ExamplePromptCategory, InspectionDisabling, Parameter, PasswordResetToken, Profile,
        SimpleApp, User, UserExtended, WaspApp, Workspace, WorkspacesType,
    },
    error::ResponseError,
    server_resources::{Gpu, ServerResources},
    session::{SessionResponse, SessionResponseData},
    Result,
};
use axum::{
    error_handling::HandleErrorLayer,
    http::{header, Method, StatusCode},
    routing::{delete, get, post, put},
    Router,
};
use std::{sync::Arc, time::Duration};
use tower::{BoxError, ServiceBuilder};
use tower_http::{
    cors::{Any, CorsLayer},
    services::ServeDir,
    trace::TraceLayer,
};
use utoipa::{
    openapi::security::{ApiKey, ApiKeyValue, SecurityScheme},
    Modify, OpenApi,
};
use utoipa_swagger_ui::SwaggerUi;

mod ai_functions;
mod ai_services;
mod auth;
mod chat_activities;
mod chat_audits;
mod chat_message_files;
mod chat_message_pictures;
mod chat_messages;
mod chat_pictures;
mod chats;
mod example_prompt_categories;
mod example_prompts;
mod inspection_disablings;
mod parameters;
mod password_resets;
mod profile_pictures;
mod profiles;
mod server_resources;
mod setup;
mod simple_apps;
mod users;
mod version;
mod wasp_apps;
mod workspaces;

#[allow(clippy::too_many_lines)]
pub fn router(context: Arc<Context>) -> Result<Router> {
    #[derive(OpenApi)]
    #[openapi(
        components(
            schemas(
                AiFunction,
                AiFunctionDirectCallPost,
                AiFunctionErrorResponse,
                AiFunctionFileResponse,
                AiFunctionPut,
                AiFunctionRequestContentType,
                AiFunctionResponse,
                AiFunctionResponseContentType,
                AiFunctionTextResponse,
                AiService,
                AiServiceAllowedUsersPut,
                AiServiceConfigurationPut,
                AiServiceHealthCheckStatus,
                AiServiceOperation,
                AiServiceOperationPost,
                AiServiceOperationResponse,
                AiServicePriorityPut,
                AiServiceRequiredPythonVersion,
                AiServiceSetupStatus,
                AiServiceStatus,
                ChangePasswordPut,
                Chat,
                ChatActivity,
                ChatAudit,
                ChatMessage,
                ChatMessageExtended,
                ChatMessageFile,
                ChatMessageFlagPut,
                ChatMessagePicture,
                ChatMessagePost,
                ChatMessagePut,
                ChatMessageStatus,
                ChatPicture,
                ChatPut,
                ExamplePrompt,
                ExamplePromptCategory,
                ExamplePromptCategoryPost,
                ExamplePromptCategoryPut,
                ExamplePromptPost,
                ExamplePromptPut,
                Gpu,
                InspectionDisabling,
                InspectionDisablingPost,
                LoginPost,
                Parameter,
                ParameterPost,
                ParameterPut,
                PasswordResetPost,
                PasswordResetPut,
                PasswordResetToken,
                Profile,
                ProfilePut,
                RegisterPost,
                ResponseError,
                ServerResources,
                SessionResponse,
                SessionResponseData,
                SetupInfoResponse,
                SetupPost,
                SimpleApp,
                User,
                UserExtended,
                UserInvitationPost,
                UserPost,
                UserPut,
                VersionInfoResponse,
                WaspApp,
                Workspace,
                WorkspacePost,
                WorkspacePut,
                WorkspacesType,
            )
        ),
        modifiers(&SecurityAddon),
        paths(
            ai_functions::delete,
            ai_functions::direct_call,
            ai_functions::list,
            ai_functions::read,
            ai_functions::update,
            ai_services::allowed_users,
            ai_services::configuration,
            ai_services::create,
            ai_services::delete,
            ai_services::installation,
            ai_services::list,
            ai_services::logs,
            ai_services::operation,
            ai_services::priority,
            ai_services::read,
            ai_services::update,
            change_password::change_password,
            chat_activities::create,
            chat_activities::list,
            chat_audits::list,
            chat_audits::read,
            chat_messages::anonymize,
            chat_messages::create,
            chat_messages::delete,
            chat_messages::flag,
            chat_messages::latest,
            chat_messages::list,
            chat_messages::not_sensitive,
            chat_messages::read,
            chat_messages::regenerate,
            chat_messages::update,
            chat_message_files::delete,
            chat_message_files::list,
            chat_message_files::read,
            chat_message_pictures::create,
            chat_message_pictures::delete,
            chat_message_pictures::read,
            chat_message_pictures::update,
            chat_pictures::create,
            chat_pictures::delete,
            chat_pictures::read,
            chat_pictures::update,
            chats::create,
            chats::delete,
            chats::latest,
            chats::list,
            chats::read,
            chats::update,
            example_prompt_categories::create,
            example_prompt_categories::delete,
            example_prompt_categories::list,
            example_prompt_categories::read,
            example_prompt_categories::update,
            example_prompts::create,
            example_prompts::delete,
            example_prompts::list,
            example_prompts::list_by_category,
            example_prompts::read,
            example_prompts::update,
            inspection_disablings::create,
            inspection_disablings::delete,
            inspection_disablings::read,
            login::login,
            logout::logout,
            parameters::create,
            parameters::delete,
            parameters::list,
            parameters::names,
            parameters::read,
            parameters::update,
            password_resets::change_password,
            password_resets::request,
            password_resets::validate,
            profiles::read,
            profiles::update,
            profile_pictures::delete,
            profile_pictures::update,
            register::register,
            server_resources::info,
            setup::info,
            setup::setup,
            simple_apps::code,
            simple_apps::create,
            simple_apps::delete,
            simple_apps::list,
            simple_apps::read,
            simple_apps::update,
            users::create,
            users::delete,
            users::invitation,
            users::list,
            users::read,
            users::roles,
            users::update,
            version::info,
            wasp_apps::create,
            wasp_apps::delete,
            wasp_apps::list,
            wasp_apps::proxy_frontend,
            wasp_apps::read,
            wasp_apps::update,
            workspaces::create,
            workspaces::delete,
            workspaces::list,
            workspaces::read,
            workspaces::update,
        ),
        tags(
            (name = "ai_functions", description = "AI functions API."),
            (name = "ai_services", description = "AI services API."),
            (name = "change_password", description = "Change password API."),
            (name = "chats", description = "Chats API."),
            (name = "chat_activities", description = "Chat activities API."),
            (name = "chat_audits", description = "Chat audits API."),
            (name = "chat_messages", description = "Chat messages API."),
            (name = "chat_message_files", description = "Chat message files API."),
            (name = "chat_message_pictures", description = "Chat message pictures API."),
            (name = "chat_pictures", description = "Chat pictures API."),
            (name = "example_prompt_categories", description = "Example prompt categories API."),
            (name = "example_prompts", description = "Example prompts API."),
            (name = "inspection_disablings", description = "Inspection disablings API."),
            (name = "login", description = "Login API."),
            (name = "logout", description = "Logout API."),
            (name = "parameters", description = "Parameters API."),
            (name = "password_resets", description = "Password resets API."),
            (name = "profiles", description = "Profiles API."),
            (name = "profile_pictures", description = "Profile pictures API."),
            (name = "register", description = "Register API."),
            (name = "server_resources", description = "Server resources API."),
            (name = "setup", description = "Setup API."),
            (name = "simple_apps", description = "Simple apps API."),
            (name = "users", description = "Users API."),
            (name = "version", description = "Version API."),
            (name = "wasp_apps", description = "Wasp apps API."),
            (name = "workspaces", description = "Workspaces API."),
        )
    )]
    struct ApiDoc;

    struct SecurityAddon;

    impl Modify for SecurityAddon {
        fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
            if let Some(components) = openapi.components.as_mut() {
                components.add_security_scheme(
                    "api_key",
                    SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::new("X-Auth-Token"))),
                );
            }
        }
    }

    let router = Router::new()
        .nest_service("/public", ServeDir::new("public"))
        .merge(SwaggerUi::new("/swagger-ui").url("/api-doc/openapi.json", ApiDoc::openapi()))
        .route("/api/v1/auth", delete(logout::logout).post(login::login))
        .route("/api/v1/auth/register", post(register::register))
        .route(
            "/api/v1/auth/:user_id",
            put(change_password::change_password),
        )
        .route(
            "/api/v1/ai-functions/direct-call",
            post(ai_functions::direct_call),
        )
        .route(
            "/api/v1/ai-functions/:ai_service_id",
            get(ai_functions::list),
        )
        .route(
            "/api/v1/ai-functions/:ai_service_id/:ai_function_id",
            delete(ai_functions::delete)
                .get(ai_functions::read)
                .put(ai_functions::update),
        )
        .route(
            "/api/v1/ai-services",
            get(ai_services::list).post(ai_services::create),
        )
        .route(
            "/api/v1/ai-services/:id/allowed-users",
            put(ai_services::allowed_users),
        )
        .route(
            "/api/v1/ai-services/:id/configuration",
            put(ai_services::configuration),
        )
        .route(
            "/api/v1/ai-services/:id/installation",
            put(ai_services::installation),
        )
        .route("/api/v1/ai-services/:id/logs", get(ai_services::logs))
        .route(
            "/api/v1/ai-services/:id/priority",
            put(ai_services::priority),
        )
        .route(
            "/api/v1/ai-services/:id",
            delete(ai_services::delete)
                .get(ai_services::read)
                .post(ai_services::operation)
                .put(ai_services::update),
        )
        .route(
            "/api/v1/chat-activities/:chat_id",
            get(chat_activities::list).post(chat_activities::create),
        )
        .route("/api/v1/chat-audits", get(chat_audits::list))
        .route("/api/v1/chat-audits/:chat_audit_id", get(chat_audits::read))
        .route(
            "/api/v1/chat-messages/:chat_id",
            get(chat_messages::list).post(chat_messages::create),
        )
        .route(
            "/api/v1/chat-messages/:chat_id/latest",
            get(chat_messages::latest),
        )
        .route(
            "/api/v1/chat-messages/:chat_id/:chat_message_id",
            delete(chat_messages::delete)
                .get(chat_messages::read)
                .post(chat_messages::regenerate)
                .put(chat_messages::update),
        )
        .route(
            "/api/v1/chat-messages/:chat_id/:chat_message_id/anonymize",
            put(chat_messages::anonymize),
        )
        .route(
            "/api/v1/chat-messages/:chat_id/:chat_message_id/flag",
            put(chat_messages::flag),
        )
        .route(
            "/api/v1/chat-messages/:chat_id/:chat_message_id/not-sensitive",
            put(chat_messages::not_sensitive),
        )
        .route(
            "/api/v1/chat-message-files/:chat_message_id",
            get(chat_message_files::list),
        )
        .route(
            "/api/v1/chat-message-files/:chat_message_id/:chat_message_file_id",
            delete(chat_message_files::delete).get(chat_message_files::read),
        )
        .route(
            "/api/v1/chat-message-pictures/:chat_message_id",
            post(chat_message_pictures::create),
        )
        .route(
            "/api/v1/chat-message-pictures/:chat_message_id/:chat_message_picture_id",
            delete(chat_message_pictures::delete)
                .get(chat_message_pictures::read)
                .put(chat_message_pictures::update),
        )
        .route(
            "/api/v1/chat-pictures/:chat_id",
            post(chat_pictures::create),
        )
        .route(
            "/api/v1/chat-pictures/:chat_id/:chat_picture_id",
            delete(chat_pictures::delete)
                .get(chat_pictures::read)
                .put(chat_pictures::update),
        )
        .route(
            "/api/v1/chats/:workspace_id",
            get(chats::list).post(chats::create),
        )
        .route("/api/v1/chats/:workspace_id/latest", get(chats::latest))
        .route(
            "/api/v1/chats/:workspace_id/:chat_id",
            delete(chats::delete).get(chats::read).put(chats::update),
        )
        .route(
            "/api/v1/example-prompts",
            get(example_prompts::list).post(example_prompts::create),
        )
        .route(
            "/api/v1/example-prompts/by-category/:example_prompt_category_id",
            get(example_prompts::list_by_category),
        )
        .route(
            "/api/v1/example-prompts/:id",
            delete(example_prompts::delete)
                .get(example_prompts::read)
                .put(example_prompts::update),
        )
        .route(
            "/api/v1/example-prompt-categories",
            get(example_prompt_categories::list).post(example_prompt_categories::create),
        )
        .route(
            "/api/v1/example-prompt-categories/:id",
            delete(example_prompt_categories::delete)
                .get(example_prompt_categories::read)
                .put(example_prompt_categories::update),
        )
        .route(
            "/api/v1/inspection-disablings/:user_id",
            delete(inspection_disablings::delete)
                .get(inspection_disablings::read)
                .post(inspection_disablings::create),
        )
        .route(
            "/api/v1/parameters",
            get(parameters::list).post(parameters::create),
        )
        .route("/api/v1/parameters/names", get(parameters::names))
        .route(
            "/api/v1/parameters/:id",
            delete(parameters::delete)
                .get(parameters::read)
                .put(parameters::update),
        )
        .route("/api/v1/password-resets", post(password_resets::request))
        .route(
            "/api/v1/password-resets/:token",
            get(password_resets::validate).put(password_resets::change_password),
        )
        .route(
            "/api/v1/profile-pictures/:user_id",
            delete(profile_pictures::delete).put(profile_pictures::update),
        )
        .route(
            "/api/v1/profiles/:user_id",
            get(profiles::read).put(profiles::update),
        )
        .route("/api/v1/server-resources", get(server_resources::info))
        .route("/api/v1/setup", get(setup::info).post(setup::setup))
        .route(
            "/api/v1/simple-apps",
            get(simple_apps::list).post(simple_apps::create),
        )
        .route("/api/v1/simple-apps/:id/code", get(simple_apps::code))
        .route(
            "/api/v1/simple-apps/:id",
            delete(simple_apps::delete)
                .get(simple_apps::read)
                .put(simple_apps::update),
        )
        .route("/api/v1/users", get(users::list).post(users::create))
        .route("/api/v1/users/invitation", post(users::invitation))
        .route("/api/v1/users/roles", get(users::roles))
        .route(
            "/api/v1/users/:user_id",
            delete(users::delete).get(users::read).put(users::update),
        )
        .route("/api/v1/version", get(version::info))
        .route(
            "/api/v1/wasp-apps",
            get(wasp_apps::list).post(wasp_apps::create),
        )
        .route(
            "/api/v1/wasp-apps/:id/:chat_message_id/proxy-backend",
            delete(wasp_apps::proxy_backend)
                .get(wasp_apps::proxy_backend)
                .post(wasp_apps::proxy_backend)
                .put(wasp_apps::proxy_backend),
        )
        .route(
            "/api/v1/wasp-apps/:id/:chat_message_id/proxy-backend/*pass",
            delete(wasp_apps::proxy_backend)
                .get(wasp_apps::proxy_backend)
                .post(wasp_apps::proxy_backend)
                .put(wasp_apps::proxy_backend),
        )
        .route(
            "/api/v1/wasp-apps/:id/:chat_message_id/proxy-frontend",
            delete(wasp_apps::proxy_frontend)
                .get(wasp_apps::proxy_frontend)
                .post(wasp_apps::proxy_frontend)
                .put(wasp_apps::proxy_frontend),
        )
        .route(
            "/api/v1/wasp-apps/:id/:chat_message_id/proxy-frontend/",
            delete(wasp_apps::proxy_frontend)
                .get(wasp_apps::proxy_frontend)
                .post(wasp_apps::proxy_frontend)
                .put(wasp_apps::proxy_frontend),
        )
        .route(
            "/api/v1/wasp-apps/:id/:chat_message_id/proxy-frontend/*pass",
            delete(wasp_apps::proxy_frontend)
                .get(wasp_apps::proxy_frontend)
                .post(wasp_apps::proxy_frontend)
                .put(wasp_apps::proxy_frontend),
        )
        .route(
            "/api/v1/wasp-apps/:id",
            delete(wasp_apps::delete)
                .get(wasp_apps::read)
                .put(wasp_apps::update),
        )
        .route(
            "/api/v1/workspaces",
            get(workspaces::list).post(workspaces::create),
        )
        .route(
            "/api/v1/workspaces/:id",
            delete(workspaces::delete)
                .get(workspaces::read)
                .put(workspaces::update),
        )
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(vec![
                    Method::DELETE,
                    Method::GET,
                    Method::OPTIONS,
                    Method::POST,
                    Method::PUT,
                ])
                .allow_headers(vec![
                    header::CONTENT_TYPE,
                    header::HeaderName::from_lowercase(b"x-auth-token")?,
                ]),
        )
        .layer(
            ServiceBuilder::new()
                .layer(HandleErrorLayer::new(|error: BoxError| async move {
                    if error.is::<tower::timeout::error::Elapsed>() {
                        Ok(StatusCode::REQUEST_TIMEOUT)
                    } else {
                        Err((
                            StatusCode::INTERNAL_SERVER_ERROR,
                            format!("Unhandled internal error: {error}"),
                        ))
                    }
                }))
                .timeout(Duration::from_secs(120))
                .layer(TraceLayer::new_for_http())
                .into_inner(),
        )
        .with_state(context);

    Ok(router)
}

pub fn ws_router(context: Arc<Context>) -> Result<Router> {
    #[derive(OpenApi)]
    #[openapi(
        modifiers(&SecurityAddon),
        paths(
            wasp_apps::proxy_backend_web_socket,
        ),
        tags(
            (name = "wasp_apps", description = "Wasp apps API."),
        )
    )]
    struct ApiDoc;

    struct SecurityAddon;

    impl Modify for SecurityAddon {
        fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
            if let Some(components) = openapi.components.as_mut() {
                components.add_security_scheme(
                    "api_key",
                    SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::new("X-Auth-Token"))),
                );
            }
        }
    }

    let router = Router::new()
        .merge(SwaggerUi::new("/swagger-ui").url("/api-doc/openapi.json", ApiDoc::openapi()))
        .route(
            "/api/v1/wasp-apps/:id/:chat_message_id/proxy-backend/",
            delete(wasp_apps::proxy_backend_web_socket)
                .get(wasp_apps::proxy_backend_web_socket)
                .post(wasp_apps::proxy_backend_web_socket)
                .put(wasp_apps::proxy_backend_web_socket),
        )
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(vec![
                    Method::DELETE,
                    Method::GET,
                    Method::OPTIONS,
                    Method::POST,
                    Method::PUT,
                ])
                .allow_headers(vec![
                    header::CONTENT_TYPE,
                    header::HeaderName::from_lowercase(b"x-auth-token")?,
                ]),
        )
        .layer(
            ServiceBuilder::new()
                .layer(HandleErrorLayer::new(|error: BoxError| async move {
                    if error.is::<tower::timeout::error::Elapsed>() {
                        Ok(StatusCode::REQUEST_TIMEOUT)
                    } else {
                        Err((
                            StatusCode::INTERNAL_SERVER_ERROR,
                            format!("Unhandled internal error: {error}"),
                        ))
                    }
                }))
                .timeout(Duration::from_secs(120))
                .layer(TraceLayer::new_for_http())
                .into_inner(),
        )
        .with_state(context);

    Ok(router)
}

#[cfg(test)]
pub mod tests {
    use crate::context::Context;
    use sqlx::{Postgres, Transaction};
    use std::sync::Arc;

    pub async fn transaction_commit(context: Arc<Context>, transaction: Transaction<'_, Postgres>) {
        context
            .octopus_database
            .transaction_commit(transaction)
            .await
            .unwrap();
    }
}
