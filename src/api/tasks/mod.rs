use crate::{
    ai::tasks,
    context::Context,
    entity::{
        ChatMessageStatus, ChatType, ROLE_SUPERVISOR, Task, TaskStatus, TaskType, WorkspacesType,
    },
    error::{AppError, ResponseError},
    session::{ExtractedSession, require_authenticated},
    util,
};
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::Deserialize;
use std::sync::Arc;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;
use validator::Validate;

#[derive(Deserialize, IntoParams)]
pub struct Params {
    workspace_id: Uuid,
    task_id: Uuid,
}

#[derive(Debug, Deserialize, ToSchema, Validate)]
pub struct TaskPost {
    pub assigned_user_id: Option<Uuid>,
    pub chat_id: Uuid,
    pub existing_task_id: Option<Uuid>,
    pub use_task_book_generation: bool,
}

#[derive(Debug, Deserialize, ToSchema, Validate)]
pub struct TaskPut {
    pub assigned_user_id: Option<Uuid>,
    pub existing_task_id: Option<Uuid>,
    pub status: TaskStatus,
    pub use_task_book_generation: bool,
}

#[axum_macros::debug_handler]
#[utoipa::path(
    post,
    path = "/api/v1/tasks/:workspace_id",
    request_body = TaskPost,
    responses(
        (status = 201, description = "Task created.", body = Task),
        (status = 401, description = "Unauthorized.", body = ResponseError),
        (status = 403, description = "Forbidden.", body = ResponseError),
    ),
    params(
        ("workspace_id" = String, Path, description = "Workspace id")
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn create(
    State(context): State<Arc<Context>>,
    extracted_session: ExtractedSession,
    Path(workspace_id): Path<Uuid>,
    Json(input): Json<TaskPost>,
) -> Result<impl IntoResponse, AppError> {
    let session = require_authenticated(extracted_session).await?;
    input.validate()?;

    let session_user = context
        .octopus_database
        .try_get_user_by_id(session.user_id)
        .await?
        .ok_or(AppError::Forbidden)?;

    if !session_user.roles.contains(&ROLE_SUPERVISOR.to_string()) {
        return Err(AppError::Forbidden);
    }

    let workspace = context
        .octopus_database
        .try_get_workspace_by_id(workspace_id)
        .await?
        .ok_or(AppError::NotFound)?;

    match workspace.r#type {
        WorkspacesType::Private | WorkspacesType::PrivateScheduled => {
            return Err(AppError::Forbidden);
        }
        WorkspacesType::Public => {
            if workspace.company_id != session_user.company_id {
                return Err(AppError::Forbidden);
            }
        }
    }

    let task_info = tasks::get_task_info(context.clone(), input.chat_id).await?;

    let description = match task_info {
        None => None,
        Some(ref task_info) => task_info.description.clone(),
    };

    let task_questions = match task_info {
        None => vec![],
        Some(ref task_info) => task_info.task_questions.clone(),
    };

    let title = match task_info {
        None => None,
        Some(ref task_info) => task_info.title.clone(),
    };

    let r#type = match task_info {
        None => TaskType::Normal,
        Some(ref task_info) => task_info.r#type.clone(),
    };

    let mut transaction = context.octopus_database.transaction_begin().await?;

    let assigned_user_chat_id = if r#type == TaskType::Normal {
        if let Some(assigned_user_id) = input.assigned_user_id {
            let r#type = ChatType::Task;

            let chat = context
                .octopus_database
                .insert_chat(&mut transaction, assigned_user_id, workspace.id, r#type)
                .await?;

            if let Some(task_info) = task_info {
                if let Some(task_description_message) = task_info.task_description_message {
                    let estimated_response_at =
                        util::get_estimated_response_at(context.clone()).await?;

                    let chat_message = context
                        .octopus_database
                        .insert_chat_message(
                            &mut transaction,
                            chat.id,
                            assigned_user_id,
                            true,
                            estimated_response_at,
                            true,
                            &task_description_message,
                            None,
                            None,
                            None,
                            false,
                            None,
                            None,
                        )
                        .await?;

                    context
                        .octopus_database
                        .update_chat_message_status(
                            &mut transaction,
                            chat_message.id,
                            ChatMessageStatus::Answered,
                        )
                        .await?;
                }
            }

            Some(chat.id)
        } else {
            None
        }
    } else {
        None
    };

    let task = context
        .octopus_database
        .insert_task(
            &mut transaction,
            assigned_user_chat_id,
            input.assigned_user_id,
            input.chat_id,
            input.existing_task_id,
            session.user_id,
            workspace.id,
            description,
            TaskStatus::NotCompleted,
            title,
            r#type.clone(),
            input.use_task_book_generation,
        )
        .await?;

    if r#type == TaskType::Test {
        for task_question in task_questions {
            let _task_test = context
                .octopus_database
                .insert_task_test(
                    &mut transaction,
                    task.id,
                    session.user_id,
                    None,
                    task_question.question,
                )
                .await?;
        }
    }

    context
        .octopus_database
        .transaction_commit(transaction)
        .await?;

    Ok((StatusCode::CREATED, Json(task)).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    delete,
    path = "/api/v1/tasks/:workspace_id/:task_id",
    responses(
        (status = 204, description = "Task deleted."),
        (status = 401, description = "Unauthorized.", body = ResponseError),
        (status = 403, description = "Forbidden.", body = ResponseError),
        (status = 404, description = "Task not found.", body = ResponseError),
    ),
    params(
        ("workspace_id" = String, Path, description = "Workspace id"),
        ("task_id" = String, Path, description = "Task id")
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn delete(
    State(context): State<Arc<Context>>,
    extracted_session: ExtractedSession,
    Path(Params {
        workspace_id,
        task_id,
    }): Path<Params>,
) -> Result<impl IntoResponse, AppError> {
    let session = require_authenticated(extracted_session).await?;

    let session_user = context
        .octopus_database
        .try_get_user_by_id(session.user_id)
        .await?
        .ok_or(AppError::Forbidden)?;

    if !session_user.roles.contains(&ROLE_SUPERVISOR.to_string()) {
        return Err(AppError::Forbidden);
    }

    let workspace = context
        .octopus_database
        .try_get_workspace_by_id(workspace_id)
        .await?
        .ok_or(AppError::NotFound)?;

    match workspace.r#type {
        WorkspacesType::Private | WorkspacesType::PrivateScheduled => {
            return Err(AppError::Forbidden);
        }
        WorkspacesType::Public => {
            if workspace.company_id != session_user.company_id {
                return Err(AppError::Forbidden);
            }
        }
    }

    let task = context
        .octopus_database
        .try_get_task_by_id(task_id)
        .await?
        .ok_or(AppError::NotFound)?;

    let user = context
        .octopus_database
        .try_get_user_by_id(task.user_id)
        .await?
        .ok_or(AppError::NotFound)?;

    if session_user.id != task.user_id
        && (!session_user.roles.contains(&ROLE_SUPERVISOR.to_string())
            || session_user.company_id != user.company_id)
    {
        return Err(AppError::Forbidden);
    }

    if task.workspace_id != workspace_id {
        return Err(AppError::Forbidden);
    }

    let mut transaction = context.octopus_database.transaction_begin().await?;

    context
        .octopus_database
        .try_delete_task_by_id(&mut transaction, task_id)
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
    get,
    path = "/api/v1/tasks/:workspace_id/latest",
    responses(
        (status = 200, description = "Task latest.", body = Task),
        (status = 401, description = "Unauthorized.", body = ResponseError),
        (status = 403, description = "Forbidden.", body = ResponseError),
        (status = 404, description = "Workspace not found.", body = ResponseError),
    ),
    params(
        ("workspace_id" = String, Path, description = "Workspace id")
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn latest(
    State(context): State<Arc<Context>>,
    extracted_session: ExtractedSession,
    Path(workspace_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let session = require_authenticated(extracted_session).await?;

    let session_user = context
        .octopus_database
        .try_get_user_by_id(session.user_id)
        .await?
        .ok_or(AppError::Forbidden)?;

    if !session_user.roles.contains(&ROLE_SUPERVISOR.to_string()) {
        return Err(AppError::Forbidden);
    }

    let workspace = context
        .octopus_database
        .try_get_workspace_by_id(workspace_id)
        .await?
        .ok_or(AppError::NotFound)?;

    match workspace.r#type {
        WorkspacesType::Private | WorkspacesType::PrivateScheduled => {
            return Err(AppError::Forbidden);
        }
        WorkspacesType::Public => {
            if workspace.company_id != session_user.company_id {
                return Err(AppError::Forbidden);
            }
        }
    }

    let task = context
        .octopus_database
        .get_task_by_workspace_id_latest(workspace.id)
        .await?;

    Ok((StatusCode::OK, Json(task)).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    get,
    path = "/api/v1/tasks/:workspace_id/latest/assigned",
    responses(
        (status = 200, description = "Task latest assigned.", body = Task),
        (status = 401, description = "Unauthorized.", body = ResponseError),
        (status = 403, description = "Forbidden.", body = ResponseError),
        (status = 404, description = "Workspace not found.", body = ResponseError),
    ),
    params(
        ("workspace_id" = String, Path, description = "Workspace id")
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn latest_assigned(
    State(context): State<Arc<Context>>,
    extracted_session: ExtractedSession,
    Path(workspace_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let session = require_authenticated(extracted_session).await?;

    let session_user = context
        .octopus_database
        .try_get_user_by_id(session.user_id)
        .await?
        .ok_or(AppError::Forbidden)?;

    let workspace = context
        .octopus_database
        .try_get_workspace_by_id(workspace_id)
        .await?
        .ok_or(AppError::NotFound)?;

    match workspace.r#type {
        WorkspacesType::Private | WorkspacesType::PrivateScheduled => {
            return Err(AppError::Forbidden);
        }
        WorkspacesType::Public => {
            if workspace.company_id != session_user.company_id {
                return Err(AppError::Forbidden);
            }
        }
    }

    let task = context
        .octopus_database
        .get_task_by_assigned_user_id_and_workspace_id_latest(session_user.id, workspace.id)
        .await?;

    Ok((StatusCode::OK, Json(task)).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    get,
    path = "/api/v1/tasks/:workspace_id",
    responses(
        (status = 200, description = "List of tasks.", body = [Task]),
        (status = 401, description = "Unauthorized.", body = ResponseError),
        (status = 403, description = "Forbidden.", body = ResponseError),
        (status = 404, description = "Workspace not found.", body = ResponseError),
    ),
    params(
        ("workspace_id" = String, Path, description = "Workspace id")
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn list(
    State(context): State<Arc<Context>>,
    extracted_session: ExtractedSession,
    Path(workspace_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let session = require_authenticated(extracted_session).await?;

    let session_user = context
        .octopus_database
        .try_get_user_by_id(session.user_id)
        .await?
        .ok_or(AppError::Forbidden)?;

    if !session_user.roles.contains(&ROLE_SUPERVISOR.to_string()) {
        return Err(AppError::Forbidden);
    }

    let workspace = context
        .octopus_database
        .try_get_workspace_by_id(workspace_id)
        .await?
        .ok_or(AppError::NotFound)?;

    match workspace.r#type {
        WorkspacesType::Private | WorkspacesType::PrivateScheduled => {
            return Err(AppError::Forbidden);
        }
        WorkspacesType::Public => {
            if workspace.company_id != session_user.company_id {
                return Err(AppError::Forbidden);
            }
        }
    }

    let tasks = context
        .octopus_database
        .get_tasks_by_workspace_id(workspace.id)
        .await?;

    Ok((StatusCode::OK, Json(tasks)).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    get,
    path = "/api/v1/tasks/:workspace_id/assigned",
    responses(
        (status = 200, description = "List of tasks assigned to user.", body = [Task]),
        (status = 401, description = "Unauthorized.", body = ResponseError),
        (status = 403, description = "Forbidden.", body = ResponseError),
        (status = 404, description = "Workspace not found.", body = ResponseError),
    ),
    params(
        ("workspace_id" = String, Path, description = "Workspace id")
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn list_assigned(
    State(context): State<Arc<Context>>,
    extracted_session: ExtractedSession,
    Path(workspace_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let session = require_authenticated(extracted_session).await?;

    let session_user = context
        .octopus_database
        .try_get_user_by_id(session.user_id)
        .await?
        .ok_or(AppError::Forbidden)?;

    let workspace = context
        .octopus_database
        .try_get_workspace_by_id(workspace_id)
        .await?
        .ok_or(AppError::NotFound)?;

    match workspace.r#type {
        WorkspacesType::Private | WorkspacesType::PrivateScheduled => {
            return Err(AppError::Forbidden);
        }
        WorkspacesType::Public => {
            if workspace.company_id != session_user.company_id {
                return Err(AppError::Forbidden);
            }
        }
    }

    let tasks = context
        .octopus_database
        .get_tasks_by_assigned_user_id_and_workspace_id(session_user.id, workspace.id)
        .await?;

    Ok((StatusCode::OK, Json(tasks)).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    get,
    path = "/api/v1/tasks/:workspace_id/:task_id",
    responses(
        (status = 200, description = "Task read.", body = Task),
        (status = 401, description = "Unauthorized.", body = ResponseError),
        (status = 403, description = "Forbidden.", body = ResponseError),
        (status = 404, description = "Task not found.", body = ResponseError),
    ),
    params(
        ("workspace_id" = String, Path, description = "Workspace id"),
        ("task_id" = String, Path, description = "Task id")
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn read(
    State(context): State<Arc<Context>>,
    extracted_session: ExtractedSession,
    Path(Params {
        workspace_id,
        task_id,
    }): Path<Params>,
) -> Result<impl IntoResponse, AppError> {
    let session = require_authenticated(extracted_session).await?;

    let session_user = context
        .octopus_database
        .try_get_user_by_id(session.user_id)
        .await?
        .ok_or(AppError::Forbidden)?;

    if !session_user.roles.contains(&ROLE_SUPERVISOR.to_string()) {
        return Err(AppError::Forbidden);
    }

    let workspace = context
        .octopus_database
        .try_get_workspace_by_id(workspace_id)
        .await?
        .ok_or(AppError::NotFound)?;

    match workspace.r#type {
        WorkspacesType::Private | WorkspacesType::PrivateScheduled => {
            return Err(AppError::Forbidden);
        }
        WorkspacesType::Public => {
            if workspace.company_id != session_user.company_id {
                return Err(AppError::Forbidden);
            }
        }
    }

    let task = context
        .octopus_database
        .try_get_task_by_id(task_id)
        .await?
        .ok_or(AppError::NotFound)?;

    let user = context
        .octopus_database
        .try_get_user_by_id(task.user_id)
        .await?
        .ok_or(AppError::NotFound)?;

    if session_user.company_id != user.company_id {
        return Err(AppError::Forbidden);
    }

    if task.workspace_id != workspace_id {
        return Err(AppError::Forbidden);
    }

    Ok((StatusCode::OK, Json(task)).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    put,
    path = "/api/v1/tasks/:workspace_id/:task_id",
    request_body = TaskPut,
    responses(
        (status = 200, description = "Task updated.", body = Task),
        (status = 401, description = "Unauthorized.", body = ResponseError),
        (status = 403, description = "Forbidden.", body = ResponseError),
        (status = 404, description = "Task not found.", body = ResponseError),
    ),
    params(
        ("workspace_id" = String, Path, description = "Workspace id"),
        ("task_id" = String, Path, description = "Task id")
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn update(
    State(context): State<Arc<Context>>,
    extracted_session: ExtractedSession,
    Path(Params {
        workspace_id,
        task_id,
    }): Path<Params>,
    Json(input): Json<TaskPut>,
) -> Result<impl IntoResponse, AppError> {
    let session = require_authenticated(extracted_session).await?;
    input.validate()?;

    let session_user = context
        .octopus_database
        .try_get_user_by_id(session.user_id)
        .await?
        .ok_or(AppError::Forbidden)?;

    if !session_user.roles.contains(&ROLE_SUPERVISOR.to_string()) {
        return Err(AppError::Forbidden);
    }

    let workspace = context
        .octopus_database
        .try_get_workspace_by_id(workspace_id)
        .await?
        .ok_or(AppError::NotFound)?;

    match workspace.r#type {
        WorkspacesType::Private | WorkspacesType::PrivateScheduled => {
            return Err(AppError::Forbidden);
        }
        WorkspacesType::Public => {
            if workspace.company_id != session_user.company_id {
                return Err(AppError::Forbidden);
            }
        }
    }

    let task = context
        .octopus_database
        .try_get_task_by_id(task_id)
        .await?
        .ok_or(AppError::NotFound)?;

    let user = context
        .octopus_database
        .try_get_user_by_id(task.user_id)
        .await?
        .ok_or(AppError::NotFound)?;

    if session_user.id != task.user_id
        && (!session_user.roles.contains(&ROLE_SUPERVISOR.to_string())
            || session_user.company_id != user.company_id)
    {
        return Err(AppError::Forbidden);
    }

    if task.workspace_id != workspace_id {
        return Err(AppError::Forbidden);
    }

    let task_info = tasks::get_task_info(context.clone(), task.chat_id).await?;

    let description = match task_info {
        None => None,
        Some(ref task_info) => task_info.description.clone(),
    };

    let task_questions = match task_info {
        None => vec![],
        Some(ref task_info) => task_info.task_questions.clone(),
    };

    let title = match task_info {
        None => None,
        Some(ref task_info) => task_info.title.clone(),
    };

    let r#type = match task_info {
        None => TaskType::Normal,
        Some(ref task_info) => task_info.r#type.clone(),
    };

    let mut transaction = context.octopus_database.transaction_begin().await?;

    let assigned_user_chat_id = if r#type == TaskType::Normal {
        let r#type = ChatType::Task;

        if let (Some(assigned_user_chat_id), Some(assigned_user_id)) =
            (task.assigned_user_chat_id, input.assigned_user_id)
        {
            let assigned_user_chat = context
                .octopus_database
                .try_get_chat_by_id(assigned_user_chat_id)
                .await?;

            match assigned_user_chat {
                None => {
                    let chat = context
                        .octopus_database
                        .insert_chat(&mut transaction, assigned_user_id, workspace.id, r#type)
                        .await?;

                    if let Some(task_info) = task_info {
                        if let Some(task_description_message) = task_info.task_description_message {
                            let estimated_response_at =
                                util::get_estimated_response_at(context.clone()).await?;

                            let chat_message = context
                                .octopus_database
                                .insert_chat_message(
                                    &mut transaction,
                                    chat.id,
                                    assigned_user_id,
                                    true,
                                    estimated_response_at,
                                    true,
                                    &task_description_message,
                                    None,
                                    None,
                                    None,
                                    false,
                                    None,
                                    None,
                                )
                                .await?;

                            context
                                .octopus_database
                                .update_chat_message_status(
                                    &mut transaction,
                                    chat_message.id,
                                    ChatMessageStatus::Answered,
                                )
                                .await?;
                        }
                    }

                    Some(chat.id)
                }
                Some(assigned_user_chat) => {
                    if assigned_user_chat.user_id == assigned_user_id {
                        Some(assigned_user_chat.id)
                    } else {
                        let chat = context
                            .octopus_database
                            .insert_chat(&mut transaction, assigned_user_id, workspace.id, r#type)
                            .await?;

                        if let Some(task_info) = task_info {
                            if let Some(task_description_message) =
                                task_info.task_description_message
                            {
                                let estimated_response_at =
                                    util::get_estimated_response_at(context.clone()).await?;

                                let chat_message = context
                                    .octopus_database
                                    .insert_chat_message(
                                        &mut transaction,
                                        chat.id,
                                        assigned_user_id,
                                        true,
                                        estimated_response_at,
                                        true,
                                        &task_description_message,
                                        None,
                                        None,
                                        None,
                                        false,
                                        None,
                                        None,
                                    )
                                    .await?;

                                context
                                    .octopus_database
                                    .update_chat_message_status(
                                        &mut transaction,
                                        chat_message.id,
                                        ChatMessageStatus::Answered,
                                    )
                                    .await?;
                            }
                        }

                        Some(chat.id)
                    }
                }
            }
        } else if let Some(assigned_user_id) = input.assigned_user_id {
            let chat = context
                .octopus_database
                .insert_chat(&mut transaction, assigned_user_id, workspace.id, r#type)
                .await?;

            if let Some(task_info) = task_info {
                if let Some(task_description_message) = task_info.task_description_message {
                    let estimated_response_at =
                        util::get_estimated_response_at(context.clone()).await?;

                    context
                        .octopus_database
                        .insert_chat_message(
                            &mut transaction,
                            chat.id,
                            assigned_user_id,
                            true,
                            estimated_response_at,
                            true,
                            &task_description_message,
                            None,
                            None,
                            None,
                            false,
                            None,
                            None,
                        )
                        .await?;
                }
            }

            Some(chat.id)
        } else {
            None
        }
    } else {
        None
    };

    let task = context
        .octopus_database
        .update_task(
            &mut transaction,
            task_id,
            assigned_user_chat_id,
            input.assigned_user_id,
            input.existing_task_id,
            description,
            input.status,
            title,
            r#type.clone(),
            input.use_task_book_generation,
        )
        .await?;

    if r#type == TaskType::Test {
        let task_tests = context
            .octopus_database
            .get_task_tests_by_task_id(task.id)
            .await?;

        for task_test in task_tests {
            context
                .octopus_database
                .try_delete_task_test_by_id(&mut transaction, task_test.id)
                .await?;
        }

        for task_question in task_questions {
            let _task_test = context
                .octopus_database
                .insert_task_test(
                    &mut transaction,
                    task.id,
                    session.user_id,
                    None,
                    task_question.question,
                )
                .await?;
        }
    }

    context
        .octopus_database
        .transaction_commit(transaction)
        .await?;

    Ok((StatusCode::OK, Json(task)).into_response())
}

#[cfg(test)]
pub mod tests {
    use crate::{
        api, app,
        context::Context,
        entity::{ROLE_SUPERVISOR, Task, TaskStatus},
    };
    use axum::{
        Router,
        body::Body,
        http::{self, Request, StatusCode},
    };
    use http_body_util::BodyExt;
    use sqlx::{Postgres, Transaction};
    use std::sync::Arc;
    use tower::ServiceExt;
    use uuid::Uuid;

    pub async fn task_cleanup(
        context: Arc<Context>,
        transaction: &mut Transaction<'_, Postgres>,
        task_id: Uuid,
    ) {
        let _ = context
            .octopus_database
            .try_delete_task_by_id(transaction, task_id)
            .await;
    }

    pub async fn task_with_deps_cleanup(
        context: Arc<Context>,
        transaction: &mut Transaction<'_, Postgres>,
        chat_id: Uuid,
        task_id: Uuid,
        workspace_id: Uuid,
    ) {
        task_cleanup(context.clone(), transaction, task_id).await;

        api::chats::tests::chat_with_deps_cleanup(context, transaction, chat_id, workspace_id)
            .await;
    }

    pub async fn task_create(
        router: Router,
        session_id: Uuid,
        user_id: Uuid,
        workspace_id: Uuid,
        chat_id: Uuid,
        status: &str,
        use_task_book_generation: bool,
    ) -> Task {
        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri(format!("/api/v1/tasks/{workspace_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "chat_id": &chat_id,
                            "status": &status,
                            "use_task_book_generation": &use_task_book_generation,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = BodyExt::collect(response.into_body())
            .await
            .unwrap()
            .to_bytes()
            .to_vec();
        let body: Task = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);
        assert_eq!(body.workspace_id, workspace_id);

        body
    }

    pub async fn task_with_deps_create(
        router: Router,
        session_id: Uuid,
        user_id: Uuid,
        name: &str,
        r#type: &str,
    ) -> (Uuid, Uuid, Uuid) {
        let (chat_id, workspace_id) = api::chats::tests::chat_with_deps_create(
            router.clone(),
            session_id,
            user_id,
            name,
            r#type,
            "Task",
        )
        .await;

        let task = task_create(
            router,
            session_id,
            user_id,
            workspace_id,
            chat_id,
            "NotCompleted",
            false,
        )
        .await;

        (chat_id, task.id, workspace_id)
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

        let (name, r#type) = api::workspaces::tests::get_workspace_create_params_public();
        let (chat_id, task_id, workspace_id) =
            task_with_deps_create(router.clone(), session_id, user_id, &name, &r#type).await;

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        task_with_deps_cleanup(
            app.context.clone(),
            &mut transaction,
            chat_id,
            task_id,
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
        let session_id = session_response.id;

        let (name, r#type) = api::workspaces::tests::get_workspace_create_params_public();
        let (chat_id, workspace_id) = api::chats::tests::chat_with_deps_create(
            router.clone(),
            session_id,
            user_id,
            &name,
            &r#type,
            "Task",
        )
        .await;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri(format!("/api/v1/tasks/{workspace_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "chat_id": &chat_id,
                            "status": "NotCompleted",
                            "use_task_book_generation": false,
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

        api::workspaces::tests::workspace_cleanup(
            app.context.clone(),
            &mut transaction,
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

        let (email, is_enabled, job_title, name, password, mut roles) =
            api::users::tests::get_user_create_params();
        roles.push(ROLE_SUPERVISOR.to_string());
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

        let (name, r#type) = api::workspaces::tests::get_workspace_create_params_private();
        let (chat_id, workspace_id) = api::chats::tests::chat_with_deps_create(
            router.clone(),
            session_id,
            second_user_id,
            &name,
            &r#type,
            "Task",
        )
        .await;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri(format!("/api/v1/tasks/{workspace_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), admin_session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "chat_id": &chat_id,
                            "status": "NotCompleted",
                            "use_task_book_generation": false,
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

        api::workspaces::tests::workspace_cleanup(
            app.context.clone(),
            &mut transaction,
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

        let (name, r#type) = api::workspaces::tests::get_workspace_create_params_public();

        let (chat_id, workspace_id) = api::chats::tests::chat_with_deps_create(
            router.clone(),
            session_id,
            user_id,
            &name,
            &r#type,
            "Task",
        )
        .await;

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
                    .method(http::Method::POST)
                    .uri(format!("/api/v1/tasks/{workspace_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "chat_id": &chat_id,
                            "status": "NotCompleted",
                            "use_task_book_generation": false,
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

        api::workspaces::tests::workspace_cleanup(
            app.context.clone(),
            &mut transaction,
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

        let (name, r#type) = api::workspaces::tests::get_workspace_create_params_public();
        let (chat_id, task_id, workspace_id) =
            task_with_deps_create(router.clone(), session_id, user_id, &name, &r#type).await;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::DELETE)
                    .uri(format!("/api/v1/tasks/{workspace_id}/{task_id}"))
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

        api::chats::tests::chat_with_deps_cleanup(
            app.context.clone(),
            &mut transaction,
            chat_id,
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
    async fn delete_204_company_admin() {
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

        let (email, is_enabled, job_title, name, password, mut roles) =
            api::users::tests::get_user_create_params();
        roles.push(ROLE_SUPERVISOR.to_string());
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

        let (name, r#type) = api::workspaces::tests::get_workspace_create_params_public();
        let (chat_id, workspace_id) = api::chats::tests::chat_with_deps_create(
            router.clone(),
            admin_session_id,
            user_id,
            &name,
            &r#type,
            "Task",
        )
        .await;

        let task = task_create(
            router.clone(),
            session_id,
            second_user_id,
            workspace_id,
            chat_id,
            "NotCompleted",
            false,
        )
        .await;
        let task_id = task.id;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::DELETE)
                    .uri(format!("/api/v1/tasks/{workspace_id}/{task_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), admin_session_id.to_string())
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

        task_with_deps_cleanup(
            app.context.clone(),
            &mut transaction,
            chat_id,
            task_id,
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

        let (name, r#type) = api::workspaces::tests::get_workspace_create_params_public();
        let (chat_id, task_id, workspace_id) =
            task_with_deps_create(router.clone(), session_id, user_id, &name, &r#type).await;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::DELETE)
                    .uri(format!("/api/v1/tasks/{workspace_id}/{task_id}"))
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

        task_with_deps_cleanup(
            app.context.clone(),
            &mut transaction,
            chat_id,
            task_id,
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

        let (name, r#type) = api::workspaces::tests::get_workspace_create_params_public();
        let (chat_id, task_id, workspace_id) =
            task_with_deps_create(router.clone(), admin_session_id, user_id, &name, &r#type).await;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::DELETE)
                    .uri(format!("/api/v1/tasks/{workspace_id}/{task_id}"))
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

        task_with_deps_cleanup(
            app.context.clone(),
            &mut transaction,
            chat_id,
            task_id,
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
    async fn delete_403_different_company_admin() {
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

        let (email, is_enabled, job_title, name, password, mut roles) =
            api::users::tests::get_user_create_params();
        roles.push(ROLE_SUPERVISOR.to_string());
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

        let (name, r#type) = api::workspaces::tests::get_workspace_create_params_public();
        let (chat_id, workspace_id) = api::chats::tests::chat_with_deps_create(
            router.clone(),
            admin_session_id,
            user_id,
            &name,
            &r#type,
            "Task",
        )
        .await;

        let task = task_create(
            router.clone(),
            session_id,
            second_user_id,
            workspace_id,
            chat_id,
            "NotCompleted",
            false,
        )
        .await;
        let task_id = task.id;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let second_company_id = user.company_id;
        let third_user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, third_user_id)
                .await;
        let session_id = session_response.id;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::DELETE)
                    .uri(format!("/api/v1/tasks/{workspace_id}/{task_id}"))
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

        task_with_deps_cleanup(
            app.context.clone(),
            &mut transaction,
            chat_id,
            task_id,
            workspace_id,
        )
        .await;

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id, second_company_id],
            &[user_id, second_user_id, third_user_id],
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

        let (name, r#type) = api::workspaces::tests::get_workspace_create_params_public();
        let (chat_id, task_id, workspace_id) =
            task_with_deps_create(router.clone(), session_id, user_id, &name, &r#type).await;

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
                    .uri(format!("/api/v1/tasks/{workspace_id}/{task_id}"))
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

        task_with_deps_cleanup(
            app.context.clone(),
            &mut transaction,
            chat_id,
            task_id,
            workspace_id,
        )
        .await;

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

        let (name, r#type) = api::workspaces::tests::get_workspace_create_params_public();
        let workspace = api::workspaces::tests::workspace_create(
            router.clone(),
            session_id,
            user_id,
            &name,
            &r#type,
        )
        .await;
        let workspace_id = workspace.id;

        let task_id = "33847746-0030-4964-a496-f75d04499160";

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::DELETE)
                    .uri(format!("/api/v1/tasks/{workspace_id}/{task_id}"))
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

        api::workspaces::tests::workspace_cleanup(
            app.context.clone(),
            &mut transaction,
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
    async fn latest_200() {
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
        let (chat_id, task_id, workspace_id) =
            task_with_deps_create(router.clone(), session_id, user_id, &name, &r#type).await;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("/api/v1/tasks/{workspace_id}/latest"))
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
        let body: Option<Task> = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.unwrap().user_id, user_id);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        task_with_deps_cleanup(
            app.context.clone(),
            &mut transaction,
            chat_id,
            task_id,
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
    async fn latest_401() {
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
        let (chat_id, task_id, workspace_id) =
            task_with_deps_create(router.clone(), session_id, user_id, &name, &r#type).await;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("/api/v1/tasks/{workspace_id}/latest"))
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

        task_with_deps_cleanup(
            app.context.clone(),
            &mut transaction,
            chat_id,
            task_id,
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
    async fn latest_403() {
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
        let (chat_id, task_id, workspace_id) =
            task_with_deps_create(router.clone(), session_id, user_id, &name, &r#type).await;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let second_company_id = user.company_id;
        let second_user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, second_user_id)
                .await;
        let session_id = session_response.id;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("/api/v1/tasks/{workspace_id}/latest"))
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

        task_with_deps_cleanup(
            app.context.clone(),
            &mut transaction,
            chat_id,
            task_id,
            workspace_id,
        )
        .await;

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id, second_company_id],
            &[user_id, second_user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn latest_403_deleted_user() {
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
        let (chat_id, task_id, workspace_id) =
            task_with_deps_create(router.clone(), session_id, user_id, &name, &r#type).await;

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
                    .uri(format!("/api/v1/tasks/{workspace_id}/latest"))
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

        task_with_deps_cleanup(
            app.context.clone(),
            &mut transaction,
            chat_id,
            task_id,
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
    async fn latest_404() {
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

        let workspace_id = "33847746-0030-4964-a496-f75d04499160";

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("/api/v1/tasks/{workspace_id}/latest"))
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
    async fn latest_assigned_200() {
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
        let (chat_id, task_id, workspace_id) =
            task_with_deps_create(router.clone(), session_id, user_id, &name, &r#type).await;

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

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        let task = app
            .context
            .octopus_database
            .try_get_task_by_id(task_id)
            .await
            .unwrap()
            .unwrap();

        let _ = app
            .context
            .octopus_database
            .update_task(
                &mut transaction,
                task.id,
                task.assigned_user_chat_id,
                Some(second_user_id),
                task.existing_task_id,
                task.description,
                task.status,
                task.title,
                task.r#type,
                task.use_task_book_generation,
            )
            .await
            .unwrap();

        api::tests::transaction_commit(app.context.clone(), transaction).await;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("/api/v1/tasks/{workspace_id}/latest/assigned"))
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
        let body: Option<Task> = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.clone().unwrap().user_id, user_id);
        assert_eq!(body.unwrap().assigned_user_id.unwrap(), second_user_id);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        task_with_deps_cleanup(
            app.context.clone(),
            &mut transaction,
            chat_id,
            task_id,
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
    async fn latest_assigned_401() {
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
        let (chat_id, task_id, workspace_id) =
            task_with_deps_create(router.clone(), session_id, user_id, &name, &r#type).await;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("/api/v1/tasks/{workspace_id}/latest/assigned"))
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

        task_with_deps_cleanup(
            app.context.clone(),
            &mut transaction,
            chat_id,
            task_id,
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
    async fn latest_assigned_403() {
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
        let (chat_id, task_id, workspace_id) =
            task_with_deps_create(router.clone(), session_id, user_id, &name, &r#type).await;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let second_company_id = user.company_id;
        let second_user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, second_user_id)
                .await;
        let session_id = session_response.id;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("/api/v1/tasks/{workspace_id}/latest/assigned"))
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

        task_with_deps_cleanup(
            app.context.clone(),
            &mut transaction,
            chat_id,
            task_id,
            workspace_id,
        )
        .await;

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id, second_company_id],
            &[user_id, second_user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn latest_assigned_403_deleted_user() {
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
        let (chat_id, task_id, workspace_id) =
            task_with_deps_create(router.clone(), session_id, user_id, &name, &r#type).await;

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

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        let task = app
            .context
            .octopus_database
            .try_get_task_by_id(task_id)
            .await
            .unwrap()
            .unwrap();

        let _ = app
            .context
            .octopus_database
            .update_task(
                &mut transaction,
                task.id,
                task.assigned_user_chat_id,
                Some(second_user_id),
                task.existing_task_id,
                task.description,
                task.status,
                task.title,
                task.r#type,
                task.use_task_book_generation,
            )
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[],
            &[second_user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("/api/v1/tasks/{workspace_id}/latest/assigned"))
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

        task_with_deps_cleanup(
            app.context.clone(),
            &mut transaction,
            chat_id,
            task_id,
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
    async fn latest_assigned_404() {
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

        let workspace_id = "33847746-0030-4964-a496-f75d04499160";

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("/api/v1/tasks/{workspace_id}/latest/assigned"))
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

        let (name, r#type) = api::workspaces::tests::get_workspace_create_params_public();
        let (chat_id, task_id, workspace_id) =
            task_with_deps_create(router.clone(), session_id, user_id, &name, &r#type).await;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("/api/v1/tasks/{workspace_id}"))
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
        let body: Vec<Task> = serde_json::from_slice(&body).unwrap();

        assert!(!body.is_empty());

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        task_with_deps_cleanup(
            app.context.clone(),
            &mut transaction,
            chat_id,
            task_id,
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

        let (name, r#type) = api::workspaces::tests::get_workspace_create_params_public();
        let (chat_id, task_id, workspace_id) =
            task_with_deps_create(router.clone(), session_id, user_id, &name, &r#type).await;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("/api/v1/tasks/{workspace_id}"))
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

        task_with_deps_cleanup(
            app.context.clone(),
            &mut transaction,
            chat_id,
            task_id,
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
    async fn list_403() {
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
        let (chat_id, task_id, workspace_id) =
            task_with_deps_create(router.clone(), session_id, user_id, &name, &r#type).await;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let second_company_id = user.company_id;
        let second_user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, second_user_id)
                .await;
        let session_id = session_response.id;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("/api/v1/tasks/{workspace_id}"))
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

        task_with_deps_cleanup(
            app.context.clone(),
            &mut transaction,
            chat_id,
            task_id,
            workspace_id,
        )
        .await;

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id, second_company_id],
            &[user_id, second_user_id],
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

        let (name, r#type) = api::workspaces::tests::get_workspace_create_params_public();
        let (chat_id, task_id, workspace_id) =
            task_with_deps_create(router.clone(), session_id, user_id, &name, &r#type).await;

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
                    .uri(format!("/api/v1/tasks/{workspace_id}"))
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

        task_with_deps_cleanup(
            app.context.clone(),
            &mut transaction,
            chat_id,
            task_id,
            workspace_id,
        )
        .await;

        api::setup::tests::setup_cleanup(app.context.clone(), &mut transaction, &[company_id], &[])
            .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn list_404() {
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

        let workspace_id = "33847746-0030-4964-a496-f75d04499160";

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("/api/v1/tasks/{workspace_id}"))
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
    async fn list_assigned_200() {
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
        let (chat_id, task_id, workspace_id) =
            task_with_deps_create(router.clone(), session_id, user_id, &name, &r#type).await;

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

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        let task = app
            .context
            .octopus_database
            .try_get_task_by_id(task_id)
            .await
            .unwrap()
            .unwrap();

        let _ = app
            .context
            .octopus_database
            .update_task(
                &mut transaction,
                task.id,
                task.assigned_user_chat_id,
                Some(second_user_id),
                task.existing_task_id,
                task.description,
                task.status,
                task.title,
                task.r#type,
                task.use_task_book_generation,
            )
            .await
            .unwrap();

        api::tests::transaction_commit(app.context.clone(), transaction).await;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("/api/v1/tasks/{workspace_id}/assigned"))
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
        let body: Vec<Task> = serde_json::from_slice(&body).unwrap();

        assert!(!body.is_empty());

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        task_with_deps_cleanup(
            app.context.clone(),
            &mut transaction,
            chat_id,
            task_id,
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
    async fn list_assigned_401() {
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
        let (chat_id, task_id, workspace_id) =
            task_with_deps_create(router.clone(), session_id, user_id, &name, &r#type).await;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("/api/v1/tasks/{workspace_id}/assigned"))
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

        task_with_deps_cleanup(
            app.context.clone(),
            &mut transaction,
            chat_id,
            task_id,
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
    async fn list_assigned_403() {
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
        let (chat_id, task_id, workspace_id) =
            task_with_deps_create(router.clone(), session_id, user_id, &name, &r#type).await;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let second_company_id = user.company_id;
        let second_user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, second_user_id)
                .await;
        let session_id = session_response.id;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("/api/v1/tasks/{workspace_id}/assigned"))
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

        task_with_deps_cleanup(
            app.context.clone(),
            &mut transaction,
            chat_id,
            task_id,
            workspace_id,
        )
        .await;

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id, second_company_id],
            &[user_id, second_user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn list_assigned_403_deleted_user() {
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
        let (chat_id, task_id, workspace_id) =
            task_with_deps_create(router.clone(), session_id, user_id, &name, &r#type).await;

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

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        let task = app
            .context
            .octopus_database
            .try_get_task_by_id(task_id)
            .await
            .unwrap()
            .unwrap();

        let _ = app
            .context
            .octopus_database
            .update_task(
                &mut transaction,
                task.id,
                task.assigned_user_chat_id,
                Some(second_user_id),
                task.existing_task_id,
                task.description,
                task.status,
                task.title,
                task.r#type,
                task.use_task_book_generation,
            )
            .await
            .unwrap();

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[],
            &[second_user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("/api/v1/tasks/{workspace_id}/assigned"))
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

        task_with_deps_cleanup(
            app.context.clone(),
            &mut transaction,
            chat_id,
            task_id,
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
    async fn list_assigned_404() {
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

        let workspace_id = "33847746-0030-4964-a496-f75d04499160";

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("/api/v1/tasks/{workspace_id}/assigned"))
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

        let (name, r#type) = api::workspaces::tests::get_workspace_create_params_public();
        let (chat_id, task_id, workspace_id) =
            task_with_deps_create(router.clone(), session_id, user_id, &name, &r#type).await;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("/api/v1/tasks/{workspace_id}/{task_id}"))
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
        let body: Task = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        task_with_deps_cleanup(
            app.context.clone(),
            &mut transaction,
            chat_id,
            task_id,
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
    async fn read_200_company_admin() {
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

        let (email, is_enabled, job_title, name, password, mut roles) =
            api::users::tests::get_user_create_params();
        roles.push(ROLE_SUPERVISOR.to_string());
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

        let (name, r#type) = api::workspaces::tests::get_workspace_create_params_public();
        let (chat_id, workspace_id) = api::chats::tests::chat_with_deps_create(
            router.clone(),
            admin_session_id,
            user_id,
            &name,
            &r#type,
            "Task",
        )
        .await;

        let task = task_create(
            router.clone(),
            session_id,
            second_user_id,
            workspace_id,
            chat_id,
            "NotCompleted",
            false,
        )
        .await;
        let task_id = task.id;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("/api/v1/tasks/{workspace_id}/{task_id}"))
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
        let body: Task = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, second_user_id);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        task_with_deps_cleanup(
            app.context.clone(),
            &mut transaction,
            chat_id,
            task_id,
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
    async fn read_200_private() {
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
        let (chat_id, task_id, workspace_id) =
            task_with_deps_create(router.clone(), session_id, user_id, &name, &r#type).await;

        let (email, is_enabled, job_title, name, password, mut roles) =
            api::users::tests::get_user_create_params();
        roles.push(ROLE_SUPERVISOR.to_string());
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
                    .uri(format!("/api/v1/tasks/{workspace_id}/{task_id}"))
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
        let body: Task = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.user_id, user_id);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        task_with_deps_cleanup(
            app.context.clone(),
            &mut transaction,
            chat_id,
            task_id,
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

        let (name, r#type) = api::workspaces::tests::get_workspace_create_params_public();
        let (chat_id, task_id, workspace_id) =
            task_with_deps_create(router.clone(), session_id, user_id, &name, &r#type).await;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("/api/v1/tasks/{workspace_id}/{task_id}"))
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

        task_with_deps_cleanup(
            app.context.clone(),
            &mut transaction,
            chat_id,
            task_id,
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
    async fn read_403() {
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

        let (email, is_enabled, job_title, name, password, mut roles) =
            api::users::tests::get_user_create_params();
        roles.push(ROLE_SUPERVISOR.to_string());
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

        let (name, r#type) = api::workspaces::tests::get_workspace_create_params_public();
        let (chat_id, workspace_id) = api::chats::tests::chat_with_deps_create(
            router.clone(),
            admin_session_id,
            user_id,
            &name,
            &r#type,
            "Task",
        )
        .await;

        let task = task_create(
            router.clone(),
            session_id,
            second_user_id,
            workspace_id,
            chat_id,
            "NotCompleted",
            false,
        )
        .await;
        let task_id = task.id;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let second_company_id = user.company_id;
        let third_user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, third_user_id)
                .await;
        let session_id = session_response.id;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("/api/v1/tasks/{workspace_id}/{task_id}"))
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

        task_with_deps_cleanup(
            app.context.clone(),
            &mut transaction,
            chat_id,
            task_id,
            workspace_id,
        )
        .await;

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id, second_company_id],
            &[user_id, second_user_id, third_user_id],
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

        let (name, r#type) = api::workspaces::tests::get_workspace_create_params_public();
        let (chat_id, task_id, workspace_id) =
            task_with_deps_create(router.clone(), session_id, user_id, &name, &r#type).await;

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
                    .uri(format!("/api/v1/tasks/{workspace_id}/{task_id}"))
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

        task_with_deps_cleanup(
            app.context.clone(),
            &mut transaction,
            chat_id,
            task_id,
            workspace_id,
        )
        .await;

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

        let (name, r#type) = api::workspaces::tests::get_workspace_create_params_public();
        let (chat_id, workspace_id) = api::chats::tests::chat_with_deps_create(
            router.clone(),
            session_id,
            user_id,
            &name,
            &r#type,
            "Task",
        )
        .await;

        let task_id = "33847746-0030-4964-a496-f75d04499160";

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("/api/v1/tasks/{workspace_id}/{task_id}"))
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

        api::chats::tests::chat_with_deps_cleanup(
            app.context.clone(),
            &mut transaction,
            chat_id,
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

        let (name, r#type) = api::workspaces::tests::get_workspace_create_params_public();
        let (chat_id, task_id, workspace_id) =
            task_with_deps_create(router.clone(), session_id, user_id, &name, &r#type).await;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::PUT)
                    .uri(format!("/api/v1/tasks/{workspace_id}/{task_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "chat_id": &chat_id,
                            "status": "Completed",
                            "use_task_book_generation": false,
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
        let body: Task = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.status, TaskStatus::Completed);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        task_with_deps_cleanup(
            app.context.clone(),
            &mut transaction,
            chat_id,
            task_id,
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
    async fn update_200_company_admin() {
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

        let (email, is_enabled, job_title, name, password, mut roles) =
            api::users::tests::get_user_create_params();
        roles.push(ROLE_SUPERVISOR.to_string());
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

        let (name, r#type) = api::workspaces::tests::get_workspace_create_params_public();
        let (chat_id, workspace_id) = api::chats::tests::chat_with_deps_create(
            router.clone(),
            admin_session_id,
            user_id,
            &name,
            &r#type,
            "Task",
        )
        .await;

        let task = task_create(
            router.clone(),
            session_id,
            second_user_id,
            workspace_id,
            chat_id,
            "NotCompleted",
            false,
        )
        .await;
        let task_id = task.id;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::PUT)
                    .uri(format!("/api/v1/tasks/{workspace_id}/{task_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), admin_session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "chat_id": &chat_id,
                            "status": "Completed",
                            "use_task_book_generation": false,
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
        let body: Task = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.status, TaskStatus::Completed);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        task_with_deps_cleanup(
            app.context.clone(),
            &mut transaction,
            chat_id,
            task_id,
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

        let (name, r#type) = api::workspaces::tests::get_workspace_create_params_public();
        let (chat_id, task_id, workspace_id) =
            task_with_deps_create(router.clone(), session_id, user_id, &name, &r#type).await;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::PUT)
                    .uri(format!("/api/v1/tasks/{workspace_id}/{task_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "chat_id": &chat_id,
                            "status": "Completed",
                            "use_task_book_generation": false,
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

        task_with_deps_cleanup(
            app.context.clone(),
            &mut transaction,
            chat_id,
            task_id,
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

        let (name, r#type) = api::workspaces::tests::get_workspace_create_params_public();
        let (chat_id, task_id, workspace_id) =
            task_with_deps_create(router.clone(), admin_session_id, user_id, &name, &r#type).await;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::PUT)
                    .uri(format!("/api/v1/tasks/{workspace_id}/{task_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "chat_id": &chat_id,
                            "status": "Completed",
                            "use_task_book_generation": false,
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

        task_with_deps_cleanup(
            app.context.clone(),
            &mut transaction,
            chat_id,
            task_id,
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
    async fn update_403_different_company_admin() {
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

        let (email, is_enabled, job_title, name, password, mut roles) =
            api::users::tests::get_user_create_params();
        roles.push(ROLE_SUPERVISOR.to_string());
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

        let (name, r#type) = api::workspaces::tests::get_workspace_create_params_public();
        let (chat_id, workspace_id) = api::chats::tests::chat_with_deps_create(
            router.clone(),
            admin_session_id,
            user_id,
            &name,
            &r#type,
            "Task",
        )
        .await;

        let task = task_create(
            router.clone(),
            session_id,
            second_user_id,
            workspace_id,
            chat_id,
            "NotCompleted",
            false,
        )
        .await;
        let task_id = task.id;

        let (company_name, email, password) = api::setup::tests::get_setup_post_params();
        let user =
            api::setup::tests::setup_post(router.clone(), &company_name, &email, &password).await;
        let second_company_id = user.company_id;
        let third_user_id = user.id;

        let session_response =
            api::auth::login::tests::login_post(router.clone(), &email, &password, third_user_id)
                .await;
        let session_id = session_response.id;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::PUT)
                    .uri(format!("/api/v1/tasks/{workspace_id}/{task_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "chat_id": &chat_id,
                            "status": "Completed",
                            "use_task_book_generation": false,
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

        task_with_deps_cleanup(
            app.context.clone(),
            &mut transaction,
            chat_id,
            task_id,
            workspace_id,
        )
        .await;

        api::setup::tests::setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id, second_company_id],
            &[user_id, second_user_id, third_user_id],
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

        let (name, r#type) = api::workspaces::tests::get_workspace_create_params_public();
        let (chat_id, task_id, workspace_id) =
            task_with_deps_create(router.clone(), session_id, user_id, &name, &r#type).await;

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
                    .method(http::Method::PUT)
                    .uri(format!("/api/v1/tasks/{workspace_id}/{task_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "chat_id": &chat_id,
                            "status": "Completed",
                            "use_task_book_generation": false,
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

        task_with_deps_cleanup(
            app.context.clone(),
            &mut transaction,
            chat_id,
            task_id,
            workspace_id,
        )
        .await;

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

        let (name, r#type) = api::workspaces::tests::get_workspace_create_params_public();
        let (chat_id, workspace_id) = api::chats::tests::chat_with_deps_create(
            router.clone(),
            session_id,
            user_id,
            &name,
            &r#type,
            "Task",
        )
        .await;

        let task_id = "33847746-0030-4964-a496-f75d04499160";

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::PUT)
                    .uri(format!("/api/v1/tasks/{workspace_id}/{task_id}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header("X-Auth-Token".to_string(), session_id.to_string())
                    .body(Body::from(
                        serde_json::json!({
                            "chat_id": &chat_id,
                            "status": "Completed",
                            "use_task_book_generation": false,
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

        api::workspaces::tests::workspace_cleanup(
            app.context.clone(),
            &mut transaction,
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
}
