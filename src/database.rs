use crate::{
    entity::{
        AiFunction, AiFunctionRequestContentType, AiFunctionResponseContentType, AiService,
        AiServiceHealthCheckStatus, AiServiceRequiredPythonVersion, AiServiceSetupStatus,
        AiServiceStatus, Chat, ChatActivity, ChatAudit, ChatMessage, ChatMessageExtended,
        ChatMessageFile, ChatMessagePicture, ChatMessageStatus, ChatPicture, Company,
        EstimatedSeconds, ExamplePrompt, ExamplePromptCategory, InspectionDisabling, Parameter,
        PasswordResetToken, Port, Profile, Session, SimpleApp, User, UserExtended, WaspApp,
        Workspace, WorkspacesType,
    },
    error::AppError,
    Result, PUBLIC_DIR,
};
use chrono::{DateTime, Utc};
use sqlx::{PgPool, Postgres, Transaction};
use std::sync::Arc;
use uuid::Uuid;

#[allow(clippy::module_name_repetitions)]
#[derive(Clone, Debug)]
pub struct OctopusDatabase {
    pool: Arc<PgPool>,
}

impl OctopusDatabase {
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool: Arc::new(pool),
        }
    }

    pub async fn transaction_begin(&self) -> Result<Transaction<Postgres>> {
        let transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| AppError::SqlTransaction)?;

        Ok(transaction)
    }

    pub async fn transaction_commit(&self, transaction: Transaction<'_, Postgres>) -> Result<()> {
        transaction.commit().await?;

        Ok(())
    }

    pub async fn create_database(&self, name: &str) -> Result<()> {
        let query = format!("CREATE DATABASE {name}");
        let _ = sqlx::query(&query).execute(&*self.pool).await;

        Ok(())
    }

    #[allow(dead_code)]
    pub async fn expire_password_reset_token(&self, id: Uuid) -> Result<PasswordResetToken> {
        let password_reset_token = sqlx::query_as!(
            PasswordResetToken,
            "UPDATE password_reset_tokens
            SET expires_at = current_timestamp(0), updated_at = current_timestamp(0)
            WHERE id = $1
            RETURNING id, user_id, email, created_at, deleted_at, expires_at, updated_at",
            id,
        )
        .fetch_one(&*self.pool)
        .await?;

        Ok(password_reset_token)
    }

    pub async fn get_ai_functions_by_ai_service_id(
        &self,
        ai_service_id: Uuid,
    ) -> Result<Vec<AiFunction>> {
        let ai_functions = sqlx::query_as!(
            AiFunction,
            r#"SELECT id, ai_service_id, description, formatted_name, is_enabled, name, parameters, request_content_type AS "request_content_type: _", response_content_type AS "response_content_type: _", created_at, deleted_at, updated_at
            FROM ai_functions
            WHERE ai_service_id = $1
            AND deleted_at IS NULL
            ORDER BY name ASC"#,
            ai_service_id
        )
        .fetch_all(&*self.pool)
        .await?;

        Ok(ai_functions)
    }

    pub async fn get_ai_functions_for_request(&self, user_id: Uuid) -> Result<Vec<AiFunction>> {
        let is_enabled = true;
        let health_check_status = AiServiceHealthCheckStatus::Ok;
        let setup_status = AiServiceSetupStatus::Performed;
        let status = AiServiceStatus::Running;

        let ai_functions = sqlx::query_as::<_, AiFunction>(
            "SELECT aif.id, aif.ai_service_id, aif.description, aif.formatted_name, aif.is_enabled, aif.name, aif.parameters, aif.request_content_type, aif.response_content_type, aif.created_at, aif.deleted_at, aif.updated_at
            FROM ai_functions AS aif
            LEFT JOIN ai_services ais ON ai_service_id = ais.id
            WHERE aif.is_enabled = $1
            AND ais.is_enabled = $1
            AND ais.health_check_status = $2
            AND ais.setup_status = $3
            AND ais.status = $4
            AND aif.deleted_at IS NULL
            AND ais.deleted_at IS NULL
            AND (ais.allowed_user_ids IS NULL OR $5 = ANY(ais.allowed_user_ids))
            ORDER BY name ASC",
        )
        .bind(is_enabled)
        .bind(health_check_status)
        .bind(setup_status)
        .bind(status)
        .bind(user_id)
        .fetch_all(&*self.pool)
        .await?;

        Ok(ai_functions)
    }

    pub async fn get_ai_services(&self) -> Result<Vec<AiService>> {
        let ai_services = sqlx::query_as!(
            AiService,
            r#"SELECT id, allowed_user_ids, device_map, health_check_execution_time, health_check_status AS "health_check_status: _", is_enabled, original_file_name, original_function_body, parser_feedback, port, priority, processed_function_body, progress, required_python_version AS "required_python_version: _", setup_execution_time, setup_status AS "setup_status: _", status AS "status: _", created_at, deleted_at, health_check_at, setup_at, updated_at
            FROM ai_services
            WHERE deleted_at IS NULL
            ORDER BY priority DESC, original_file_name ASC"#
        )
        .fetch_all(&*self.pool)
        .await?;

        Ok(ai_services)
    }

    pub async fn get_ai_services_max_port(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
    ) -> Result<Port> {
        let port = sqlx::query_as::<_, Port>("SELECT MAX(port) FROM ai_services")
            .fetch_one(&mut **transaction)
            .await?;

        Ok(port)
    }

    pub async fn get_chats_by_workspace_id(&self, workspace_id: Uuid) -> Result<Vec<Chat>> {
        let chats = sqlx::query_as!(
            Chat,
            "SELECT id, user_id, workspace_id, name, created_at, deleted_at, updated_at
            FROM chats
            WHERE workspace_id = $1
            AND deleted_at IS NULL
            ORDER BY created_at DESC",
            workspace_id
        )
        .fetch_all(&*self.pool)
        .await?;

        Ok(chats)
    }

    pub async fn get_chat_by_workspace_id_latest(
        &self,
        workspace_id: Uuid,
    ) -> Result<Option<Chat>> {
        let chat = sqlx::query_as!(
            Chat,
            "SELECT id, user_id, workspace_id, name, created_at, deleted_at, updated_at
            FROM chats
            WHERE workspace_id = $1
            AND deleted_at IS NULL
            ORDER BY created_at DESC
            LIMIT 1",
            workspace_id
        )
        .fetch_optional(&*self.pool)
        .await?;

        Ok(chat)
    }

    pub async fn get_chat_activities_latest_by_chat_id_and_session_id(
        &self,
        chat_id: Uuid,
        session_id: Uuid,
    ) -> Result<Vec<ChatActivity>> {
        let chat_activities = sqlx::query_as!(
            ChatActivity,
            "SELECT id, chat_id, session_id, user_id, created_at, updated_at
            FROM chat_activities
            WHERE chat_id = $1
            AND session_id != $2
            ORDER BY updated_at DESC
            LIMIT 5",
            chat_id,
            session_id
        )
        .fetch_all(&*self.pool)
        .await?;

        Ok(chat_activities)
    }

    pub async fn get_chat_audits(&self) -> Result<Vec<ChatAudit>> {
        let chat_audits = sqlx::query_as!(
            ChatAudit,
            "SELECT id, chat_id, chat_message_id, user_id, trail, created_at
            FROM chat_audits
            ORDER BY created_at DESC"
        )
        .fetch_all(&*self.pool)
        .await?;

        Ok(chat_audits)
    }

    pub async fn get_chat_messages_estimated_response_at(&self) -> Result<EstimatedSeconds> {
        let estimated_seconds = sqlx::query_as::<_, EstimatedSeconds>(
            "SELECT CAST(CEILING(EXTRACT(SECONDS FROM AVG(updated_at - created_at))) AS INT8) AS ceiling FROM chat_messages",
        )
        .fetch_one(&*self.pool)
        .await?;

        Ok(estimated_seconds)
    }

    pub async fn get_chat_messages_by_chat_id(&self, chat_id: Uuid) -> Result<Vec<ChatMessage>> {
        let chat_messages = sqlx::query_as!(
            ChatMessage,
            r#"SELECT id, ai_function_id, chat_id, simple_app_id, user_id, wasp_app_id, ai_function_call, ai_function_error, bad_reply_comment, bad_reply_is_harmful, bad_reply_is_not_helpful, bad_reply_is_not_true, bypass_sensitive_information_filter, estimated_response_at, is_anonymized, is_marked_as_not_sensitive, is_not_checked_by_system, is_sensitive, message, progress, response, simple_app_data, status AS "status: _", created_at, deleted_at, updated_at
            FROM chat_messages
            WHERE chat_id = $1
            AND deleted_at IS NULL
            ORDER BY created_at ASC"#,
            chat_id
        )
        .fetch_all(&*self.pool)
        .await?;

        Ok(chat_messages)
    }

    pub async fn get_chat_messages_by_chat_id_latest(
        &self,
        chat_id: Uuid,
    ) -> Result<Option<ChatMessage>> {
        let chat_message = sqlx::query_as!(
            ChatMessage,
            r#"SELECT id, ai_function_id, chat_id, simple_app_id, user_id, wasp_app_id, ai_function_call, ai_function_error, bad_reply_comment, bad_reply_is_harmful, bad_reply_is_not_helpful, bad_reply_is_not_true, bypass_sensitive_information_filter, estimated_response_at, is_anonymized, is_marked_as_not_sensitive, is_not_checked_by_system, is_sensitive, message, progress, response, simple_app_data, status AS "status: _", created_at, deleted_at, updated_at
            FROM chat_messages
            WHERE chat_id = $1
            AND deleted_at IS NULL
            ORDER BY created_at DESC
            LIMIT 1"#,
            chat_id
        )
        .fetch_optional(&*self.pool)
        .await?;

        Ok(chat_message)
    }

    pub async fn get_chat_messages_extended_by_chat_id(
        &self,
        chat_id: Uuid,
    ) -> Result<Vec<ChatMessageExtended>> {
        let chat_messages = self.get_chat_messages_by_chat_id(chat_id).await?;
        let chat_messages_ids = chat_messages.iter().map(|x| x.id).collect::<Vec<Uuid>>();
        let user_ids = chat_messages
            .iter()
            .map(|x| x.user_id)
            .collect::<Vec<Uuid>>();

        let chat_message_files = self
            .get_chat_message_files_by_chat_message_ids(&chat_messages_ids)
            .await?;
        let chat_message_pictures = self
            .get_chat_message_pictures_by_chat_message_ids(&chat_messages_ids)
            .await?;

        let profiles = self.get_profiles_by_user_ids(&user_ids).await?;

        let mut chat_messages_extended = vec![];

        for chat_message in chat_messages {
            let mapped_chat_message_extended = Self::map_to_chat_message_extended(
                &chat_message,
                chat_message_files.clone(),
                chat_message_pictures.clone(),
                profiles.clone(),
            );
            chat_messages_extended.push(mapped_chat_message_extended);
        }

        Ok(chat_messages_extended)
    }

    pub async fn get_chat_messages_extended_by_chat_id_latest(
        &self,
        chat_id: Uuid,
    ) -> Result<Option<ChatMessageExtended>> {
        let chat_message = self.get_chat_messages_by_chat_id_latest(chat_id).await?;

        match chat_message {
            None => Ok(None),
            Some(chat_message) => {
                let chat_message_files = self
                    .get_chat_message_files_by_chat_message_id(chat_message.id)
                    .await?;
                let chat_message_pictures = self
                    .get_chat_message_pictures_by_chat_message_ids(&[chat_message.id])
                    .await?;
                let profiles = self
                    .get_profiles_by_user_ids(&[chat_message.user_id])
                    .await?;

                let chat_message_extended = Self::map_to_chat_message_extended(
                    &chat_message,
                    chat_message_files,
                    chat_message_pictures,
                    profiles,
                );

                Ok(Some(chat_message_extended))
            }
        }
    }

    pub async fn get_chat_messages_by_chat_id_and_status(
        &self,
        chat_id: Uuid,
        status: ChatMessageStatus,
    ) -> Result<Vec<ChatMessage>> {
        let chat_messages = sqlx::query_as::<_, ChatMessage>(
            "SELECT id, ai_function_id, chat_id, simple_app_id, user_id, wasp_app_id, ai_function_call, ai_function_error, bad_reply_comment, bad_reply_is_harmful, bad_reply_is_not_helpful, bad_reply_is_not_true, bypass_sensitive_information_filter, estimated_response_at, is_anonymized, is_marked_as_not_sensitive, is_not_checked_by_system, is_sensitive, message, progress, response, simple_app_data, status, created_at, deleted_at, updated_at
            FROM chat_messages
            WHERE chat_id = $1
            AND status = $2
            AND deleted_at IS NULL
            ORDER BY created_at ASC",
        )
        .bind(chat_id)
        .bind(status)
        .fetch_all(&*self.pool)
        .await?;

        Ok(chat_messages)
    }

    pub async fn get_chat_message_files_by_chat_message_id(
        &self,
        chat_message_id: Uuid,
    ) -> Result<Vec<ChatMessageFile>> {
        let chat_message_files = sqlx::query_as!(
            ChatMessageFile,
            "SELECT id, chat_message_id, file_name, media_type, created_at, deleted_at
            FROM chat_message_files
            WHERE chat_message_id = $1
            AND deleted_at IS NULL
            ORDER BY created_at ASC",
            chat_message_id
        )
        .fetch_all(&*self.pool)
        .await?;

        Ok(chat_message_files)
    }

    pub async fn get_chat_message_files_by_chat_message_ids(
        &self,
        chat_message_ids: &[Uuid],
    ) -> Result<Vec<ChatMessageFile>> {
        let chat_message_files = sqlx::query_as!(
            ChatMessageFile,
            "SELECT id, chat_message_id, file_name, media_type, created_at, deleted_at
            FROM chat_message_files
            WHERE chat_message_id = ANY($1)
            AND deleted_at IS NULL
            ORDER BY created_at ASC",
            chat_message_ids
        )
        .fetch_all(&*self.pool)
        .await?;

        Ok(chat_message_files)
    }

    pub async fn get_chat_message_pictures_by_chat_message_ids(
        &self,
        chat_message_ids: &[Uuid],
    ) -> Result<Vec<ChatMessagePicture>> {
        let chat_message_pictures = sqlx::query_as!(
            ChatMessagePicture,
            "SELECT id, chat_message_id, file_name, created_at, deleted_at, updated_at
            FROM chat_message_pictures
            WHERE chat_message_id = ANY($1)
            AND deleted_at IS NULL
            ORDER BY created_at ASC",
            chat_message_ids
        )
        .fetch_all(&*self.pool)
        .await?;

        Ok(chat_message_pictures)
    }

    pub async fn get_companies(&self) -> Result<Vec<Company>> {
        let companies = sqlx::query_as!(
            Company,
            "SELECT id, address, name, created_at, deleted_at, updated_at
            FROM companies
            WHERE deleted_at IS NULL",
        )
        .fetch_all(&*self.pool)
        .await?;

        Ok(companies)
    }

    pub async fn get_example_prompts(&self) -> Result<Vec<ExamplePrompt>> {
        let is_visible = true;

        let example_prompts = sqlx::query_as!(
            ExamplePrompt,
            "SELECT id, example_prompt_category_id, background_file_name, is_visible, priority, prompt, title, created_at, deleted_at, updated_at
            FROM example_prompts
            WHERE is_visible = $1
            AND deleted_at IS NULL
            ORDER BY priority DESC",
            is_visible
        )
        .fetch_all(&*self.pool)
        .await?;

        Ok(example_prompts)
    }

    pub async fn get_example_prompts_by_example_prompt_category_id(
        &self,
        example_prompt_category_id: Uuid,
    ) -> Result<Vec<ExamplePrompt>> {
        let is_visible = true;

        let example_prompts = sqlx::query_as!(
            ExamplePrompt,
            "SELECT id, example_prompt_category_id, background_file_name, is_visible, priority, prompt, title, created_at, deleted_at, updated_at
            FROM example_prompts
            WHERE is_visible = $1
            AND example_prompt_category_id = $2
            AND deleted_at IS NULL
            ORDER BY priority DESC",
            is_visible,
            example_prompt_category_id
        )
        .fetch_all(&*self.pool)
        .await?;

        Ok(example_prompts)
    }

    pub async fn get_example_prompt_categories(&self) -> Result<Vec<ExamplePromptCategory>> {
        let is_visible = true;

        let example_prompt_categories: Vec<ExamplePromptCategory> = sqlx::query_as!(
            ExamplePromptCategory,
            "SELECT id, description, is_visible, title, created_at, deleted_at, updated_at
            FROM example_prompt_categories
            WHERE is_visible = $1
            AND deleted_at IS NULL
            ORDER BY title ASC",
            is_visible
        )
        .fetch_all(&*self.pool)
        .await?;

        Ok(example_prompt_categories)
    }

    pub async fn get_parameters(&self) -> Result<Vec<Parameter>> {
        let parameters = sqlx::query_as!(
            Parameter,
            "SELECT id, name, value, created_at, deleted_at, updated_at
            FROM parameters
            WHERE deleted_at IS NULL
            ORDER BY name ASC"
        )
        .fetch_all(&*self.pool)
        .await?;

        Ok(parameters)
    }

    pub async fn get_profiles_by_user_ids(&self, user_ids: &[Uuid]) -> Result<Vec<Profile>> {
        let profiles = sqlx::query_as!(
            Profile,
            "SELECT id, user_id, job_title, language, name, photo_file_name, text_size, created_at, deleted_at, updated_at
            FROM profiles
            WHERE user_id = ANY($1)
            AND deleted_at IS NULL",
            user_ids
        )
        .fetch_all(&*self.pool)
        .await?;

        Ok(profiles)
    }

    pub async fn get_simple_apps(&self) -> Result<Vec<SimpleApp>> {
        let simple_apps = sqlx::query_as!(
            SimpleApp,
            "SELECT id, code, description, formatted_name, is_enabled, name, created_at, deleted_at, updated_at
            FROM simple_apps
            WHERE deleted_at IS NULL"
        )
        .fetch_all(&*self.pool)
        .await?;

        Ok(simple_apps)
    }

    pub async fn get_simple_apps_for_request(&self) -> Result<Vec<SimpleApp>> {
        let is_enabled = true;
        let simple_apps = sqlx::query_as!(
            SimpleApp,
            "SELECT id, code, description, formatted_name, is_enabled, name, created_at, deleted_at, updated_at
            FROM simple_apps
            WHERE is_enabled = $1
            AND deleted_at IS NULL",
            is_enabled
        )
        .fetch_all(&*self.pool)
        .await?;

        Ok(simple_apps)
    }

    pub async fn get_users_by_company_id(&self, company_id: Uuid) -> Result<Vec<User>> {
        let users = sqlx::query_as!(
            User,
            "SELECT id, company_id, email, is_enabled, is_invited, roles, created_at, deleted_at, updated_at
            FROM users
            WHERE company_id = $1
            AND deleted_at IS NULL",
            company_id
        )
        .fetch_all(&*self.pool)
        .await?;

        Ok(users)
    }

    pub async fn get_users_extended_by_company_id(
        &self,
        company_id: Uuid,
    ) -> Result<Vec<UserExtended>> {
        let users = self.get_users_by_company_id(company_id).await?;

        let user_ids = users.iter().map(|x| x.id).collect::<Vec<Uuid>>();

        let profiles = self.get_profiles_by_user_ids(&user_ids).await?;

        let mut users_extended = vec![];

        for user in users {
            let profile = profiles
                .clone()
                .into_iter()
                .filter(|x| x.id == user.id)
                .collect::<Vec<Profile>>()
                .first()
                .cloned();
            let mapped_user_extended = self.map_to_user_extended(&user, profile).await?;
            users_extended.push(mapped_user_extended);
        }

        Ok(users_extended)
    }

    pub async fn get_wasp_apps(&self) -> Result<Vec<WaspApp>> {
        let wasp_apps = sqlx::query_as!(
            WaspApp,
            "SELECT id, allowed_user_ids, code, description, formatted_name, is_enabled, name, created_at, deleted_at, updated_at
            FROM wasp_apps
            WHERE deleted_at IS NULL"
        )
        .fetch_all(&*self.pool)
        .await?;

        Ok(wasp_apps)
    }

    pub async fn get_wasp_apps_for_request(&self, user_id: Uuid) -> Result<Vec<WaspApp>> {
        let is_enabled = true;
        let wasp_apps = sqlx::query_as!(
            WaspApp,
            "SELECT id, allowed_user_ids, code, description, formatted_name, is_enabled, name, created_at, deleted_at, updated_at
            FROM wasp_apps
            WHERE is_enabled = $1
            AND deleted_at IS NULL
            AND (allowed_user_ids IS NULL OR $2 = ANY(allowed_user_ids))",
            is_enabled,
            user_id
        )
        .fetch_all(&*self.pool)
        .await?;

        Ok(wasp_apps)
    }

    pub async fn get_workspaces_by_company_id_and_type(
        &self,
        company_id: Uuid,
        r#type: WorkspacesType,
    ) -> Result<Vec<Workspace>> {
        let workspaces = sqlx::query_as::<_, Workspace>(
            "SELECT id, company_id, user_id, name, type, created_at, deleted_at, updated_at
            FROM workspaces
            WHERE company_id = $1
            AND type = $2
            AND deleted_at IS NULL",
        )
        .bind(company_id)
        .bind(r#type)
        .fetch_all(&*self.pool)
        .await?;

        Ok(workspaces)
    }

    pub async fn get_workspaces_by_user_id_and_type(
        &self,
        user_id: Uuid,
        r#type: WorkspacesType,
    ) -> Result<Vec<Workspace>> {
        let workspaces = sqlx::query_as::<_, Workspace>(
            "SELECT id, company_id, user_id, name, type, created_at, deleted_at, updated_at
            FROM workspaces
            WHERE user_id = $1
            AND type = $2
            AND deleted_at IS NULL",
        )
        .bind(user_id)
        .bind(r#type)
        .fetch_all(&*self.pool)
        .await?;

        Ok(workspaces)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn insert_ai_function(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        ai_service_id: Uuid,
        description: &str,
        formatted_name: &str,
        name: &str,
        parameters: serde_json::Value,
        request_content_type: AiFunctionRequestContentType,
        response_content_type: AiFunctionResponseContentType,
    ) -> Result<AiFunction> {
        let ai_function = sqlx::query_as::<_, AiFunction>(
            "INSERT INTO ai_functions
            (ai_service_id, description, formatted_name, name, parameters, request_content_type, response_content_type)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING id, ai_service_id, description, formatted_name, is_enabled, name, parameters, request_content_type, response_content_type, created_at, deleted_at, updated_at",
        )
        .bind(ai_service_id)
        .bind(description)
        .bind(formatted_name)
        .bind(name)
        .bind(parameters)
        .bind(request_content_type)
        .bind(response_content_type)
        .fetch_one(&mut **transaction)
        .await?;

        Ok(ai_function)
    }

    pub async fn insert_ai_service(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        original_file_name: &str,
        original_function_body: &str,
        port: i32,
    ) -> Result<AiService> {
        let ai_service = sqlx::query_as!(
            AiService,
            r#"INSERT INTO ai_services
            (original_file_name, original_function_body, port)
            VALUES ($1, $2, $3)
            RETURNING id, allowed_user_ids, device_map, health_check_execution_time, health_check_status AS "health_check_status: _", is_enabled, original_file_name, original_function_body, parser_feedback, port, priority, processed_function_body, progress, required_python_version AS "required_python_version: _", setup_execution_time, setup_status AS "setup_status: _", status AS "status: _", created_at, deleted_at, health_check_at, setup_at, updated_at"#,
            original_file_name,
            original_function_body,
            port,
        )
        .fetch_one(&mut **transaction)
        .await?;

        Ok(ai_service)
    }

    pub async fn insert_chat(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        user_id: Uuid,
        workspace_id: Uuid,
    ) -> Result<Chat> {
        let chat = sqlx::query_as!(
            Chat,
            "INSERT INTO chats
            (user_id, workspace_id)
            VALUES ($1, $2)
            RETURNING id, user_id, workspace_id, name, created_at, deleted_at, updated_at",
            user_id,
            workspace_id
        )
        .fetch_one(&mut **transaction)
        .await?;

        Ok(chat)
    }

    pub async fn insert_chat_activity(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        chat_id: Uuid,
        session_id: Uuid,
        user_id: Uuid,
    ) -> Result<ChatActivity> {
        let chat_activity = sqlx::query_as!(
            ChatActivity,
            "INSERT INTO chat_activities
            (chat_id, session_id, user_id)
            VALUES ($1, $2, $3)
            ON CONFLICT (chat_id, session_id, user_id)
            DO UPDATE SET updated_at = current_timestamp(0)
            RETURNING id, chat_id, session_id, user_id, created_at, updated_at",
            chat_id,
            session_id,
            user_id,
        )
        .fetch_one(&mut **transaction)
        .await?;

        Ok(chat_activity)
    }

    pub async fn insert_chat_audit(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        chat_id: Uuid,
        chat_message_id: Uuid,
        user_id: Uuid,
        trail: serde_json::Value,
    ) -> Result<ChatAudit> {
        let chat_audit = sqlx::query_as!(
            ChatAudit,
            "INSERT INTO chat_audits
            (chat_id, chat_message_id, user_id, trail)
            VALUES ($1, $2, $3, $4)
            RETURNING id, chat_id, chat_message_id, user_id, trail, created_at",
            chat_id,
            chat_message_id,
            user_id,
            trail
        )
        .fetch_one(&mut **transaction)
        .await?;

        Ok(chat_audit)
    }

    pub async fn insert_chat_message(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        chat_id: Uuid,
        user_id: Uuid,
        bypass_sensitive_information_filter: bool,
        estimated_response_at: DateTime<Utc>,
        message: &str,
    ) -> Result<ChatMessage> {
        let chat_message = sqlx::query_as!(
            ChatMessage,
            r#"INSERT INTO chat_messages
            (chat_id, user_id, bypass_sensitive_information_filter, estimated_response_at, message)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id, ai_function_id, chat_id, simple_app_id, user_id, wasp_app_id, ai_function_call, ai_function_error, bad_reply_comment, bad_reply_is_harmful, bad_reply_is_not_helpful, bad_reply_is_not_true, bypass_sensitive_information_filter, estimated_response_at, is_anonymized, is_marked_as_not_sensitive, is_not_checked_by_system, is_sensitive, message, progress, response, simple_app_data, status AS "status: _", created_at, deleted_at, updated_at"#,
            chat_id,
            user_id,
            bypass_sensitive_information_filter,
            estimated_response_at,
            message,
        )
        .fetch_one(&mut **transaction)
        .await?;

        Ok(chat_message)
    }

    #[allow(dead_code)]
    pub async fn insert_chat_message_file(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        chat_message_id: Uuid,
        file_name: &str,
        media_type: &str,
    ) -> Result<ChatMessageFile> {
        let chat_message_file = sqlx::query_as!(
            ChatMessageFile,
            "INSERT INTO chat_message_files
            (chat_message_id, file_name, media_type)
            VALUES ($1, $2, $3)
            RETURNING id, chat_message_id, file_name, media_type, created_at, deleted_at",
            chat_message_id,
            file_name,
            media_type,
        )
        .fetch_one(&mut **transaction)
        .await?;

        Ok(chat_message_file)
    }

    pub async fn insert_chat_message_picture(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        chat_message_id: Uuid,
        file_name: &str,
    ) -> Result<ChatMessagePicture> {
        let chat_message_picture = sqlx::query_as!(
            ChatMessagePicture,
            "INSERT INTO chat_message_pictures
            (chat_message_id, file_name)
            VALUES ($1, $2)
            RETURNING id, chat_message_id, file_name, created_at, deleted_at, updated_at",
            chat_message_id,
            file_name,
        )
        .fetch_one(&mut **transaction)
        .await?;

        Ok(chat_message_picture)
    }

    pub async fn insert_chat_picture(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        chat_id: Uuid,
        file_name: &str,
    ) -> Result<ChatPicture> {
        let chat_picture = sqlx::query_as!(
            ChatPicture,
            "INSERT INTO chat_pictures
            (chat_id, file_name)
            VALUES ($1, $2)
            RETURNING id, chat_id, file_name, created_at, deleted_at, updated_at",
            chat_id,
            file_name
        )
        .fetch_one(&mut **transaction)
        .await?;

        Ok(chat_picture)
    }

    pub async fn insert_company(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        address: Option<String>,
        name: &str,
    ) -> Result<Company> {
        let company = sqlx::query_as!(
            Company,
            "INSERT INTO companies
            (address, name)
            VALUES ($1, $2)
            RETURNING id, address, name, created_at, deleted_at, updated_at",
            address,
            name
        )
        .fetch_one(&mut **transaction)
        .await?;

        Ok(company)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn insert_example_prompt(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        example_prompt_category_id: Uuid,
        background_file_name: Option<String>,
        is_visible: bool,
        priority: i32,
        prompt: &str,
        title: &str,
    ) -> Result<ExamplePrompt> {
        let example_prompt = sqlx::query_as!(
            ExamplePrompt,
            "INSERT INTO example_prompts
            (example_prompt_category_id, background_file_name, is_visible, priority, prompt, title)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id, example_prompt_category_id, background_file_name, is_visible, priority, prompt, title, created_at, deleted_at, updated_at",
            example_prompt_category_id,
            background_file_name,
            is_visible,
            priority,
            prompt,
            title
        )
        .fetch_one(&mut **transaction)
        .await?;

        Ok(example_prompt)
    }

    pub async fn insert_example_prompt_category(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        description: &str,
        is_visible: bool,
        title: &str,
    ) -> Result<ExamplePromptCategory> {
        let example_prompt_category = sqlx::query_as!(
            ExamplePromptCategory,
            "INSERT INTO example_prompt_categories
            (description, is_visible, title)
            VALUES ($1, $2, $3)
            RETURNING id, description, is_visible, title, created_at, deleted_at, updated_at",
            description,
            is_visible,
            title
        )
        .fetch_one(&mut **transaction)
        .await?;

        Ok(example_prompt_category)
    }

    pub async fn insert_inspection_disabling(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        user_id: Uuid,
        content_safety_disabled_until: DateTime<Utc>,
    ) -> Result<InspectionDisabling> {
        let inspection_disabling = sqlx::query_as!(
            InspectionDisabling,
            "INSERT INTO inspection_disablings
            (user_id, content_safety_disabled_until)
            VALUES ($1, $2)
            RETURNING id, user_id, content_safety_disabled_until, created_at, updated_at",
            user_id,
            content_safety_disabled_until
        )
        .fetch_one(&mut **transaction)
        .await?;

        Ok(inspection_disabling)
    }

    pub async fn insert_parameter(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        name: &str,
        value: &str,
    ) -> Result<Parameter> {
        let parameter = sqlx::query_as!(
            Parameter,
            "INSERT INTO parameters
            (name, value)
            VALUES ($1, $2)
            RETURNING id, name, value, created_at, deleted_at, updated_at",
            name,
            value
        )
        .fetch_one(&mut **transaction)
        .await?;

        Ok(parameter)
    }

    pub async fn insert_password_reset_token(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        user_id: Uuid,
        email: &str,
        token: &str,
    ) -> Result<PasswordResetToken> {
        let password_reset_token = sqlx::query_as!(
            PasswordResetToken,
            "INSERT INTO password_reset_tokens
            (user_id, email, token)
            VALUES ($1, $2, $3)
            RETURNING id, user_id, email, created_at, deleted_at, expires_at, updated_at",
            user_id,
            email,
            token
        )
        .fetch_one(&mut **transaction)
        .await?;

        Ok(password_reset_token)
    }

    pub async fn insert_profile(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        user_id: Uuid,
        job_title: Option<String>,
        name: Option<String>,
    ) -> Result<Profile> {
        let profile = sqlx::query_as!(
            Profile,
            "INSERT INTO profiles
            (user_id, job_title, name)
            VALUES ($1, $2, $3)
            RETURNING id, user_id, job_title, language, name, photo_file_name, text_size, created_at, deleted_at, updated_at",
            user_id,
            job_title,
            name
        )
        .fetch_one(&mut **transaction)
        .await?;

        Ok(profile)
    }

    pub async fn insert_session(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        user_id: Uuid,
        data: &str,
        expired_at: DateTime<Utc>,
    ) -> Result<Session> {
        let session = sqlx::query_as!(
            Session,
            "INSERT INTO sessions
            (user_id, data, expired_at)
            VALUES ($1, $2, $3)
            RETURNING id, user_id, data, expired_at",
            user_id,
            data,
            expired_at
        )
        .fetch_one(&mut **transaction)
        .await?;

        Ok(session)
    }

    pub async fn insert_simple_app(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        code: &str,
        description: &str,
        formatted_name: &str,
        is_enabled: bool,
        name: &str,
    ) -> Result<SimpleApp> {
        let simple_app = sqlx::query_as!(
            SimpleApp,
            "INSERT INTO simple_apps
            (code, description, formatted_name, is_enabled, name)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id, code, description, formatted_name, is_enabled, name, created_at, deleted_at, updated_at",
            code,
            description,
            formatted_name,
            is_enabled,
            name,
        )
        .fetch_one(&mut **transaction)
        .await?;

        Ok(simple_app)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn insert_user(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        company_id: Uuid,
        email: &str,
        is_enabled: bool,
        is_invited: bool,
        pepper_id: i32,
        password: &str,
        roles: &[String],
    ) -> Result<User> {
        let user = sqlx::query_as!(
            User,
            "INSERT INTO users
            (company_id, email, is_enabled, is_invited, pepper_id, password, roles)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (email) DO NOTHING
            RETURNING id, company_id, email, is_enabled, is_invited, roles, created_at, deleted_at, updated_at",
            company_id,
            email,
            is_enabled,
            is_invited,
            pepper_id,
            password,
            roles
        )
        .fetch_one(&mut **transaction)
        .await?;

        Ok(user)
    }

    pub async fn insert_wasp_app(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        code: &[u8],
        description: &str,
        formatted_name: &str,
        is_enabled: bool,
        name: &str,
    ) -> Result<WaspApp> {
        let wasp_app = sqlx::query_as!(
            WaspApp,
            "INSERT INTO wasp_apps
            (code, description, formatted_name, is_enabled, name)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id, allowed_user_ids, code, description, formatted_name, is_enabled, name, created_at, deleted_at, updated_at",
            code,
            description,
            formatted_name,
            is_enabled,
            name,
        )
        .fetch_one(&mut **transaction)
        .await?;

        Ok(wasp_app)
    }

    pub async fn insert_workspace(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        company_id: Uuid,
        user_id: Uuid,
        name: &str,
        r#type: WorkspacesType,
    ) -> Result<Workspace> {
        let workspace = sqlx::query_as::<_, Workspace>(
            "INSERT INTO workspaces
            (company_id, user_id, name, type)
            VALUES ($1, $2, $3, $4)
            RETURNING id, company_id, user_id, name, type, created_at, deleted_at, updated_at",
        )
        .bind(company_id)
        .bind(user_id)
        .bind(name)
        .bind(r#type)
        .fetch_one(&mut **transaction)
        .await?;

        Ok(workspace)
    }

    pub fn map_to_chat_message_extended(
        chat_message: &ChatMessage,
        chat_message_files: Vec<ChatMessageFile>,
        chat_message_pictures: Vec<ChatMessagePicture>,
        profiles: Vec<Profile>,
    ) -> ChatMessageExtended {
        let mut selected_chat_message_files = vec![];
        let mut selected_chat_message_pictures = vec![];
        let mut profile = None;
        for mut chat_message_file in chat_message_files {
            if chat_message_file.chat_message_id == chat_message.id {
                if !chat_message_file.file_name.contains(PUBLIC_DIR) {
                    chat_message_file.file_name =
                        format!("{PUBLIC_DIR}/{}", chat_message_file.file_name);
                }
                selected_chat_message_files.push(chat_message_file);
            }
        }
        for mut chat_message_picture in chat_message_pictures {
            if chat_message_picture.chat_message_id == chat_message.id {
                if !chat_message_picture.file_name.contains(PUBLIC_DIR) {
                    chat_message_picture.file_name =
                        format!("{PUBLIC_DIR}/{}", chat_message_picture.file_name);
                }
                selected_chat_message_pictures.push(chat_message_picture);
            }
        }

        for profile_tmp in profiles {
            if profile_tmp.user_id == chat_message.user_id {
                profile = Some(profile_tmp);
            }
        }

        ChatMessageExtended {
            id: chat_message.id,
            ai_function_id: chat_message.ai_function_id,
            chat_id: chat_message.chat_id,
            simple_app_id: chat_message.simple_app_id,
            user_id: chat_message.user_id,
            wasp_app_id: chat_message.wasp_app_id,
            ai_function_call: chat_message.ai_function_call.clone(),
            ai_function_error: chat_message.ai_function_error.clone(),
            bad_reply_comment: chat_message.bad_reply_comment.clone(),
            bad_reply_is_harmful: chat_message.bad_reply_is_harmful,
            bad_reply_is_not_helpful: chat_message.bad_reply_is_not_helpful,
            bad_reply_is_not_true: chat_message.bad_reply_is_not_true,
            bypass_sensitive_information_filter: chat_message.bypass_sensitive_information_filter,
            chat_message_files: selected_chat_message_files,
            chat_message_pictures: selected_chat_message_pictures,
            estimated_response_at: chat_message.estimated_response_at,
            is_anonymized: chat_message.is_anonymized,
            is_marked_as_not_sensitive: chat_message.is_marked_as_not_sensitive,
            is_not_checked_by_system: chat_message.is_not_checked_by_system,
            is_sensitive: chat_message.is_sensitive,
            message: chat_message.message.clone(),
            profile,
            progress: chat_message.progress,
            response: chat_message.response.clone(),
            simple_app_data: chat_message.simple_app_data.clone(),
            status: chat_message.status.clone(),
            created_at: chat_message.created_at,
            deleted_at: chat_message.deleted_at,
            updated_at: chat_message.updated_at,
        }
    }

    pub async fn map_to_user_extended(
        &self,
        user: &User,
        profile: Option<Profile>,
    ) -> Result<UserExtended> {
        let profile = match profile {
            None => self.try_get_profile_by_user_id(user.id).await?,
            Some(profile) => Some(profile),
        };

        let user_extended = UserExtended {
            id: user.id,
            company_id: user.company_id,
            email: user.email.clone(),
            is_enabled: user.is_enabled,
            is_invited: user.is_invited,
            profile,
            roles: user.roles.clone(),
            created_at: user.created_at,
            deleted_at: user.deleted_at,
            updated_at: user.updated_at,
        };

        Ok(user_extended)
    }

    pub async fn try_delete_ai_function_by_id(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        id: Uuid,
    ) -> Result<Option<Uuid>> {
        let ai_function = sqlx::query_scalar::<_, Uuid>(
            "UPDATE ai_functions
                SET deleted_at = current_timestamp(0)
                WHERE id = $1
                AND deleted_at IS NULL
                RETURNING id",
        )
        .bind(id)
        .fetch_optional(&mut **transaction)
        .await?;

        Ok(ai_function)
    }

    pub async fn try_delete_ai_service_by_id(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        id: Uuid,
    ) -> Result<Option<Uuid>> {
        let ai_service = sqlx::query_scalar::<_, Uuid>(
            "UPDATE ai_services
                SET deleted_at = current_timestamp(0)
                WHERE id = $1
                AND deleted_at IS NULL
                RETURNING id",
        )
        .bind(id)
        .fetch_optional(&mut **transaction)
        .await?;

        Ok(ai_service)
    }

    pub async fn try_delete_chat_by_id(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        id: Uuid,
    ) -> Result<Option<Uuid>> {
        let chat = sqlx::query_scalar::<_, Uuid>(
            "UPDATE chats
            SET deleted_at = current_timestamp(0)
            WHERE id = $1
            AND deleted_at IS NULL
            RETURNING id",
        )
        .bind(id)
        .fetch_optional(&mut **transaction)
        .await?;

        Ok(chat)
    }

    pub async fn try_delete_chat_message_by_id(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        id: Uuid,
    ) -> Result<Option<Uuid>> {
        let chat_message = sqlx::query_scalar::<_, Uuid>(
            "UPDATE chat_messages
                SET deleted_at = current_timestamp(0)
                WHERE id = $1
                AND deleted_at IS NULL
                RETURNING id",
        )
        .bind(id)
        .fetch_optional(&mut **transaction)
        .await?;

        Ok(chat_message)
    }

    pub async fn try_delete_chat_messages_by_ids(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        ids: &[Uuid],
    ) -> Result<Vec<Uuid>> {
        let chat_message_ids = sqlx::query_scalar::<_, Uuid>(
            "UPDATE chat_messages
            SET deleted_at = current_timestamp(0)
            WHERE id = ANY($1)
            AND deleted_at IS NULL
            RETURNING id",
        )
        .bind(ids)
        .fetch_all(&mut **transaction)
        .await?;

        Ok(chat_message_ids)
    }

    pub async fn try_delete_chat_message_file_by_id(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        id: Uuid,
    ) -> Result<Option<Uuid>> {
        let chat_message_file = sqlx::query_scalar::<_, Uuid>(
            "UPDATE chat_message_files
            SET deleted_at = current_timestamp(0)
            WHERE id = $1
            AND deleted_at IS NULL
            RETURNING id",
        )
        .bind(id)
        .fetch_optional(&mut **transaction)
        .await?;

        Ok(chat_message_file)
    }

    pub async fn try_delete_chat_message_picture_by_id(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        id: Uuid,
    ) -> Result<Option<Uuid>> {
        let chat_message_picture = sqlx::query_scalar::<_, Uuid>(
            "UPDATE chat_message_pictures
            SET deleted_at = current_timestamp(0)
            WHERE id = $1
            AND deleted_at IS NULL
            RETURNING id",
        )
        .bind(id)
        .fetch_optional(&mut **transaction)
        .await?;

        Ok(chat_message_picture)
    }

    pub async fn try_delete_chat_picture_by_id(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        id: Uuid,
    ) -> Result<Option<Uuid>> {
        let chat_picture = sqlx::query_scalar::<_, Uuid>(
            "UPDATE chat_pictures
                SET deleted_at = current_timestamp(0)
                WHERE id = $1
                AND deleted_at IS NULL
                RETURNING id",
        )
        .bind(id)
        .fetch_optional(&mut **transaction)
        .await?;

        Ok(chat_picture)
    }

    #[allow(dead_code)]
    pub async fn try_delete_company_by_ids(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        ids: &[Uuid],
    ) -> Result<Vec<Uuid>> {
        let companies = sqlx::query_scalar::<_, Uuid>(
            "UPDATE companies
                SET deleted_at = current_timestamp(0)
                WHERE id = ANY($1)
                AND deleted_at IS NULL
                RETURNING id",
        )
        .bind(ids)
        .fetch_all(&mut **transaction)
        .await?;

        Ok(companies)
    }

    pub async fn try_delete_example_prompt_by_id(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        id: Uuid,
    ) -> Result<Option<Uuid>> {
        let example_prompt = sqlx::query_scalar::<_, Uuid>(
            "UPDATE example_prompts
                SET deleted_at = current_timestamp(0)
                WHERE id = $1
                AND deleted_at IS NULL
                RETURNING id",
        )
        .bind(id)
        .fetch_optional(&mut **transaction)
        .await?;

        Ok(example_prompt)
    }

    pub async fn try_delete_example_prompt_category_by_id(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        id: Uuid,
    ) -> Result<Option<Uuid>> {
        let example_prompt_category = sqlx::query_scalar::<_, Uuid>(
            "UPDATE example_prompt_categories
                SET deleted_at = current_timestamp(0)
                WHERE id = $1
                AND deleted_at IS NULL
                RETURNING id",
        )
        .bind(id)
        .fetch_optional(&mut **transaction)
        .await?;

        Ok(example_prompt_category)
    }

    pub async fn try_delete_inspection_disabling_by_user_id(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        user_id: Uuid,
    ) -> Result<Option<Uuid>> {
        let inspection_disabling = sqlx::query_scalar::<_, Uuid>(
            "DELETE FROM inspection_disablings
                WHERE user_id = $1
                RETURNING id",
        )
        .bind(user_id)
        .fetch_optional(&mut **transaction)
        .await?;

        Ok(inspection_disabling)
    }

    pub async fn try_delete_parameter_by_id(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        id: Uuid,
    ) -> Result<Option<Uuid>> {
        let parameter = sqlx::query_scalar::<_, Uuid>(
            "UPDATE parameters
                SET deleted_at = current_timestamp(0)
                WHERE id = $1
                AND deleted_at IS NULL
                RETURNING id",
        )
        .bind(id)
        .fetch_optional(&mut **transaction)
        .await?;

        Ok(parameter)
    }

    pub async fn try_delete_password_reset_token_by_id(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        id: Uuid,
    ) -> Result<Option<Uuid>> {
        let password_reset_token = sqlx::query_scalar::<_, Uuid>(
            "UPDATE password_reset_tokens
                SET deleted_at = current_timestamp(0)
                WHERE id = $1
                AND deleted_at IS NULL
                RETURNING id",
        )
        .bind(id)
        .fetch_optional(&mut **transaction)
        .await?;

        Ok(password_reset_token)
    }

    pub async fn try_delete_session_by_id(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        id: Uuid,
    ) -> Result<Option<Uuid>> {
        let session = sqlx::query_scalar::<_, Uuid>(
            "DELETE FROM sessions
                WHERE id = $1
                RETURNING id",
        )
        .bind(id)
        .fetch_optional(&mut **transaction)
        .await?;

        Ok(session)
    }

    pub async fn try_delete_simple_app_by_id(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        id: Uuid,
    ) -> Result<Option<Uuid>> {
        let simple_app = sqlx::query_scalar::<_, Uuid>(
            "UPDATE simple_apps
            SET deleted_at = current_timestamp(0)
            WHERE id = $1
            AND deleted_at IS NULL
            RETURNING id",
        )
        .bind(id)
        .fetch_optional(&mut **transaction)
        .await?;

        Ok(simple_app)
    }

    pub async fn try_delete_user_by_id(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        id: Uuid,
    ) -> Result<Option<Uuid>> {
        let user = sqlx::query_scalar::<_, Uuid>(
            "UPDATE users
            SET deleted_at = current_timestamp(0)
            WHERE id = $1
            AND deleted_at IS NULL
            RETURNING id",
        )
        .bind(id)
        .fetch_optional(&mut **transaction)
        .await?;

        Ok(user)
    }

    #[allow(dead_code)]
    pub async fn try_delete_user_by_ids(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        ids: &[Uuid],
    ) -> Result<Vec<Uuid>> {
        let users = sqlx::query_scalar::<_, Uuid>(
            "UPDATE users
            SET deleted_at = current_timestamp(0)
            WHERE id = ANY($1)
            AND deleted_at IS NULL
            RETURNING id",
        )
        .bind(ids)
        .fetch_all(&mut **transaction)
        .await?;

        Ok(users)
    }

    pub async fn try_delete_wasp_app_by_id(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        id: Uuid,
    ) -> Result<Option<Uuid>> {
        let wasp_app = sqlx::query_scalar::<_, Uuid>(
            "UPDATE wasp_apps
            SET deleted_at = current_timestamp(0)
            WHERE id = $1
            AND deleted_at IS NULL
            RETURNING id",
        )
        .bind(id)
        .fetch_optional(&mut **transaction)
        .await?;

        Ok(wasp_app)
    }

    pub async fn try_delete_workspace_by_id(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        id: Uuid,
    ) -> Result<Option<Uuid>> {
        let workspace = sqlx::query_scalar::<_, Uuid>(
            "UPDATE workspaces
                SET deleted_at = current_timestamp(0)
                WHERE id = $1
                AND deleted_at IS NULL
                RETURNING id",
        )
        .bind(id)
        .fetch_optional(&mut **transaction)
        .await?;

        Ok(workspace)
    }

    pub async fn try_get_ai_function_for_direct_call(
        &self,
        formatted_name: &str,
    ) -> Result<Option<AiFunction>> {
        let is_enabled = true;
        let health_check_status = AiServiceHealthCheckStatus::Ok;
        let setup_status = AiServiceSetupStatus::Performed;
        let status = AiServiceStatus::Running;

        let ai_function = sqlx::query_as::<_, AiFunction>(
            "SELECT aif.id, aif.ai_service_id, aif.description, aif.formatted_name, aif.is_enabled, aif.name, aif.parameters, aif.request_content_type, aif.response_content_type, aif.created_at, aif.deleted_at, aif.updated_at
            FROM ai_functions AS aif
            LEFT JOIN ai_services ais ON ai_service_id = ais.id
            WHERE aif.formatted_name = $1
            AND aif.is_enabled = $2
            AND ais.is_enabled = $2
            AND ais.health_check_status = $3
            AND ais.setup_status = $4
            AND ais.status = $5
            AND aif.deleted_at IS NULL
            AND ais.deleted_at IS NULL
            ORDER BY aif.created_at DESC",
        )
        .bind(formatted_name)
        .bind(is_enabled)
        .bind(health_check_status)
        .bind(setup_status)
        .bind(status)
        .fetch_optional(&*self.pool)
        .await?;

        Ok(ai_function)
    }

    pub async fn try_get_ai_function_by_id(&self, id: Uuid) -> Result<Option<AiFunction>> {
        let ai_function = sqlx::query_as!(
            AiFunction,
            r#"SELECT id, ai_service_id, description, formatted_name, is_enabled, name, parameters, request_content_type AS "request_content_type: _", response_content_type AS "response_content_type: _", created_at, deleted_at, updated_at
            FROM ai_functions
            WHERE id = $1
            AND deleted_at IS NULL"#,
            id
        )
        .fetch_optional(&*self.pool)
        .await?;

        Ok(ai_function)
    }

    pub async fn try_get_ai_function_by_name(&self, name: &str) -> Result<Option<AiFunction>> {
        let ai_function = sqlx::query_as!(
            AiFunction,
            r#"SELECT id, ai_service_id, description, formatted_name, is_enabled, name, parameters, request_content_type AS "request_content_type: _", response_content_type AS "response_content_type: _", created_at, deleted_at, updated_at
            FROM ai_functions
            WHERE name = $1
            AND deleted_at IS NULL"#,
            name
        )
        .fetch_optional(&*self.pool)
        .await?;

        Ok(ai_function)
    }

    pub async fn try_get_ai_service_by_id(&self, id: Uuid) -> Result<Option<AiService>> {
        let ai_service = sqlx::query_as!(
            AiService,
            r#"SELECT id, allowed_user_ids, device_map, health_check_execution_time, health_check_status AS "health_check_status: _", is_enabled, original_file_name, original_function_body, parser_feedback, port, priority, processed_function_body, progress, required_python_version AS "required_python_version: _", setup_execution_time, setup_status AS "setup_status: _", status AS "status: _", created_at, deleted_at, health_check_at, setup_at, updated_at
            FROM ai_services
            WHERE id = $1
            AND deleted_at IS NULL"#,
            id
        )
        .fetch_optional(&*self.pool)
        .await?;

        Ok(ai_service)
    }

    pub async fn try_get_ai_service_id_by_id(&self, id: Uuid) -> Result<Option<Uuid>> {
        let ai_service_id = sqlx::query_scalar::<_, Uuid>(
            "SELECT id
            FROM ai_services
            WHERE id = $1
            AND deleted_at IS NULL",
        )
        .bind(id)
        .fetch_optional(&*self.pool)
        .await?;

        Ok(ai_service_id)
    }

    pub async fn try_get_hash_for_user_id(&self, id: Uuid) -> Result<Option<String>> {
        let hash = sqlx::query_scalar::<_, String>(
            "SELECT password
            FROM users
            WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&*self.pool)
        .await?;

        Ok(hash)
    }

    pub async fn try_get_hash_for_email(&self, email: &str) -> Result<Option<String>> {
        let hash = sqlx::query_scalar::<_, String>(
            "SELECT password
            FROM users
            WHERE email = $1",
        )
        .bind(email)
        .fetch_optional(&*self.pool)
        .await?;

        Ok(hash)
    }

    pub async fn try_get_chat_by_id(&self, id: Uuid) -> Result<Option<Chat>> {
        let chat = sqlx::query_as!(
            Chat,
            "SELECT id, user_id, workspace_id, name, created_at, deleted_at, updated_at
            FROM chats
            WHERE id = $1
            AND deleted_at IS NULL",
            id
        )
        .fetch_optional(&*self.pool)
        .await?;

        Ok(chat)
    }

    pub async fn try_get_chat_audit_by_id(&self, id: Uuid) -> Result<Option<ChatAudit>> {
        let chat_audit = sqlx::query_as!(
            ChatAudit,
            "SELECT id, chat_id, chat_message_id, user_id, trail, created_at
            FROM chat_audits
            WHERE id = $1",
            id
        )
        .fetch_optional(&*self.pool)
        .await?;

        Ok(chat_audit)
    }

    #[allow(dead_code)]
    pub async fn try_get_chat_audit_by_chat_message_id(
        &self,
        chat_message_id: Uuid,
    ) -> Result<Option<ChatAudit>> {
        let chat_audit = sqlx::query_as!(
            ChatAudit,
            "SELECT id, chat_id, chat_message_id, user_id, trail, created_at
            FROM chat_audits
            WHERE chat_message_id = $1
            ORDER BY created_at DESC
            LIMIT 1",
            chat_message_id
        )
        .fetch_optional(&*self.pool)
        .await?;

        Ok(chat_audit)
    }

    pub async fn try_get_chat_message_by_id(&self, id: Uuid) -> Result<Option<ChatMessage>> {
        let chat_message = sqlx::query_as!(
            ChatMessage,
            r#"SELECT id, ai_function_id, chat_id, simple_app_id, user_id, wasp_app_id, ai_function_call, ai_function_error, bad_reply_comment, bad_reply_is_harmful, bad_reply_is_not_helpful, bad_reply_is_not_true, bypass_sensitive_information_filter, estimated_response_at, is_anonymized, is_marked_as_not_sensitive, is_not_checked_by_system, is_sensitive, message, progress, response, simple_app_data, status AS "status: _", created_at, deleted_at, updated_at
            FROM chat_messages
            WHERE id = $1
            AND deleted_at IS NULL"#,
            id
        )
        .fetch_optional(&*self.pool)
        .await?;

        Ok(chat_message)
    }

    pub async fn try_get_chat_message_extended_by_id(
        &self,
        id: Uuid,
    ) -> Result<Option<ChatMessageExtended>> {
        let chat_message = self.try_get_chat_message_by_id(id).await?;

        match chat_message {
            None => Ok(None),
            Some(chat_message) => {
                let chat_message_files = self
                    .get_chat_message_files_by_chat_message_id(chat_message.id)
                    .await?;
                let chat_message_pictures = self
                    .get_chat_message_pictures_by_chat_message_ids(&[chat_message.id])
                    .await?;
                let profiles = self
                    .get_profiles_by_user_ids(&[chat_message.user_id])
                    .await?;
                let chat_message_extended = Self::map_to_chat_message_extended(
                    &chat_message,
                    chat_message_files,
                    chat_message_pictures,
                    profiles,
                );

                Ok(Some(chat_message_extended))
            }
        }
    }

    pub async fn try_get_chat_message_file_by_id(
        &self,
        id: Uuid,
    ) -> Result<Option<ChatMessageFile>> {
        let chat_message_file = sqlx::query_as!(
            ChatMessageFile,
            "SELECT id, chat_message_id, file_name, media_type, created_at, deleted_at
            FROM chat_message_files
            WHERE id = $1
            AND deleted_at IS NULL",
            id
        )
        .fetch_optional(&*self.pool)
        .await?;

        Ok(chat_message_file)
    }

    pub async fn try_get_chat_message_picture_by_id(
        &self,
        id: Uuid,
    ) -> Result<Option<ChatMessagePicture>> {
        let chat_message_picture = sqlx::query_as!(
            ChatMessagePicture,
            "SELECT id, chat_message_id, file_name, created_at, deleted_at, updated_at
            FROM chat_message_pictures
            WHERE id = $1
            AND deleted_at IS NULL",
            id
        )
        .fetch_optional(&*self.pool)
        .await?;

        Ok(chat_message_picture)
    }

    pub async fn try_get_chat_picture_by_chat_id(
        &self,
        chat_id: Uuid,
    ) -> Result<Option<ChatPicture>> {
        let chat_picture = sqlx::query_as!(
            ChatPicture,
            "SELECT id, chat_id, file_name, created_at, deleted_at, updated_at
            FROM chat_pictures
            WHERE chat_id = $1
            AND deleted_at IS NULL",
            chat_id
        )
        .fetch_optional(&*self.pool)
        .await?;

        Ok(chat_picture)
    }

    pub async fn try_get_chat_picture_by_id(&self, id: Uuid) -> Result<Option<ChatPicture>> {
        let chat_picture = sqlx::query_as!(
            ChatPicture,
            "SELECT id, chat_id, file_name, created_at, deleted_at, updated_at
            FROM chat_pictures
            WHERE id = $1
            AND deleted_at IS NULL",
            id
        )
        .fetch_optional(&*self.pool)
        .await?;

        Ok(chat_picture)
    }

    pub async fn try_get_company_primary(&self) -> Result<Option<Company>> {
        let company = sqlx::query_as!(
            Company,
            "SELECT id, address, name, created_at, deleted_at, updated_at
            FROM companies
            WHERE deleted_at IS NULL
            ORDER BY created_at ASC
            LIMIT 1"
        )
        .fetch_optional(&*self.pool)
        .await?;

        Ok(company)
    }

    pub async fn try_get_example_prompt_by_id(&self, id: Uuid) -> Result<Option<ExamplePrompt>> {
        let example_prompt = sqlx::query_as!(
            ExamplePrompt,
            "SELECT id, example_prompt_category_id, background_file_name, is_visible, priority, prompt, title, created_at, deleted_at, updated_at
            FROM example_prompts
            WHERE id = $1
            AND deleted_at IS NULL",
            id
        )
        .fetch_optional(&*self.pool)
        .await?;

        Ok(example_prompt)
    }

    pub async fn try_get_example_prompt_id_by_id(&self, id: Uuid) -> Result<Option<Uuid>> {
        let example_prompt_id = sqlx::query_scalar::<_, Uuid>(
            "SELECT id
            FROM example_prompts
            WHERE id = $1
            AND deleted_at IS NULL",
        )
        .bind(id)
        .fetch_optional(&*self.pool)
        .await?;

        Ok(example_prompt_id)
    }

    pub async fn try_get_example_prompt_category_by_id(
        &self,
        id: Uuid,
    ) -> Result<Option<ExamplePromptCategory>> {
        let example_prompt_category = sqlx::query_as!(
            ExamplePromptCategory,
            "SELECT id, description, is_visible, title, created_at, deleted_at, updated_at
            FROM example_prompt_categories
            WHERE id = $1
            AND deleted_at IS NULL",
            id
        )
        .fetch_optional(&*self.pool)
        .await?;

        Ok(example_prompt_category)
    }

    pub async fn try_get_example_prompt_category_id_by_id(&self, id: Uuid) -> Result<Option<Uuid>> {
        let example_prompt_category_id = sqlx::query_scalar::<_, Uuid>(
            "SELECT id
            FROM example_prompt_categories
            WHERE id = $1
            AND deleted_at IS NULL",
        )
        .bind(id)
        .fetch_optional(&*self.pool)
        .await?;

        Ok(example_prompt_category_id)
    }

    pub async fn try_get_inspection_disabling_by_user_id(
        &self,
        user_id: Uuid,
    ) -> Result<Option<InspectionDisabling>> {
        let inspection_disabling = sqlx::query_as!(
            InspectionDisabling,
            "SELECT id, user_id, content_safety_disabled_until, created_at, updated_at
            FROM inspection_disablings
            WHERE user_id = $1",
            user_id
        )
        .fetch_optional(&*self.pool)
        .await?;

        Ok(inspection_disabling)
    }

    pub async fn try_get_parameter_by_id(&self, id: Uuid) -> Result<Option<Parameter>> {
        let parameter = sqlx::query_as!(
            Parameter,
            "SELECT id, name, value, created_at, deleted_at, updated_at
            FROM parameters
            WHERE id = $1
            AND deleted_at IS NULL",
            id
        )
        .fetch_optional(&*self.pool)
        .await?;

        Ok(parameter)
    }

    pub async fn try_get_parameter_by_name(&self, name: &str) -> Result<Option<Parameter>> {
        let parameter = sqlx::query_as!(
            Parameter,
            "SELECT id, name, value, created_at, deleted_at, updated_at
            FROM parameters
            WHERE name = $1
            AND deleted_at IS NULL
            ORDER BY created_at DESC
            LIMIT 1",
            name
        )
        .fetch_optional(&*self.pool)
        .await?;

        Ok(parameter)
    }

    pub async fn try_get_parameter_id_by_id(&self, id: Uuid) -> Result<Option<Uuid>> {
        let parameter_id = sqlx::query_scalar::<_, Uuid>(
            "SELECT id
            FROM parameters
            WHERE id = $1
            AND deleted_at IS NULL",
        )
        .bind(id)
        .fetch_optional(&*self.pool)
        .await?;

        Ok(parameter_id)
    }

    pub async fn try_get_password_reset_token_by_token(
        &self,
        token: &str,
    ) -> Result<Option<PasswordResetToken>> {
        let password_reset_token = sqlx::query_as!(
            PasswordResetToken,
            "SELECT id, user_id, email, created_at, deleted_at, expires_at, updated_at
            FROM password_reset_tokens
            WHERE token = $1
            AND deleted_at IS NULL",
            token
        )
        .fetch_optional(&*self.pool)
        .await?;

        Ok(password_reset_token)
    }

    pub async fn try_get_password_reset_token_by_user_id(
        &self,
        user_id: Uuid,
    ) -> Result<Option<PasswordResetToken>> {
        let password_reset_token = sqlx::query_as!(
            PasswordResetToken,
            "SELECT id, user_id, email, created_at, deleted_at, expires_at, updated_at
            FROM password_reset_tokens
            WHERE user_id = $1
            AND deleted_at IS NULL
            ORDER BY created_at DESC
            LIMIT 1",
            user_id
        )
        .fetch_optional(&*self.pool)
        .await?;

        Ok(password_reset_token)
    }

    #[allow(dead_code)]
    pub async fn try_get_password_reset_token_token_by_id(
        &self,
        id: Uuid,
    ) -> Result<Option<String>> {
        let token = sqlx::query_scalar::<_, String>(
            "SELECT token
            FROM password_reset_tokens
            WHERE id = $1
            AND deleted_at IS NULL",
        )
        .bind(id)
        .fetch_optional(&*self.pool)
        .await?;

        Ok(token)
    }

    pub async fn try_get_profile_by_user_id(&self, user_id: Uuid) -> Result<Option<Profile>> {
        let profile = sqlx::query_as!(
            Profile,
            "SELECT id, user_id, job_title, language, name, photo_file_name, text_size, created_at, deleted_at, updated_at
            FROM profiles
            WHERE user_id = $1
            AND deleted_at IS NULL",
            user_id
        )
        .fetch_optional(&*self.pool)
        .await?;

        Ok(profile)
    }

    pub async fn try_get_session_by_id(&self, id: Uuid) -> Result<Option<Session>> {
        let session = sqlx::query_as!(
            Session,
            "SELECT id, user_id, data, expired_at
            FROM sessions
            WHERE id = $1",
            id
        )
        .fetch_optional(&*self.pool)
        .await?;

        Ok(session)
    }

    pub async fn try_get_simple_app_by_id(&self, id: Uuid) -> Result<Option<SimpleApp>> {
        let simple_app = sqlx::query_as!(
            SimpleApp,
            "SELECT id, code, description, formatted_name, is_enabled, name, created_at, deleted_at, updated_at
            FROM simple_apps
            WHERE id = $1
            AND deleted_at IS NULL",
            id
        )
        .fetch_optional(&*self.pool)
        .await?;

        Ok(simple_app)
    }

    pub async fn try_get_simple_app_id_by_id(&self, id: Uuid) -> Result<Option<Uuid>> {
        let simple_app_id = sqlx::query_scalar::<_, Uuid>(
            "SELECT id
            FROM simple_apps
            WHERE id = $1
            AND deleted_at IS NULL",
        )
        .bind(id)
        .fetch_optional(&*self.pool)
        .await?;

        Ok(simple_app_id)
    }

    pub async fn try_get_simple_app_by_formatted_name(
        &self,
        formatted_name: &str,
    ) -> Result<Option<SimpleApp>> {
        let simple_app = sqlx::query_as!(
            SimpleApp,
            "SELECT id, code, description, formatted_name, is_enabled, name, created_at, deleted_at, updated_at
            FROM simple_apps
            WHERE formatted_name = $1
            AND deleted_at IS NULL",
            formatted_name
        )
        .fetch_optional(&*self.pool)
        .await?;

        Ok(simple_app)
    }

    pub async fn try_get_user_by_email(&self, email: &str) -> Result<Option<User>> {
        let user = sqlx::query_as!(
            User,
            "SELECT id, company_id, email, is_enabled, is_invited, roles, created_at, deleted_at, updated_at
            FROM users
            WHERE email = $1
            AND deleted_at IS NULL",
            email
        )
        .fetch_optional(&*self.pool)
        .await?;

        Ok(user)
    }

    pub async fn try_get_user_by_id(&self, id: Uuid) -> Result<Option<User>> {
        let user = sqlx::query_as!(
            User,
            "SELECT id, company_id, email, is_enabled, is_invited, roles, created_at, deleted_at, updated_at
            FROM users
            WHERE id = $1
            AND deleted_at IS NULL",
            id
        )
        .fetch_optional(&*self.pool)
        .await?;

        Ok(user)
    }

    pub async fn try_get_user_roles_by_id(&self, id: Uuid) -> Result<Option<Vec<String>>> {
        let user_roles =
            sqlx::query_scalar::<_, Vec<String>>("SELECT roles FROM users WHERE id = $1")
                .bind(id)
                .fetch_optional(&*self.pool)
                .await?;

        Ok(user_roles)
    }

    pub async fn try_get_wasp_app_by_id(&self, id: Uuid) -> Result<Option<WaspApp>> {
        let wasp_app = sqlx::query_as!(
            WaspApp,
            "SELECT id, allowed_user_ids, code, description, formatted_name, is_enabled, name, created_at, deleted_at, updated_at
            FROM wasp_apps
            WHERE id = $1
            AND deleted_at IS NULL",
            id
        )
        .fetch_optional(&*self.pool)
        .await?;

        Ok(wasp_app)
    }

    pub async fn try_get_wasp_app_id_by_id(&self, id: Uuid) -> Result<Option<Uuid>> {
        let wasp_app_id = sqlx::query_scalar::<_, Uuid>(
            "SELECT id
            FROM wasp_apps
            WHERE id = $1
            AND deleted_at IS NULL",
        )
        .bind(id)
        .fetch_optional(&*self.pool)
        .await?;

        Ok(wasp_app_id)
    }

    pub async fn try_get_wasp_app_by_formatted_name(
        &self,
        formatted_name: &str,
    ) -> Result<Option<WaspApp>> {
        let wasp_app = sqlx::query_as!(
            WaspApp,
            "SELECT id, allowed_user_ids, code, description, formatted_name, is_enabled, name, created_at, deleted_at, updated_at
            FROM wasp_apps
            WHERE formatted_name = $1
            AND deleted_at IS NULL",
            formatted_name
        )
        .fetch_optional(&*self.pool)
        .await?;

        Ok(wasp_app)
    }

    pub async fn try_get_workspace_by_id(&self, id: Uuid) -> Result<Option<Workspace>> {
        let workspace = sqlx::query_as!(
            Workspace,
            r#"SELECT id, company_id, user_id, name, type AS "type: _", created_at, deleted_at, updated_at
            FROM workspaces
            WHERE id = $1
            AND deleted_at IS NULL"#,
            id
        )
        .fetch_optional(&*self.pool)
        .await?;

        Ok(workspace)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn update_ai_function(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        id: Uuid,
        description: &str,
        formatted_name: &str,
        name: &str,
        parameters: serde_json::Value,
        request_content_type: AiFunctionRequestContentType,
        response_content_type: AiFunctionResponseContentType,
    ) -> Result<AiFunction> {
        let ai_function = sqlx::query_as::<_, AiFunction>(
            "UPDATE ai_functions
            SET description = $2, formatted_name = $3, name = $4, parameters = $5, request_content_type = $6, response_content_type = $7, updated_at = current_timestamp(0)
            WHERE id = $1
            RETURNING id, ai_service_id, description, formatted_name, is_enabled, name, parameters, request_content_type, response_content_type, created_at, deleted_at, updated_at",
        )
        .bind(id)
        .bind(description)
        .bind(formatted_name)
        .bind(name)
        .bind(parameters)
        .bind(request_content_type)
        .bind(response_content_type)
        .fetch_one(&mut **transaction)
        .await?;

        Ok(ai_function)
    }

    pub async fn update_ai_function_is_enabled(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        id: Uuid,
        is_enabled: bool,
    ) -> Result<AiFunction> {
        let ai_function = sqlx::query_as!(
            AiFunction,
            r#"UPDATE ai_functions
            SET is_enabled = $2, updated_at = current_timestamp(0)
            WHERE id = $1
            RETURNING id, ai_service_id, description, formatted_name, is_enabled, name, parameters, request_content_type AS "request_content_type: _", response_content_type AS "response_content_type: _", created_at, deleted_at, updated_at"#,
            id,
            is_enabled,
        )
        .fetch_one(&mut **transaction)
        .await?;

        Ok(ai_function)
    }

    pub async fn update_ai_functions_is_enabled(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        ai_service_id: Uuid,
        is_enabled: bool,
    ) -> Result<Vec<AiFunction>> {
        let ai_functions = sqlx::query_as!(
            AiFunction,
            r#"UPDATE ai_functions
            SET is_enabled = $2, updated_at = current_timestamp(0)
            WHERE ai_service_id = $1
            RETURNING id, ai_service_id, description, formatted_name, is_enabled, name, parameters, request_content_type AS "request_content_type: _", response_content_type AS "response_content_type: _", created_at, deleted_at, updated_at"#,
            ai_service_id,
            is_enabled,
        )
        .fetch_all(&mut **transaction)
        .await?;

        Ok(ai_functions)
    }

    pub async fn update_ai_service(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        id: Uuid,
        is_enabled: bool,
        original_file_name: &str,
        original_function_body: &str,
    ) -> Result<AiService> {
        let ai_service = sqlx::query_as!(
            AiService,
            r#"UPDATE ai_services
            SET is_enabled = $2, original_file_name = $3, original_function_body = $4, updated_at = current_timestamp(0)
            WHERE id = $1
            RETURNING id, allowed_user_ids, device_map, health_check_execution_time, health_check_status AS "health_check_status: _", is_enabled, original_file_name, original_function_body, parser_feedback, port, priority, processed_function_body, progress, required_python_version AS "required_python_version: _", setup_execution_time, setup_status AS "setup_status: _", status AS "status: _", created_at, deleted_at, health_check_at, setup_at, updated_at"#,
            id,
            is_enabled,
            original_file_name,
            original_function_body,
        )
        .fetch_one(&mut **transaction)
        .await?;

        Ok(ai_service)
    }

    pub async fn update_ai_service_allowed_user_ids(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        id: Uuid,
        allowed_user_ids: &[Uuid],
    ) -> Result<AiService> {
        let ai_service = sqlx::query_as!(
            AiService,
            r#"UPDATE ai_services
            SET allowed_user_ids = $2, updated_at = current_timestamp(0)
            WHERE id = $1
            RETURNING id, allowed_user_ids, device_map, health_check_execution_time, health_check_status AS "health_check_status: _", is_enabled, original_file_name, original_function_body, parser_feedback, port, priority, processed_function_body, progress, required_python_version AS "required_python_version: _", setup_execution_time, setup_status AS "setup_status: _", status AS "status: _", created_at, deleted_at, health_check_at, setup_at, updated_at"#,
            id,
            allowed_user_ids,
        )
        .fetch_one(&mut **transaction)
        .await?;

        Ok(ai_service)
    }

    pub async fn update_ai_service_device_map(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        id: Uuid,
        device_map: serde_json::Value,
        status: AiServiceStatus,
    ) -> Result<AiService> {
        let ai_service = sqlx::query_as::<_, AiService>(
            "UPDATE ai_services
            SET device_map = $2, status = $3, updated_at = current_timestamp(0)
            WHERE id = $1
            RETURNING id, allowed_user_ids, device_map, health_check_execution_time, health_check_status, is_enabled, original_file_name, original_function_body, parser_feedback, port, priority, processed_function_body, progress, required_python_version, setup_execution_time, setup_status, status, created_at, deleted_at, health_check_at, setup_at, updated_at",
        )
        .bind(id)
        .bind(device_map)
        .bind(status)
        .fetch_one(&mut **transaction)
        .await?;

        Ok(ai_service)
    }

    pub async fn update_ai_service_device_map_and_processed_function_body(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        id: Uuid,
        device_map: serde_json::Value,
        processed_function_body: &str,
    ) -> Result<AiService> {
        let ai_service = sqlx::query_as!(
            AiService,
            r#"UPDATE ai_services
            SET device_map = $2, processed_function_body = $3, updated_at = current_timestamp(0)
            WHERE id = $1
            RETURNING id, allowed_user_ids, device_map, health_check_execution_time, health_check_status AS "health_check_status: _", is_enabled, original_file_name, original_function_body, parser_feedback, port, priority, processed_function_body, progress, required_python_version AS "required_python_version: _", setup_execution_time, setup_status AS "setup_status: _", status AS "status: _", created_at, deleted_at, health_check_at, setup_at, updated_at"#,
            id,
            device_map,
            processed_function_body,
        )
        .fetch_one(&mut **transaction)
        .await?;

        Ok(ai_service)
    }

    pub async fn update_ai_service_health_check_status(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        id: Uuid,
        health_check_execution_time: i32,
        health_check_status: AiServiceHealthCheckStatus,
    ) -> Result<AiService> {
        let ai_service = sqlx::query_as::<_, AiService>(
            "UPDATE ai_services
            SET health_check_execution_time = $2, health_check_status = $3, health_check_at = current_timestamp(0), updated_at = current_timestamp(0)
            WHERE id = $1
            RETURNING id, allowed_user_ids, device_map, health_check_execution_time, health_check_status, is_enabled, original_file_name, original_function_body, parser_feedback, port, priority, processed_function_body, progress, required_python_version, setup_execution_time, setup_status, status, created_at, deleted_at, health_check_at, setup_at, updated_at",
        )
        .bind(id)
        .bind(health_check_execution_time)
        .bind(health_check_status)
        .fetch_one(&mut **transaction)
        .await?;

        Ok(ai_service)
    }

    pub async fn update_ai_service_is_enabled(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        id: Uuid,
        is_enabled: bool,
    ) -> Result<AiService> {
        let ai_service = sqlx::query_as!(
            AiService,
            r#"UPDATE ai_services
            SET is_enabled = $2, updated_at = current_timestamp(0)
            WHERE id = $1
            RETURNING id, allowed_user_ids, device_map, health_check_execution_time, health_check_status AS "health_check_status: _", is_enabled, original_file_name, original_function_body, parser_feedback, port, priority, processed_function_body, progress, required_python_version AS "required_python_version: _", setup_execution_time, setup_status AS "setup_status: _", status AS "status: _", created_at, deleted_at, health_check_at, setup_at, updated_at"#,
            id,
            is_enabled,
        )
        .fetch_one(&mut **transaction)
        .await?;

        Ok(ai_service)
    }

    pub async fn update_ai_service_is_enabled_and_status(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        id: Uuid,
        is_enabled: bool,
        progress: i32,
        status: AiServiceStatus,
    ) -> Result<AiService> {
        let ai_service = sqlx::query_as::<_, AiService>(
            "UPDATE ai_services
            SET is_enabled = $2, progress = $3, status = $4, updated_at = current_timestamp(0)
            WHERE id = $1
            RETURNING id, allowed_user_ids, device_map, health_check_execution_time, health_check_status, is_enabled, original_file_name, original_function_body, parser_feedback, port, priority, processed_function_body, progress, required_python_version, setup_execution_time, setup_status, status, created_at, deleted_at, health_check_at, setup_at, updated_at",
        )
        .bind(id)
        .bind(is_enabled)
        .bind(progress)
        .bind(status)
        .fetch_one(&mut **transaction)
        .await?;

        Ok(ai_service)
    }

    pub async fn update_ai_service_parser_feedback(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        id: Uuid,
        parser_feedback: &str,
        progress: i32,
        status: AiServiceStatus,
    ) -> Result<AiService> {
        let ai_service = sqlx::query_as::<_, AiService>(
            "UPDATE ai_services
            SET parser_feedback = $2, progress = $3, status = $4, updated_at = current_timestamp(0)
            WHERE id = $1
            RETURNING id, allowed_user_ids, device_map, health_check_execution_time, health_check_status, is_enabled, original_file_name, original_function_body, parser_feedback, port, priority, processed_function_body, progress, required_python_version, setup_execution_time, setup_status, status, created_at, deleted_at, health_check_at, setup_at, updated_at",
        )
        .bind(id)
        .bind(parser_feedback)
        .bind(progress)
        .bind(status)
        .fetch_one(&mut **transaction)
        .await?;

        Ok(ai_service)
    }

    pub async fn update_ai_service_priority(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        id: Uuid,
        priority: i32,
    ) -> Result<AiService> {
        let ai_service = sqlx::query_as!(
            AiService,
            r#"UPDATE ai_services
            SET priority = $2, updated_at = current_timestamp(0)
            WHERE id = $1
            RETURNING id, allowed_user_ids, device_map, health_check_execution_time, health_check_status AS "health_check_status: _", is_enabled, original_file_name, original_function_body, parser_feedback, port, priority, processed_function_body, progress, required_python_version AS "required_python_version: _", setup_execution_time, setup_status AS "setup_status: _", status AS "status: _", created_at, deleted_at, health_check_at, setup_at, updated_at"#,
            id,
            priority,
        )
        .fetch_one(&mut **transaction)
        .await?;

        Ok(ai_service)
    }

    pub async fn update_ai_service_processed_function_body(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        id: Uuid,
        processed_function_body: &str,
        progress: i32,
        status: AiServiceStatus,
    ) -> Result<AiService> {
        let ai_service = sqlx::query_as::<_, AiService>(
            "UPDATE ai_services
            SET processed_function_body = $2, progress = $3, status = $4, updated_at = current_timestamp(0)
            WHERE id = $1
            RETURNING id, allowed_user_ids, device_map, health_check_execution_time, health_check_status, is_enabled, original_file_name, original_function_body, parser_feedback, port, priority, processed_function_body, progress, required_python_version, setup_execution_time, setup_status, status, created_at, deleted_at, health_check_at, setup_at, updated_at",
        )
        .bind(id)
        .bind(processed_function_body)
        .bind(progress)
        .bind(status)
        .fetch_one(&mut **transaction)
        .await?;

        Ok(ai_service)
    }

    pub async fn update_ai_service_required_python_version(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        id: Uuid,
        required_python_version: AiServiceRequiredPythonVersion,
    ) -> Result<AiService> {
        let ai_service = sqlx::query_as::<_, AiService>(
            "UPDATE ai_services
            SET required_python_version = $2, updated_at = current_timestamp(0)
            WHERE id = $1
            RETURNING id, allowed_user_ids, device_map, health_check_execution_time, health_check_status, is_enabled, original_file_name, original_function_body, parser_feedback, port, priority, processed_function_body, progress, required_python_version, setup_execution_time, setup_status, status, created_at, deleted_at, health_check_at, setup_at, updated_at",
        )
        .bind(id)
        .bind(required_python_version)
        .fetch_one(&mut **transaction)
        .await?;

        Ok(ai_service)
    }

    pub async fn update_ai_service_setup_status(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        id: Uuid,
        setup_execution_time: i32,
        setup_status: AiServiceSetupStatus,
    ) -> Result<AiService> {
        let ai_service = sqlx::query_as::<_, AiService>(
            "UPDATE ai_services
            SET setup_execution_time = $2, setup_status = $3, setup_at = current_timestamp(0), updated_at = current_timestamp(0)
            WHERE id = $1
            RETURNING id, allowed_user_ids, device_map, health_check_execution_time, health_check_status, is_enabled, original_file_name, original_function_body, parser_feedback, port, priority, processed_function_body, progress, required_python_version, setup_execution_time, setup_status, status, created_at, deleted_at, health_check_at, setup_at, updated_at",
        )
        .bind(id)
        .bind(setup_execution_time)
        .bind(setup_status)
        .fetch_one(&mut **transaction)
        .await?;

        Ok(ai_service)
    }

    pub async fn update_ai_service_status(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        id: Uuid,
        progress: i32,
        status: AiServiceStatus,
    ) -> Result<AiService> {
        let ai_service = sqlx::query_as::<_, AiService>(
            "UPDATE ai_services
            SET progress = $2, status = $3, updated_at = current_timestamp(0)
            WHERE id = $1
            RETURNING id, allowed_user_ids, device_map, health_check_execution_time, health_check_status, is_enabled, original_file_name, original_function_body, parser_feedback, port, priority, processed_function_body, progress, required_python_version, setup_execution_time, setup_status, status, created_at, deleted_at, health_check_at, setup_at, updated_at",
        )
        .bind(id)
        .bind(progress)
        .bind(status)
        .fetch_one(&mut **transaction)
        .await?;

        Ok(ai_service)
    }

    pub async fn update_chat(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        id: Uuid,
        name: &str,
    ) -> Result<Chat> {
        let chat = sqlx::query_as!(
            Chat,
            "UPDATE chats
            SET name = $2, updated_at = current_timestamp(0)
            WHERE id = $1
            RETURNING id, user_id, workspace_id, name, created_at, deleted_at, updated_at",
            id,
            name
        )
        .fetch_one(&mut **transaction)
        .await?;

        Ok(chat)
    }

    pub async fn update_chat_message(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        id: Uuid,
        progress: i32,
        response: &str,
        status: ChatMessageStatus,
    ) -> Result<ChatMessage> {
        let chat_message = sqlx::query_as::<_, ChatMessage>(
            "UPDATE chat_messages
            SET progress = $2, response = $3, status = $4, updated_at = current_timestamp(0)
            WHERE id = $1
            RETURNING id, ai_function_id, chat_id, simple_app_id, user_id, wasp_app_id, ai_function_call, ai_function_error, bad_reply_comment, bad_reply_is_harmful, bad_reply_is_not_helpful, bad_reply_is_not_true, bypass_sensitive_information_filter, estimated_response_at, is_anonymized, is_marked_as_not_sensitive, is_not_checked_by_system, is_sensitive, message, progress, response, simple_app_data, status, created_at, deleted_at, updated_at",
        )
        .bind(id)
        .bind(progress)
        .bind(response)
        .bind(status)
        .fetch_one(&mut **transaction)
        .await?;

        Ok(chat_message)
    }

    pub async fn update_chat_message_ai_function_call(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        id: Uuid,
        ai_function_call: serde_json::Value,
    ) -> Result<ChatMessage> {
        let chat_message = sqlx::query_as::<_, ChatMessage>(
            "UPDATE chat_messages
            SET ai_function_call = $2, updated_at = current_timestamp(0)
            WHERE id = $1
            RETURNING id, ai_function_id, chat_id, simple_app_id, user_id, wasp_app_id, ai_function_call, ai_function_error, bad_reply_comment, bad_reply_is_harmful, bad_reply_is_not_helpful, bad_reply_is_not_true, bypass_sensitive_information_filter, estimated_response_at, is_anonymized, is_marked_as_not_sensitive, is_not_checked_by_system, is_sensitive, message, progress, response, simple_app_data, status, created_at, deleted_at, updated_at",
        )
        .bind(id)
        .bind(ai_function_call)
        .fetch_one(&mut **transaction)
        .await?;

        Ok(chat_message)
    }

    pub async fn update_chat_message_flag(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        id: Uuid,
        bad_reply_comment: Option<String>,
        bad_reply_is_harmful: bool,
        bad_reply_is_not_helpful: bool,
        bad_reply_is_not_true: bool,
    ) -> Result<ChatMessage> {
        let chat_message = sqlx::query_as!(
            ChatMessage,
            r#"UPDATE chat_messages
            SET bad_reply_comment = $2, bad_reply_is_harmful = $3, bad_reply_is_not_helpful = $4, bad_reply_is_not_true = $5, updated_at = current_timestamp(0)
            WHERE id = $1
            RETURNING id, ai_function_id, chat_id, simple_app_id, user_id, wasp_app_id, ai_function_call, ai_function_error, bad_reply_comment, bad_reply_is_harmful, bad_reply_is_not_helpful, bad_reply_is_not_true, bypass_sensitive_information_filter, estimated_response_at, is_anonymized, is_marked_as_not_sensitive, is_not_checked_by_system, is_sensitive, message, progress, response, simple_app_data, status AS "status: _", created_at, deleted_at, updated_at"#,
            id,
            bad_reply_comment,
            bad_reply_is_harmful,
            bad_reply_is_not_helpful,
            bad_reply_is_not_true,
        )
        .fetch_one(&mut **transaction)
        .await?;

        Ok(chat_message)
    }

    pub async fn update_chat_message_from_function(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        id: Uuid,
        ai_function_id: Uuid,
        status: ChatMessageStatus,
        progress: i32,
        response: Option<String>,
    ) -> Result<ChatMessage> {
        let chat_message = sqlx::query_as::<_, ChatMessage>(
            "UPDATE chat_messages
            SET ai_function_id = $2, status = $3, progress = $4, response = $5, updated_at = current_timestamp(0)
            WHERE id = $1
            RETURNING id, ai_function_id, chat_id, simple_app_id, user_id, wasp_app_id, ai_function_call, ai_function_error, bad_reply_comment, bad_reply_is_harmful, bad_reply_is_not_helpful, bad_reply_is_not_true, bypass_sensitive_information_filter, estimated_response_at, is_anonymized, is_marked_as_not_sensitive, is_not_checked_by_system, is_sensitive, message, progress, response, simple_app_data, status, created_at, deleted_at, updated_at",
        )
        .bind(id)
        .bind(ai_function_id)
        .bind(status)
        .bind(progress)
        .bind(response)
        .fetch_one(&mut **transaction)
        .await?;

        Ok(chat_message)
    }

    pub async fn update_chat_message_from_function_error(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        id: Uuid,
        ai_function_id: Uuid,
        ai_function_error: Option<String>,
        status: ChatMessageStatus,
        progress: i32,
    ) -> Result<ChatMessage> {
        let chat_message = sqlx::query_as::<_, ChatMessage>(
            "UPDATE chat_messages
            SET ai_function_id = $2, ai_function_error = $3, status = $4, progress = $5, updated_at = current_timestamp(0)
            WHERE id = $1
            RETURNING id, ai_function_id, chat_id, simple_app_id, user_id, wasp_app_id, ai_function_call, ai_function_error, bad_reply_comment, bad_reply_is_harmful, bad_reply_is_not_helpful, bad_reply_is_not_true, bypass_sensitive_information_filter, estimated_response_at, is_anonymized, is_marked_as_not_sensitive, is_not_checked_by_system, is_sensitive, message, progress, response, simple_app_data, status, created_at, deleted_at, updated_at",
        )
        .bind(id)
        .bind(ai_function_id)
        .bind(ai_function_error)
        .bind(status)
        .bind(progress)
        .fetch_one(&mut **transaction)
        .await?;

        Ok(chat_message)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn update_chat_message_full(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        id: Uuid,
        estimated_response_at: DateTime<Utc>,
        message: &str,
        status: ChatMessageStatus,
        progress: i32,
        response: Option<String>,
    ) -> Result<ChatMessage> {
        let chat_message = sqlx::query_as::<_, ChatMessage>(
            "UPDATE chat_messages
            SET estimated_response_at = $2, message = $3, status = $4, progress = $5, response = $6, created_at = current_timestamp(0), updated_at = current_timestamp(0)
            WHERE id = $1
            RETURNING id, ai_function_id, chat_id, simple_app_id, user_id, wasp_app_id, ai_function_call, ai_function_error, bad_reply_comment, bad_reply_is_harmful, bad_reply_is_not_helpful, bad_reply_is_not_true, bypass_sensitive_information_filter, estimated_response_at, is_anonymized, is_marked_as_not_sensitive, is_not_checked_by_system, is_sensitive, message, progress, response, simple_app_data, status, created_at, deleted_at, updated_at",
        )
        .bind(id)
        .bind(estimated_response_at)
        .bind(message)
        .bind(status)
        .bind(progress)
        .bind(response)
        .fetch_one(&mut **transaction)
        .await?;

        Ok(chat_message)
    }

    pub async fn update_chat_message_is_anonymized(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        id: Uuid,
        is_anonymized: bool,
        message: &str,
        status: ChatMessageStatus,
        progress: i32,
    ) -> Result<ChatMessage> {
        let chat_message = sqlx::query_as::<_, ChatMessage>(
            "UPDATE chat_messages
            SET is_anonymized = $2, message = $3, status = $4, progress = $5, updated_at = current_timestamp(0)
            WHERE id = $1
            RETURNING id, ai_function_id, chat_id, simple_app_id, user_id, wasp_app_id, ai_function_call, ai_function_error, bad_reply_comment, bad_reply_is_harmful, bad_reply_is_not_helpful, bad_reply_is_not_true, bypass_sensitive_information_filter, estimated_response_at, is_anonymized, is_marked_as_not_sensitive, is_not_checked_by_system, is_sensitive, message, progress, response, simple_app_data, status, created_at, deleted_at, updated_at",
        )
        .bind(id)
        .bind(is_anonymized)
        .bind(message)
        .bind(status)
        .bind(progress)
        .fetch_one(&mut **transaction)
        .await?;

        Ok(chat_message)
    }

    pub async fn update_chat_message_is_marked_as_not_sensitive(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        id: Uuid,
        is_marked_as_not_sensitive: bool,
        status: ChatMessageStatus,
        progress: i32,
    ) -> Result<ChatMessage> {
        let chat_message = sqlx::query_as::<_, ChatMessage>(
            "UPDATE chat_messages
            SET is_marked_as_not_sensitive = $2, status = $3, progress = $4, updated_at = current_timestamp(0)
            WHERE id = $1
            RETURNING id, ai_function_id, chat_id, simple_app_id, user_id, wasp_app_id, ai_function_call, ai_function_error, bad_reply_comment, bad_reply_is_harmful, bad_reply_is_not_helpful, bad_reply_is_not_true, bypass_sensitive_information_filter, estimated_response_at, is_anonymized, is_marked_as_not_sensitive, is_not_checked_by_system, is_sensitive, message, progress, response, simple_app_data, status, created_at, deleted_at, updated_at",
        )
        .bind(id)
        .bind(is_marked_as_not_sensitive)
        .bind(status)
        .bind(progress)
        .fetch_one(&mut **transaction)
        .await?;

        Ok(chat_message)
    }

    pub async fn update_chat_message_is_not_checked_by_system(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        id: Uuid,
        is_not_checked_by_system: bool,
    ) -> Result<ChatMessage> {
        let chat_message = sqlx::query_as!(
            ChatMessage,
            r#"UPDATE chat_messages
            SET is_not_checked_by_system = $2, updated_at = current_timestamp(0)
            WHERE id = $1
            RETURNING id, ai_function_id, chat_id, simple_app_id, user_id, wasp_app_id, ai_function_call, ai_function_error, bad_reply_comment, bad_reply_is_harmful, bad_reply_is_not_helpful, bad_reply_is_not_true, bypass_sensitive_information_filter, estimated_response_at, is_anonymized, is_marked_as_not_sensitive, is_not_checked_by_system, is_sensitive, message, progress, response, simple_app_data, status AS "status: _", created_at, deleted_at, updated_at"#,
            id,
            is_not_checked_by_system,
        )
        .fetch_one(&mut **transaction)
        .await?;

        Ok(chat_message)
    }

    pub async fn update_chat_message_is_sensitive(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        id: Uuid,
        is_sensitive: bool,
        status: ChatMessageStatus,
        progress: i32,
    ) -> Result<ChatMessage> {
        let chat_message = sqlx::query_as::<_, ChatMessage>(
            "UPDATE chat_messages
            SET is_sensitive = $2, status = $3, progress = $4, updated_at = current_timestamp(0)
            WHERE id = $1
            RETURNING id, ai_function_id, chat_id, simple_app_id, user_id, wasp_app_id, ai_function_call, ai_function_error, bad_reply_comment, bad_reply_is_harmful, bad_reply_is_not_helpful, bad_reply_is_not_true, bypass_sensitive_information_filter, estimated_response_at, is_anonymized, is_marked_as_not_sensitive, is_not_checked_by_system, is_sensitive, message, progress, response, simple_app_data, status, created_at, deleted_at, updated_at",
        )
        .bind(id)
        .bind(is_sensitive)
        .bind(status)
        .bind(progress)
        .fetch_one(&mut **transaction)
        .await?;

        Ok(chat_message)
    }

    pub async fn update_chat_message_simple_app_id(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        id: Uuid,
        progress: i32,
        simple_app_id: Uuid,
        status: ChatMessageStatus,
    ) -> Result<ChatMessage> {
        let chat_message = sqlx::query_as::<_, ChatMessage>(
            "UPDATE chat_messages
            SET progress = $2, simple_app_id = $3, status = $4, updated_at = current_timestamp(0)
            WHERE id = $1
            RETURNING id, ai_function_id, chat_id, simple_app_id, user_id, wasp_app_id, ai_function_call, ai_function_error, bad_reply_comment, bad_reply_is_harmful, bad_reply_is_not_helpful, bad_reply_is_not_true, bypass_sensitive_information_filter, estimated_response_at, is_anonymized, is_marked_as_not_sensitive, is_not_checked_by_system, is_sensitive, message, progress, response, simple_app_data, status, created_at, deleted_at, updated_at",
        )
        .bind(id)
        .bind(progress)
        .bind(simple_app_id)
        .bind(status)
        .fetch_one(&mut **transaction)
        .await?;

        Ok(chat_message)
    }

    pub async fn update_chat_message_wasp_app_id(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        id: Uuid,
        progress: i32,
        wasp_app_id: Uuid,
        status: ChatMessageStatus,
    ) -> Result<ChatMessage> {
        let chat_message = sqlx::query_as::<_, ChatMessage>(
            "UPDATE chat_messages
            SET progress = $2, wasp_app_id = $3, status = $4, updated_at = current_timestamp(0)
            WHERE id = $1
            RETURNING id, ai_function_id, chat_id, simple_app_id, user_id, wasp_app_id, ai_function_call, ai_function_error, bad_reply_comment, bad_reply_is_harmful, bad_reply_is_not_helpful, bad_reply_is_not_true, bypass_sensitive_information_filter, estimated_response_at, is_anonymized, is_marked_as_not_sensitive, is_not_checked_by_system, is_sensitive, message, progress, response, simple_app_data, status, created_at, deleted_at, updated_at",
        )
        .bind(id)
        .bind(progress)
        .bind(wasp_app_id)
        .bind(status)
        .fetch_one(&mut **transaction)
        .await?;

        Ok(chat_message)
    }

    pub async fn update_chat_message_picture(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        id: Uuid,
        file_name: &str,
    ) -> Result<ChatMessagePicture> {
        let chat_message_picture = sqlx::query_as!(
            ChatMessagePicture,
            "UPDATE chat_message_pictures
            SET file_name = $2, updated_at = current_timestamp(0)
            WHERE id = $1
            RETURNING id, chat_message_id, file_name, created_at, deleted_at, updated_at",
            id,
            file_name
        )
        .fetch_one(&mut **transaction)
        .await?;

        Ok(chat_message_picture)
    }

    pub async fn update_chat_picture(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        id: Uuid,
        file_name: &str,
    ) -> Result<ChatPicture> {
        let chat = sqlx::query_as!(
            ChatPicture,
            "UPDATE chat_pictures
            SET file_name = $2, updated_at = current_timestamp(0)
            WHERE id = $1
            RETURNING id, chat_id, file_name, created_at, deleted_at, updated_at",
            id,
            file_name
        )
        .fetch_one(&mut **transaction)
        .await?;

        Ok(chat)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn update_example_prompt(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        id: Uuid,
        example_prompt_category_id: Uuid,
        background_file_name: Option<String>,
        is_visible: bool,
        priority: i32,
        prompt: &str,
        title: &str,
    ) -> Result<ExamplePrompt> {
        let example_prompt = sqlx::query_as!(
            ExamplePrompt,
            "UPDATE example_prompts
            SET example_prompt_category_id = $2, background_file_name = $3, is_visible = $4, priority = $5, prompt = $6, title = $7, updated_at = current_timestamp(0)
            WHERE id = $1
            RETURNING id, example_prompt_category_id, background_file_name, is_visible, priority, prompt, title, created_at, deleted_at, updated_at",
            id,
            example_prompt_category_id,
            background_file_name,
            is_visible,
            priority,
            prompt,
            title
        )
        .fetch_one(&mut **transaction)
        .await?;

        Ok(example_prompt)
    }

    pub async fn update_example_prompt_category(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        id: Uuid,
        description: &str,
        is_visible: bool,
        title: &str,
    ) -> Result<ExamplePromptCategory> {
        let example_prompt_category = sqlx::query_as!(
            ExamplePromptCategory,
            "UPDATE example_prompt_categories
            SET description = $2, is_visible = $3, title = $4, updated_at = current_timestamp(0)
            WHERE id = $1
            RETURNING id, description, is_visible, title, created_at, deleted_at, updated_at",
            id,
            description,
            is_visible,
            title
        )
        .fetch_one(&mut **transaction)
        .await?;

        Ok(example_prompt_category)
    }

    pub async fn update_inspection_disabling(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        id: Uuid,
        user_id: Uuid,
        content_safety_disabled_until: DateTime<Utc>,
    ) -> Result<InspectionDisabling> {
        let inspection_disabling = sqlx::query_as!(
            InspectionDisabling,
            "UPDATE inspection_disablings
            SET user_id = $2, content_safety_disabled_until = $3, updated_at = current_timestamp(0)
            WHERE id = $1
            RETURNING id, user_id, content_safety_disabled_until, created_at, updated_at",
            id,
            user_id,
            content_safety_disabled_until
        )
        .fetch_one(&mut **transaction)
        .await?;

        Ok(inspection_disabling)
    }

    pub async fn update_parameter(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        id: Uuid,
        name: &str,
        value: &str,
    ) -> Result<Parameter> {
        let parameter = sqlx::query_as!(
            Parameter,
            "UPDATE parameters
            SET name = $2, value = $3, updated_at = current_timestamp(0)
            WHERE id = $1
            RETURNING id, name, value, created_at, deleted_at, updated_at",
            id,
            name,
            value
        )
        .fetch_one(&mut **transaction)
        .await?;

        Ok(parameter)
    }

    pub async fn update_profile(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        id: Uuid,
        job_title: Option<String>,
        language: &str,
        name: Option<String>,
        text_size: i32,
    ) -> Result<Profile> {
        let profile = sqlx::query_as!(
            Profile,
            "UPDATE profiles
            SET job_title = $2, language = $3, name = $4, text_size = $5, updated_at = current_timestamp(0)
            WHERE id = $1
            RETURNING id, user_id, job_title, language, name, photo_file_name, text_size, created_at, deleted_at, updated_at",
            id,
            job_title,
            language,
            name,
            text_size
        )
        .fetch_one(&mut **transaction)
        .await?;

        Ok(profile)
    }

    pub async fn update_profile_photo_file_name(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        id: Uuid,
        photo_file_name: Option<String>,
    ) -> Result<Profile> {
        let profile = sqlx::query_as!(
            Profile,
            "UPDATE profiles
            SET photo_file_name = $2, updated_at = current_timestamp(0)
            WHERE id = $1
            RETURNING id, user_id, job_title, language, name, photo_file_name, text_size, created_at, deleted_at, updated_at",
            id,
            photo_file_name
        )
        .fetch_one(&mut **transaction)
        .await?;

        Ok(profile)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn update_simple_app(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        id: Uuid,
        code: &str,
        description: &str,
        formatted_name: &str,
        is_enabled: bool,
        name: &str,
    ) -> Result<SimpleApp> {
        let simple_app = sqlx::query_as!(
            SimpleApp,
            "UPDATE simple_apps
            SET code = $2, description = $3, formatted_name = $4, is_enabled = $5, name = $6, updated_at = current_timestamp(0)
            WHERE id = $1
            RETURNING id, code, description, formatted_name, is_enabled, name, created_at, deleted_at, updated_at",
            id,
            code,
            description,
            formatted_name,
            is_enabled,
            name,
        )
        .fetch_one(&mut **transaction)
        .await?;

        Ok(simple_app)
    }

    pub async fn update_user(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        id: Uuid,
        email: &str,
        is_enabled: bool,
        roles: &[String],
    ) -> Result<User> {
        let user = sqlx::query_as!(
            User,
            "UPDATE users
            SET email = $2, is_enabled = $3, roles = $4, updated_at = current_timestamp(0)
            WHERE id = $1
            RETURNING id, company_id, email, is_enabled, is_invited, roles, created_at, deleted_at, updated_at",
            id,
            email,
            is_enabled,
            roles
        )
        .fetch_one(&mut **transaction)
        .await?;

        Ok(user)
    }

    pub async fn update_user_email(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        id: Uuid,
        email: &str,
    ) -> Result<User> {
        let user = sqlx::query_as!(
            User,
            "UPDATE users
            SET email = $2, updated_at = current_timestamp(0)
            WHERE id = $1
            RETURNING id, company_id, email, is_enabled, is_invited, roles, created_at, deleted_at, updated_at",
            id,
            email
        )
        .fetch_one(&mut **transaction)
        .await?;

        Ok(user)
    }

    pub async fn update_user_password(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        id: Uuid,
        password: &str,
    ) -> Result<User> {
        let user = sqlx::query_as!(
            User,
            "UPDATE users
            SET password = $2, updated_at = current_timestamp(0)
            WHERE id = $1
            RETURNING id, company_id, email, is_enabled, is_invited, roles, created_at, deleted_at, updated_at",
            id,
            password
        )
        .fetch_one(&mut **transaction)
        .await?;

        Ok(user)
    }

    #[allow(dead_code)]
    pub async fn update_user_roles(&self, id: Uuid, roles: &[String]) -> Result<User> {
        let user = sqlx::query_as!(
            User,
            "UPDATE users
            SET roles = $2, updated_at = current_timestamp(0)
            WHERE id = $1
            RETURNING id, company_id, email, is_enabled, is_invited, roles, created_at, deleted_at, updated_at",
            id,
            roles
        )
        .fetch_one(&*self.pool)
        .await?;

        Ok(user)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn update_wasp_app(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        id: Uuid,
        code: &[u8],
        description: &str,
        formatted_name: &str,
        is_enabled: bool,
        name: &str,
    ) -> Result<WaspApp> {
        let wasp_app = sqlx::query_as!(
            WaspApp,
            "UPDATE wasp_apps
            SET code = $2, description = $3, formatted_name = $4, is_enabled = $5, name = $6, updated_at = current_timestamp(0)
            WHERE id = $1
            RETURNING id, allowed_user_ids, code, description, formatted_name, is_enabled, name, created_at, deleted_at, updated_at",
            id,
            code,
            description,
            formatted_name,
            is_enabled,
            name,
        )
        .fetch_one(&mut **transaction)
        .await?;

        Ok(wasp_app)
    }

    pub async fn update_wasp_app_allowed_user_ids(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        id: Uuid,
        allowed_user_ids: &[Uuid],
    ) -> Result<WaspApp> {
        let wasp_app = sqlx::query_as!(
            WaspApp,
            r#"UPDATE wasp_apps
            SET allowed_user_ids = $2, updated_at = current_timestamp(0)
            WHERE id = $1
            RETURNING id, allowed_user_ids, code, description, formatted_name, is_enabled, name, created_at, deleted_at, updated_at"#,
            id,
            allowed_user_ids,
        )
        .fetch_one(&mut **transaction)
        .await?;

        Ok(wasp_app)
    }

    pub async fn update_wasp_app_info(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        id: Uuid,
        description: &str,
        formatted_name: &str,
        is_enabled: bool,
        name: &str,
    ) -> Result<WaspApp> {
        let wasp_app = sqlx::query_as!(
            WaspApp,
            "UPDATE wasp_apps
            SET description = $2, formatted_name = $3, is_enabled = $4, name = $5, updated_at = current_timestamp(0)
            WHERE id = $1
            RETURNING id, allowed_user_ids, code, description, formatted_name, is_enabled, name, created_at, deleted_at, updated_at",
            id,
            description,
            formatted_name,
            is_enabled,
            name,
        )
        .fetch_one(&mut **transaction)
        .await?;

        Ok(wasp_app)
    }

    pub async fn update_workspace(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        id: Uuid,
        name: &str,
        r#type: WorkspacesType,
    ) -> Result<Workspace> {
        let workspace = sqlx::query_as::<_, Workspace>(
            "UPDATE workspaces
            SET name = $2, type = $3, updated_at = current_timestamp(0)
            WHERE id = $1
            RETURNING id, company_id, user_id, name, type, created_at, deleted_at, updated_at",
        )
        .bind(id)
        .bind(name)
        .bind(r#type)
        .fetch_one(&mut **transaction)
        .await?;

        Ok(workspace)
    }
}
