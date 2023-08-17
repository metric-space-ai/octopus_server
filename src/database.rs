use crate::{
    entity::{
        AiFunction, AiFunctionSetupStatus, Chat, ChatActivity, ChatAudit, ChatMessage,
        ChatMessageExtended, ChatMessageFile, ChatMessagePicture, ChatMessageStatus, ChatPicture,
        Company, EstimatedSeconds, ExamplePrompt, PasswordResetToken, Profile, Session, User,
        Workspace, WorkspacesType,
    },
    Result, PUBLIC_DIR,
};
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

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

    pub async fn get_ai_functions(&self) -> Result<Vec<AiFunction>> {
        let ai_functions = sqlx::query_as!(
            AiFunction,
            r#"SELECT id, base_function_url, description, device_map, health_check_execution_time, health_check_status AS "health_check_status: _", health_check_url, is_available, is_enabled, k8s_configuration, name, parameters, setup_execution_time, setup_status AS "setup_status: _", setup_url, warmup_execution_time, warmup_status AS "warmup_status: _", created_at, deleted_at, health_check_at, setup_at, updated_at, warmup_at
            FROM ai_functions
            WHERE deleted_at IS NULL
            ORDER BY name ASC"#
        )
        .fetch_all(&*self.pool)
        .await?;

        Ok(ai_functions)
    }

    pub async fn get_ai_functions_for_request(&self) -> Result<Vec<AiFunction>> {
        let is_available = true;
        let is_enabled = true;
        let setup_status = AiFunctionSetupStatus::Performed;

        let ai_functions = sqlx::query_as::<_, AiFunction>(
            "SELECT id, base_function_url, description, device_map, health_check_execution_time, health_check_status, health_check_url, is_available, is_enabled, k8s_configuration, name, parameters, setup_execution_time, setup_status, setup_url, warmup_execution_time, warmup_status, created_at, deleted_at, health_check_at, setup_at, updated_at, warmup_at
            FROM ai_functions
            WHERE is_available = $1
            AND is_enabled = $2
            AND setup_status = $3
            AND deleted_at IS NULL
            ORDER BY name ASC",
        )
        .bind(is_available)
        .bind(is_enabled)
        .bind(setup_status)
        .fetch_all(&*self.pool)
        .await?;

        Ok(ai_functions)
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
            r#"SELECT id, ai_function_id, chat_id, user_id, bad_reply_comment, bad_reply_is_harmful, bad_reply_is_not_helpful, bad_reply_is_not_true, estimated_response_at, message, progress, response, status AS "status: _", created_at, deleted_at, updated_at
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
            r#"SELECT id, ai_function_id, chat_id, user_id, bad_reply_comment, bad_reply_is_harmful, bad_reply_is_not_helpful, bad_reply_is_not_true, estimated_response_at, message, progress, response, status AS "status: _", created_at, deleted_at, updated_at
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

        let chat_message_files = self
            .get_chat_message_files_by_chat_message_ids(&chat_messages_ids)
            .await?;
        let chat_message_pictures = self
            .get_chat_message_pictures_by_chat_message_ids(&chat_messages_ids)
            .await?;

        let mut chat_messages_extended = vec![];

        for chat_message in chat_messages {
            let chat_message_extended = self
                .map_to_chat_message_extended(
                    &chat_message,
                    chat_message_files.clone(),
                    chat_message_pictures.clone(),
                )
                .await?;
            chat_messages_extended.push(chat_message_extended);
        }

        Ok(chat_messages_extended)
    }

    pub async fn get_chat_messages_by_chat_id_and_status(
        &self,
        chat_id: Uuid,
        status: ChatMessageStatus,
    ) -> Result<Vec<ChatMessage>> {
        let chat_messages = sqlx::query_as::<_, ChatMessage>(
            "SELECT id, ai_function_id, chat_id, user_id, bad_reply_comment, bad_reply_is_harmful, bad_reply_is_not_helpful, bad_reply_is_not_true, estimated_response_at, message, progress, response, status, created_at, deleted_at, updated_at
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
            "SELECT id, is_visible, priority, prompt, created_at, deleted_at, updated_at
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
        base_function_url: &str,
        description: &str,
        device_map: serde_json::Value,
        health_check_url: &str,
        is_available: bool,
        is_enabled: bool,
        k8s_configuration: Option<String>,
        name: &str,
        parameters: serde_json::Value,
        setup_url: &str,
    ) -> Result<AiFunction> {
        let ai_function = sqlx::query_as!(
            AiFunction,
            r#"INSERT INTO ai_functions
            (base_function_url, description, device_map, health_check_url, is_available, is_enabled, k8s_configuration, name, parameters, setup_url)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            RETURNING id, base_function_url, description, device_map, health_check_execution_time, health_check_status AS "health_check_status: _", health_check_url, is_available, is_enabled, k8s_configuration, name, parameters, setup_execution_time, setup_status AS "setup_status: _", setup_url, warmup_execution_time, warmup_status AS "warmup_status: _", created_at, deleted_at, health_check_at, setup_at, updated_at, warmup_at"#,
            base_function_url,
            description,
            device_map,
            health_check_url,
            is_available,
            is_enabled,
            k8s_configuration,
            name,
            parameters,
            setup_url,
        )
        .fetch_one(&*self.pool)
        .await?;

        Ok(ai_function)
    }

    pub async fn insert_chat(&self, user_id: Uuid, workspace_id: Uuid) -> Result<Chat> {
        let chat = sqlx::query_as!(
            Chat,
            "INSERT INTO chats
            (user_id, workspace_id)
            VALUES ($1, $2)
            RETURNING id, user_id, workspace_id, name, created_at, deleted_at, updated_at",
            user_id,
            workspace_id
        )
        .fetch_one(&*self.pool)
        .await?;

        Ok(chat)
    }

    pub async fn insert_chat_activity(
        &self,
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
        .fetch_one(&*self.pool)
        .await?;

        Ok(chat_activity)
    }

    pub async fn insert_chat_audit(
        &self,
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
        .fetch_one(&*self.pool)
        .await?;

        Ok(chat_audit)
    }

    pub async fn insert_chat_message(
        &self,
        chat_id: Uuid,
        user_id: Uuid,
        estimated_response_at: DateTime<Utc>,
        message: &str,
    ) -> Result<ChatMessage> {
        let chat_message = sqlx::query_as!(
            ChatMessage,
            r#"INSERT INTO chat_messages
            (chat_id, user_id, estimated_response_at, message)
            VALUES ($1, $2, $3, $4)
            RETURNING id, ai_function_id, chat_id, user_id, bad_reply_comment, bad_reply_is_harmful, bad_reply_is_not_helpful, bad_reply_is_not_true, estimated_response_at, message, progress, response, status AS "status: _", created_at, deleted_at, updated_at"#,
            chat_id,
            user_id,
            estimated_response_at,
            message,
        )
        .fetch_one(&*self.pool)
        .await?;

        Ok(chat_message)
    }

    #[allow(dead_code)]
    pub async fn insert_chat_message_file(
        &self,
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
        .fetch_one(&*self.pool)
        .await?;

        Ok(chat_message_file)
    }

    pub async fn insert_chat_message_picture(
        &self,
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
        .fetch_one(&*self.pool)
        .await?;

        Ok(chat_message_picture)
    }

    pub async fn insert_chat_picture(&self, chat_id: Uuid, file_name: &str) -> Result<ChatPicture> {
        let chat_picture = sqlx::query_as!(
            ChatPicture,
            "INSERT INTO chat_pictures
            (chat_id, file_name)
            VALUES ($1, $2)
            RETURNING id, chat_id, file_name, created_at, deleted_at, updated_at",
            chat_id,
            file_name
        )
        .fetch_one(&*self.pool)
        .await?;

        Ok(chat_picture)
    }

    pub async fn insert_company(&self, address: Option<String>, name: &str) -> Result<Company> {
        let company = sqlx::query_as!(
            Company,
            "INSERT INTO companies
            (address, name)
            VALUES ($1, $2)
            RETURNING id, address, name, created_at, deleted_at, updated_at",
            address,
            name
        )
        .fetch_one(&*self.pool)
        .await?;

        Ok(company)
    }

    pub async fn insert_example_prompt(
        &self,
        is_visible: bool,
        priority: i32,
        prompt: &str,
    ) -> Result<ExamplePrompt> {
        let example_prompt = sqlx::query_as!(
            ExamplePrompt,
            "INSERT INTO example_prompts
            (is_visible, priority, prompt)
            VALUES ($1, $2, $3)
            RETURNING id, is_visible, priority, prompt, created_at, deleted_at, updated_at",
            is_visible,
            priority,
            prompt
        )
        .fetch_one(&*self.pool)
        .await?;

        Ok(example_prompt)
    }

    pub async fn insert_password_reset_token(
        &self,
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
        .fetch_one(&*self.pool)
        .await?;

        Ok(password_reset_token)
    }

    pub async fn insert_profile(
        &self,
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
        .fetch_one(&*self.pool)
        .await?;

        Ok(profile)
    }

    pub async fn insert_session(
        &self,
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
        .fetch_one(&*self.pool)
        .await?;

        Ok(session)
    }

    pub async fn insert_user(
        &self,
        company_id: Uuid,
        email: &str,
        is_enabled: bool,
        pepper_id: i32,
        password: &str,
        roles: &[String],
    ) -> Result<User> {
        let user = sqlx::query_as!(
            User,
            "INSERT INTO users
            (company_id, email, is_enabled, pepper_id, password, roles)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (email) DO NOTHING
            RETURNING id, company_id, email, is_enabled, roles, created_at, deleted_at, updated_at",
            company_id,
            email,
            is_enabled,
            pepper_id,
            password,
            roles
        )
        .fetch_one(&*self.pool)
        .await?;

        Ok(user)
    }

    pub async fn insert_workspace(
        &self,
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
        .fetch_one(&*self.pool)
        .await?;

        Ok(workspace)
    }

    pub async fn try_delete_ai_function_by_id(&self, id: Uuid) -> Result<Option<Uuid>> {
        let ai_function = sqlx::query_scalar::<_, Uuid>(
            "UPDATE ai_functions
                SET deleted_at = current_timestamp(0)
                WHERE id = $1
                AND deleted_at IS NULL
                RETURNING id",
        )
        .bind(id)
        .fetch_optional(&*self.pool)
        .await?;

        Ok(ai_function)
    }

    pub async fn try_delete_chat_by_id(&self, id: Uuid) -> Result<Option<Uuid>> {
        let chat = sqlx::query_scalar::<_, Uuid>(
            "UPDATE chats
            SET deleted_at = current_timestamp(0)
            WHERE id = $1
            AND deleted_at IS NULL
            RETURNING id",
        )
        .bind(id)
        .fetch_optional(&*self.pool)
        .await?;

        Ok(chat)
    }

    pub async fn try_delete_chat_message_by_id(&self, id: Uuid) -> Result<Option<Uuid>> {
        let chat_message = sqlx::query_scalar::<_, Uuid>(
            "UPDATE chat_messages
                SET deleted_at = current_timestamp(0)
                WHERE id = $1
                AND deleted_at IS NULL
                RETURNING id",
        )
        .bind(id)
        .fetch_optional(&*self.pool)
        .await?;

        Ok(chat_message)
    }

    pub async fn try_delete_chat_messages_by_ids(&self, ids: &[Uuid]) -> Result<Vec<Uuid>> {
        let chat_message_ids = sqlx::query_scalar::<_, Uuid>(
            "UPDATE chat_messages
            SET deleted_at = current_timestamp(0)
            WHERE id = ANY($1)
            AND deleted_at IS NULL
            RETURNING id",
        )
        .bind(ids)
        .fetch_all(&*self.pool)
        .await?;

        Ok(chat_message_ids)
    }

    pub async fn try_delete_chat_message_file_by_id(&self, id: Uuid) -> Result<Option<Uuid>> {
        let chat_message_file = sqlx::query_scalar::<_, Uuid>(
            "UPDATE chat_message_files
            SET deleted_at = current_timestamp(0)
            WHERE id = $1
            AND deleted_at IS NULL
            RETURNING id",
        )
        .bind(id)
        .fetch_optional(&*self.pool)
        .await?;

        Ok(chat_message_file)
    }

    pub async fn try_delete_chat_message_picture_by_id(&self, id: Uuid) -> Result<Option<Uuid>> {
        let chat_message_picture = sqlx::query_scalar::<_, Uuid>(
            "UPDATE chat_message_pictures
            SET deleted_at = current_timestamp(0)
            WHERE id = $1
            AND deleted_at IS NULL
            RETURNING id",
        )
        .bind(id)
        .fetch_optional(&*self.pool)
        .await?;

        Ok(chat_message_picture)
    }

    pub async fn try_delete_chat_picture_by_id(&self, id: Uuid) -> Result<Option<Uuid>> {
        let chat_picture = sqlx::query_scalar::<_, Uuid>(
            "UPDATE chat_pictures
                SET deleted_at = current_timestamp(0)
                WHERE id = $1
                AND deleted_at IS NULL
                RETURNING id",
        )
        .bind(id)
        .fetch_optional(&*self.pool)
        .await?;

        Ok(chat_picture)
    }

    #[allow(dead_code)]
    pub async fn try_delete_company_by_id(&self, id: Uuid) -> Result<Option<Uuid>> {
        let company = sqlx::query_scalar::<_, Uuid>(
            "UPDATE companies
                SET deleted_at = current_timestamp(0)
                WHERE id = $1
                AND deleted_at IS NULL
                RETURNING id",
        )
        .bind(id)
        .fetch_optional(&*self.pool)
        .await?;

        Ok(company)
    }

    pub async fn try_delete_example_prompt_by_id(&self, id: Uuid) -> Result<Option<Uuid>> {
        let example_prompt = sqlx::query_scalar::<_, Uuid>(
            "UPDATE example_prompts
                SET deleted_at = current_timestamp(0)
                WHERE id = $1
                AND deleted_at IS NULL
                RETURNING id",
        )
        .bind(id)
        .fetch_optional(&*self.pool)
        .await?;

        Ok(example_prompt)
    }

    pub async fn try_delete_password_reset_token_by_id(&self, id: Uuid) -> Result<Option<Uuid>> {
        let password_reset_token = sqlx::query_scalar::<_, Uuid>(
            "UPDATE password_reset_tokens
                SET deleted_at = current_timestamp(0)
                WHERE id = $1
                AND deleted_at IS NULL
                RETURNING id",
        )
        .bind(id)
        .fetch_optional(&*self.pool)
        .await?;

        Ok(password_reset_token)
    }

    pub async fn try_delete_session_by_id(&self, id: Uuid) -> Result<Option<Uuid>> {
        let session = sqlx::query_scalar::<_, Uuid>(
            "DELETE FROM sessions
                WHERE id = $1
                RETURNING id",
        )
        .bind(id)
        .fetch_optional(&*self.pool)
        .await?;

        Ok(session)
    }

    #[allow(dead_code)]
    pub async fn try_delete_user_by_id(&self, id: Uuid) -> Result<Option<Uuid>> {
        let user = sqlx::query_scalar::<_, Uuid>(
            "UPDATE users
            SET deleted_at = current_timestamp(0)
            WHERE id = $1
            AND deleted_at IS NULL
            RETURNING id",
        )
        .bind(id)
        .fetch_optional(&*self.pool)
        .await?;

        Ok(user)
    }

    pub async fn try_delete_workspace_by_id(&self, id: Uuid) -> Result<Option<Uuid>> {
        let workspace = sqlx::query_scalar::<_, Uuid>(
            "UPDATE workspaces
                SET deleted_at = current_timestamp(0)
                WHERE id = $1
                AND deleted_at IS NULL
                RETURNING id",
        )
        .bind(id)
        .fetch_optional(&*self.pool)
        .await?;

        Ok(workspace)
    }

    pub async fn try_get_ai_function_by_id(&self, id: Uuid) -> Result<Option<AiFunction>> {
        let ai_function = sqlx::query_as!(
            AiFunction,
            r#"SELECT id, base_function_url, description, device_map, health_check_execution_time, health_check_status AS "health_check_status: _", health_check_url, is_available, is_enabled, k8s_configuration, name, parameters, setup_execution_time, setup_status AS "setup_status: _", setup_url, warmup_execution_time, warmup_status AS "warmup_status: _", created_at, deleted_at, health_check_at, setup_at, updated_at, warmup_at
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
            r#"SELECT id, base_function_url, description, device_map, health_check_execution_time, health_check_status AS "health_check_status: _", health_check_url, is_available, is_enabled, k8s_configuration, name, parameters, setup_execution_time, setup_status AS "setup_status: _", setup_url, warmup_execution_time, warmup_status AS "warmup_status: _", created_at, deleted_at, health_check_at, setup_at, updated_at, warmup_at
            FROM ai_functions
            WHERE name = $1
            AND deleted_at IS NULL"#,
            name
        )
        .fetch_optional(&*self.pool)
        .await?;

        Ok(ai_function)
    }

    pub async fn try_get_ai_function_id_by_id(&self, id: Uuid) -> Result<Option<Uuid>> {
        let ai_function_id = sqlx::query_scalar::<_, Uuid>(
            "SELECT id
            FROM ai_functions
            WHERE id = $1
            AND deleted_at IS NULL",
        )
        .bind(id)
        .fetch_optional(&*self.pool)
        .await?;

        Ok(ai_function_id)
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
            r#"SELECT id, ai_function_id, chat_id, user_id, bad_reply_comment, bad_reply_is_harmful, bad_reply_is_not_helpful, bad_reply_is_not_true, estimated_response_at, message, progress, response, status AS "status: _", created_at, deleted_at, updated_at
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
                let chat_message_extended = self
                    .map_to_chat_message_extended(
                        &chat_message,
                        chat_message_files,
                        chat_message_pictures,
                    )
                    .await?;

                Ok(Some(chat_message_extended))
            }
        }
    }

    pub async fn map_to_chat_message_extended(
        &self,
        chat_message: &ChatMessage,
        chat_message_files: Vec<ChatMessageFile>,
        chat_message_pictures: Vec<ChatMessagePicture>,
    ) -> Result<ChatMessageExtended> {
        let mut selected_chat_message_files = vec![];
        let mut selected_chat_message_pictures = vec![];
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

        let chat_message_extended = ChatMessageExtended {
            id: chat_message.id,
            ai_function_id: chat_message.ai_function_id,
            chat_id: chat_message.chat_id,
            user_id: chat_message.user_id,
            bad_reply_comment: chat_message.bad_reply_comment.clone(),
            bad_reply_is_harmful: chat_message.bad_reply_is_harmful,
            bad_reply_is_not_helpful: chat_message.bad_reply_is_not_helpful,
            bad_reply_is_not_true: chat_message.bad_reply_is_not_true,
            chat_message_files: selected_chat_message_files,
            chat_message_pictures: selected_chat_message_pictures,
            estimated_response_at: chat_message.estimated_response_at,
            message: chat_message.message.clone(),
            progress: chat_message.progress,
            response: chat_message.response.clone(),
            status: chat_message.status.clone(),
            created_at: chat_message.created_at,
            deleted_at: chat_message.deleted_at,
            updated_at: chat_message.updated_at,
        };

        Ok(chat_message_extended)
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
            "SELECT id, is_visible, priority, prompt, created_at, deleted_at, updated_at
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

    pub async fn try_get_user_by_email(&self, email: &str) -> Result<Option<User>> {
        let user = sqlx::query_as!(
            User,
            "SELECT id, company_id, email, is_enabled, roles, created_at, deleted_at, updated_at
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
            "SELECT id, company_id, email, is_enabled, roles, created_at, deleted_at, updated_at
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
        id: Uuid,
        base_function_url: &str,
        description: &str,
        device_map: serde_json::Value,
        health_check_url: &str,
        is_available: bool,
        is_enabled: bool,
        k8s_configuration: Option<String>,
        name: &str,
        parameters: serde_json::Value,
        setup_url: &str,
    ) -> Result<AiFunction> {
        let ai_function = sqlx::query_as!(
            AiFunction,
            r#"UPDATE ai_functions
            SET base_function_url = $2, description = $3, device_map = $4, health_check_url = $5, is_available = $6, is_enabled = $7, k8s_configuration = $8, name = $9, parameters = $10, setup_url = $11, updated_at = current_timestamp(0)
            WHERE id = $1
            RETURNING id, base_function_url, description, device_map, health_check_execution_time, health_check_status AS "health_check_status: _", health_check_url, is_available, is_enabled, k8s_configuration, name, parameters, setup_execution_time, setup_status AS "setup_status: _", setup_url, warmup_execution_time, warmup_status AS "warmup_status: _", created_at, deleted_at, health_check_at, setup_at, updated_at, warmup_at"#,
            id,
            base_function_url,
            description,
            device_map,
            health_check_url,
            is_available,
            is_enabled,
            k8s_configuration,
            name,
            parameters,
            setup_url,
        )
        .fetch_one(&*self.pool)
        .await?;

        Ok(ai_function)
    }

    pub async fn update_ai_function_setup_status(
        &self,
        id: Uuid,
        setup_execution_time: i32,
        setup_status: AiFunctionSetupStatus,
    ) -> Result<AiFunction> {
        let ai_function = sqlx::query_as::<_, AiFunction>(
            "UPDATE ai_functions
            SET setup_execution_time = $2, setup_status = $3, setup_at = current_timestamp(0), updated_at = current_timestamp(0)
            WHERE id = $1
            RETURNING id, base_function_url, description, device_map, health_check_execution_time, health_check_status, health_check_url, is_available, is_enabled, k8s_configuration, name, parameters, setup_execution_time, setup_status, setup_url, warmup_execution_time, warmup_status, created_at, deleted_at, health_check_at, setup_at, updated_at, warmup_at",
        )
        .bind(id)
        .bind(setup_execution_time)
        .bind(setup_status)
        .fetch_one(&*self.pool)
        .await?;

        Ok(ai_function)
    }

    pub async fn update_chat(&self, id: Uuid, name: &str) -> Result<Chat> {
        let chat = sqlx::query_as!(
            Chat,
            "UPDATE chats
            SET name = $2, updated_at = current_timestamp(0)
            WHERE id = $1
            RETURNING id, user_id, workspace_id, name, created_at, deleted_at, updated_at",
            id,
            name
        )
        .fetch_one(&*self.pool)
        .await?;

        Ok(chat)
    }

    pub async fn update_chat_message(
        &self,
        id: Uuid,
        progress: i32,
        response: &str,
        status: ChatMessageStatus,
    ) -> Result<ChatMessage> {
        let chat_message = sqlx::query_as::<_, ChatMessage>(
            "UPDATE chat_messages
            SET progress = $2, response = $3, status = $4, updated_at = current_timestamp(0)
            WHERE id = $1
            RETURNING id, ai_function_id, chat_id, user_id, bad_reply_comment, bad_reply_is_harmful, bad_reply_is_not_helpful, bad_reply_is_not_true, estimated_response_at, message, progress, response, status, created_at, deleted_at, updated_at",
        )
        .bind(id)
        .bind(progress)
        .bind(response)
        .bind(status)
        .fetch_one(&*self.pool)
        .await?;

        Ok(chat_message)
    }

    pub async fn update_chat_message_flag(
        &self,
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
            RETURNING id, ai_function_id, chat_id, user_id, bad_reply_comment, bad_reply_is_harmful, bad_reply_is_not_helpful, bad_reply_is_not_true, estimated_response_at, message, progress, response, status AS "status: _", created_at, deleted_at, updated_at"#,
            id,
            bad_reply_comment,
            bad_reply_is_harmful,
            bad_reply_is_not_helpful,
            bad_reply_is_not_true,
        )
        .fetch_one(&*self.pool)
        .await?;

        Ok(chat_message)
    }

    pub async fn update_chat_message_from_function(
        &self,
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
            RETURNING id, ai_function_id, chat_id, user_id, bad_reply_comment, bad_reply_is_harmful, bad_reply_is_not_helpful, bad_reply_is_not_true, estimated_response_at, message, progress, response, status, created_at, deleted_at, updated_at",
        )
        .bind(id)
        .bind(ai_function_id)
        .bind(status)
        .bind(progress)
        .bind(response)
        .fetch_one(&*self.pool)
        .await?;

        Ok(chat_message)
    }

    pub async fn update_chat_message_full(
        &self,
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
            RETURNING id, ai_function_id, chat_id, user_id, bad_reply_comment, bad_reply_is_harmful, bad_reply_is_not_helpful, bad_reply_is_not_true, estimated_response_at, message, progress, response, status, created_at, deleted_at, updated_at",
        )
        .bind(id)
        .bind(estimated_response_at)
        .bind(message)
        .bind(status)
        .bind(progress)
        .bind(response)
        .fetch_one(&*self.pool)
        .await?;

        Ok(chat_message)
    }

    pub async fn update_chat_message_picture(
        &self,
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
        .fetch_one(&*self.pool)
        .await?;

        Ok(chat_message_picture)
    }

    pub async fn update_chat_picture(&self, id: Uuid, file_name: &str) -> Result<ChatPicture> {
        let chat = sqlx::query_as!(
            ChatPicture,
            "UPDATE chat_pictures
            SET file_name = $2, updated_at = current_timestamp(0)
            WHERE id = $1
            RETURNING id, chat_id, file_name, created_at, deleted_at, updated_at",
            id,
            file_name
        )
        .fetch_one(&*self.pool)
        .await?;

        Ok(chat)
    }

    pub async fn update_example_prompt(
        &self,
        id: Uuid,
        is_visible: bool,
        priority: i32,
        prompt: &str,
    ) -> Result<ExamplePrompt> {
        let example_prompt = sqlx::query_as!(
            ExamplePrompt,
            "UPDATE example_prompts
            SET is_visible = $2, priority = $3, prompt = $4, updated_at = current_timestamp(0)
            WHERE id = $1
            RETURNING id, is_visible, priority, prompt, created_at, deleted_at, updated_at",
            id,
            is_visible,
            priority,
            prompt
        )
        .fetch_one(&*self.pool)
        .await?;

        Ok(example_prompt)
    }

    pub async fn update_profile(
        &self,
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
        .fetch_one(&*self.pool)
        .await?;

        Ok(profile)
    }

    pub async fn update_profile_photo_file_name(
        &self,
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
        .fetch_one(&*self.pool)
        .await?;

        Ok(profile)
    }

    pub async fn update_user_password(&self, id: Uuid, password: &str) -> Result<User> {
        let user = sqlx::query_as!(
            User,
            "UPDATE users
            SET password = $2, updated_at = current_timestamp(0)
            WHERE id = $1
            RETURNING id, company_id, email, is_enabled, roles, created_at, deleted_at, updated_at",
            id,
            password
        )
        .fetch_one(&*self.pool)
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
            RETURNING id, company_id, email, is_enabled, roles, created_at, deleted_at, updated_at",
            id,
            roles
        )
        .fetch_one(&*self.pool)
        .await?;

        Ok(user)
    }

    pub async fn update_workspace(
        &self,
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
        .fetch_one(&*self.pool)
        .await?;

        Ok(workspace)
    }
}
