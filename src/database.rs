use crate::{
    entity::{
        Chat, ChatMessage, ChatMessageFile, ChatMessageStatus, ChatPicture, Company,
        EstimatedSeconds, ExamplePrompt, Profile, Session, User, Workspace, WorkspacesType,
    },
    Result,
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

    pub async fn get_chats_by_workspace_id(&self, workspace_id: Uuid) -> Result<Vec<Chat>> {
        let chats = sqlx::query_as!(
            Chat,
            "SELECT id, user_id, workspace_id, name, created_at, updated_at
            FROM chats
            WHERE workspace_id = $1",
            workspace_id
        )
        .fetch_all(&*self.pool)
        .await?;

        Ok(chats)
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
            r#"SELECT id, chat_id, estimated_response_at, message, response, status AS "status: _", created_at, updated_at
            FROM chat_messages
            WHERE chat_id = $1
            ORDER BY created_at ASC"#,
            chat_id
        )
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
            "SELECT id, chat_message_id, file_name, created_at
            FROM chat_message_files
            WHERE chat_message_id = $1
            ORDER BY created_at ASC",
            chat_message_id
        )
        .fetch_all(&*self.pool)
        .await?;

        Ok(chat_message_files)
    }

    pub async fn get_example_prompts(&self) -> Result<Vec<ExamplePrompt>> {
        let example_prompts = sqlx::query_as!(
            ExamplePrompt,
            "SELECT id, is_visible, priority, prompt, created_at, updated_at
            FROM example_prompts"
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
            "SELECT id, company_id, user_id, name, type, created_at, updated_at
            FROM workspaces
            WHERE company_id = $1
            AND type = $2",
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
            "SELECT id, company_id, user_id, name, type, created_at, updated_at
            FROM workspaces
            WHERE user_id = $1
            AND type = $2",
        )
        .bind(user_id)
        .bind(r#type)
        .fetch_all(&*self.pool)
        .await?;

        Ok(workspaces)
    }

    pub async fn insert_chat(&self, user_id: Uuid, workspace_id: Uuid) -> Result<Chat> {
        let chat = sqlx::query_as!(
            Chat,
            "INSERT INTO chats
            (user_id, workspace_id)
            VALUES ($1, $2)
            RETURNING id, user_id, workspace_id, name, created_at, updated_at",
            user_id,
            workspace_id
        )
        .fetch_one(&*self.pool)
        .await?;

        Ok(chat)
    }

    pub async fn insert_chat_message(
        &self,
        chat_id: Uuid,
        estimated_response_at: DateTime<Utc>,
        message: &str,
    ) -> Result<ChatMessage> {
        let chat_message = sqlx::query_as!(
            ChatMessage,
            r#"INSERT INTO chat_messages
            (chat_id, estimated_response_at, message)
            VALUES ($1, $2, $3)
            RETURNING id, chat_id, estimated_response_at, message, response, status AS "status: _", created_at, updated_at"#,
            chat_id,
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
    ) -> Result<ChatMessageFile> {
        let chat_message_file = sqlx::query_as!(
            ChatMessageFile,
            "INSERT INTO chat_message_files
            (chat_message_id, file_name)
            VALUES ($1, $2)
            RETURNING id, chat_message_id, file_name, created_at",
            chat_message_id,
            file_name,
        )
        .fetch_one(&*self.pool)
        .await?;

        Ok(chat_message_file)
    }

    pub async fn insert_chat_picture(&self, chat_id: Uuid, file_name: &str) -> Result<ChatPicture> {
        let chat_picture = sqlx::query_as!(
            ChatPicture,
            "INSERT INTO chat_pictures
            (chat_id, file_name)
            VALUES ($1, $2)
            RETURNING id, chat_id, file_name, created_at, updated_at",
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
            RETURNING id, address, name, created_at, updated_at",
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
            RETURNING id, is_visible, priority, prompt, created_at, updated_at",
            is_visible,
            priority,
            prompt
        )
        .fetch_one(&*self.pool)
        .await?;

        Ok(example_prompt)
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
            RETURNING id, user_id, job_title, language, name, photo_file_name, text_size, created_at, updated_at",
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
            RETURNING id, company_id, email, is_enabled, roles, created_at, updated_at",
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
            RETURNING id, company_id, user_id, name, type, created_at, updated_at",
        )
        .bind(company_id)
        .bind(user_id)
        .bind(name)
        .bind(r#type)
        .fetch_one(&*self.pool)
        .await?;

        Ok(workspace)
    }

    pub async fn try_delete_chat_by_id(&self, id: Uuid) -> Result<Option<Uuid>> {
        let chat = sqlx::query_scalar::<_, Uuid>("DELETE FROM chats WHERE id = $1 RETURNING id")
            .bind(id)
            .fetch_optional(&*self.pool)
            .await?;

        Ok(chat)
    }

    pub async fn try_delete_chat_message_by_id(&self, id: Uuid) -> Result<Option<Uuid>> {
        let chat_message =
            sqlx::query_scalar::<_, Uuid>("DELETE FROM chat_messages WHERE id = $1 RETURNING id")
                .bind(id)
                .fetch_optional(&*self.pool)
                .await?;

        Ok(chat_message)
    }

    pub async fn try_delete_chat_message_file_by_id(&self, id: Uuid) -> Result<Option<Uuid>> {
        let chat_message_file = sqlx::query_scalar::<_, Uuid>(
            "DELETE FROM chat_message_files WHERE id = $1 RETURNING id",
        )
        .bind(id)
        .fetch_optional(&*self.pool)
        .await?;

        Ok(chat_message_file)
    }

    pub async fn try_delete_chat_picture_by_id(&self, id: Uuid) -> Result<Option<Uuid>> {
        let chat_picture =
            sqlx::query_scalar::<_, Uuid>("DELETE FROM chat_pictures WHERE id = $1 RETURNING id")
                .bind(id)
                .fetch_optional(&*self.pool)
                .await?;

        Ok(chat_picture)
    }

    #[allow(dead_code)]
    pub async fn try_delete_company_by_id(&self, id: Uuid) -> Result<Option<Uuid>> {
        let company =
            sqlx::query_scalar::<_, Uuid>("DELETE FROM companies WHERE id = $1 RETURNING id")
                .bind(id)
                .fetch_optional(&*self.pool)
                .await?;

        Ok(company)
    }

    pub async fn try_delete_example_prompt_by_id(&self, id: Uuid) -> Result<Option<Uuid>> {
        let example_prompt =
            sqlx::query_scalar::<_, Uuid>("DELETE FROM example_prompts WHERE id = $1 RETURNING id")
                .bind(id)
                .fetch_optional(&*self.pool)
                .await?;

        Ok(example_prompt)
    }

    pub async fn try_delete_session_by_id(&self, id: Uuid) -> Result<Option<Uuid>> {
        let session =
            sqlx::query_scalar::<_, Uuid>("DELETE FROM sessions WHERE id = $1 RETURNING id")
                .bind(id)
                .fetch_optional(&*self.pool)
                .await?;

        Ok(session)
    }

    #[allow(dead_code)]
    pub async fn try_delete_user_by_id(&self, id: Uuid) -> Result<Option<Uuid>> {
        let user = sqlx::query_scalar::<_, Uuid>("DELETE FROM users WHERE id = $1 RETURNING id")
            .bind(id)
            .fetch_optional(&*self.pool)
            .await?;

        Ok(user)
    }

    pub async fn try_delete_workspace_by_id(&self, id: Uuid) -> Result<Option<Uuid>> {
        let workspace =
            sqlx::query_scalar::<_, Uuid>("DELETE FROM workspaces WHERE id = $1 RETURNING id")
                .bind(id)
                .fetch_optional(&*self.pool)
                .await?;

        Ok(workspace)
    }

    pub async fn try_get_hash_for_email(&self, email: &str) -> Result<Option<String>> {
        let hash = sqlx::query_scalar::<_, String>("SELECT password FROM users WHERE email = $1")
            .bind(email)
            .fetch_optional(&*self.pool)
            .await?;

        Ok(hash)
    }

    pub async fn try_get_chat_by_id(&self, id: Uuid) -> Result<Option<Chat>> {
        let chat = sqlx::query_as!(
            Chat,
            "SELECT id, user_id, workspace_id, name, created_at, updated_at
            FROM chats
            WHERE id = $1",
            id
        )
        .fetch_optional(&*self.pool)
        .await?;

        Ok(chat)
    }

    pub async fn try_get_chat_message_by_id(&self, id: Uuid) -> Result<Option<ChatMessage>> {
        let chat_message = sqlx::query_as!(
            ChatMessage,
            r#"SELECT id, chat_id, estimated_response_at, message, response, status AS "status: _", created_at, updated_at
            FROM chat_messages
            WHERE id = $1"#,
            id
        )
        .fetch_optional(&*self.pool)
        .await?;

        Ok(chat_message)
    }

    pub async fn try_get_chat_message_file_by_id(
        &self,
        id: Uuid,
    ) -> Result<Option<ChatMessageFile>> {
        let chat_message_file = sqlx::query_as!(
            ChatMessageFile,
            "SELECT id, chat_message_id, file_name, created_at
            FROM chat_message_files
            WHERE id = $1",
            id
        )
        .fetch_optional(&*self.pool)
        .await?;

        Ok(chat_message_file)
    }

    pub async fn try_get_chat_picture_by_chat_id(
        &self,
        chat_id: Uuid,
    ) -> Result<Option<ChatPicture>> {
        let chat_picture = sqlx::query_as!(
            ChatPicture,
            "SELECT id, chat_id, file_name, created_at, updated_at
            FROM chat_pictures
            WHERE chat_id = $1",
            chat_id
        )
        .fetch_optional(&*self.pool)
        .await?;

        Ok(chat_picture)
    }

    pub async fn try_get_chat_picture_by_id(&self, id: Uuid) -> Result<Option<ChatPicture>> {
        let chat_picture = sqlx::query_as!(
            ChatPicture,
            "SELECT id, chat_id, file_name, created_at, updated_at
            FROM chat_pictures
            WHERE id = $1",
            id
        )
        .fetch_optional(&*self.pool)
        .await?;

        Ok(chat_picture)
    }

    pub async fn try_get_company_primary(&self) -> Result<Option<Company>> {
        let company = sqlx::query_as!(
            Company,
            "SELECT id, address, name, created_at, updated_at
            FROM companies
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
            "SELECT id, is_visible, priority, prompt, created_at, updated_at
            FROM example_prompts
            WHERE id = $1",
            id
        )
        .fetch_optional(&*self.pool)
        .await?;

        Ok(example_prompt)
    }

    pub async fn try_get_example_prompt_id_by_id(&self, id: Uuid) -> Result<Option<Uuid>> {
        let example_prompt_id =
            sqlx::query_scalar::<_, Uuid>("SELECT id FROM example_prompts WHERE id = $1")
                .bind(id)
                .fetch_optional(&*self.pool)
                .await?;

        Ok(example_prompt_id)
    }

    pub async fn try_get_profile_by_user_id(&self, user_id: Uuid) -> Result<Option<Profile>> {
        let profile = sqlx::query_as!(
            Profile,
            "SELECT id, user_id, job_title, language, name, photo_file_name, text_size, created_at, updated_at
            FROM profiles
            WHERE user_id = $1",
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
            "SELECT id, company_id, email, is_enabled, roles, created_at, updated_at
            FROM users
            WHERE email = $1",
            email
        )
        .fetch_optional(&*self.pool)
        .await?;

        Ok(user)
    }

    pub async fn try_get_user_by_id(&self, id: Uuid) -> Result<Option<User>> {
        let user = sqlx::query_as!(
            User,
            "SELECT id, company_id, email, is_enabled, roles, created_at, updated_at
            FROM users
            WHERE id = $1",
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
            r#"SELECT id, company_id, user_id, name, type AS "type: _", created_at, updated_at
            FROM workspaces
            WHERE id = $1"#,
            id
        )
        .fetch_optional(&*self.pool)
        .await?;

        Ok(workspace)
    }

    pub async fn update_chat(&self, id: Uuid, name: &str) -> Result<Chat> {
        let chat = sqlx::query_as!(
            Chat,
            "UPDATE chats
            SET name = $2, updated_at = current_timestamp(0)
            WHERE id = $1
            RETURNING id, user_id, workspace_id, name, created_at, updated_at",
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
        response: &str,
        status: ChatMessageStatus,
    ) -> Result<ChatMessage> {
        let chat_message = sqlx::query_as::<_, ChatMessage>(
            "UPDATE chat_messages
            SET response = $2, status = $3, updated_at = current_timestamp(0)
            WHERE id = $1
            RETURNING id, chat_id, estimated_response_at, message, response, status, created_at, updated_at",
        )
        .bind(id)
        .bind(response)
        .bind(status)
        .fetch_one(&*self.pool)
        .await?;
        /*
                let chat_message = sqlx::query_as!(
                    ChatMessage,
                    r#"UPDATE chat_messages
                    SET response = $2, status = $3, updated_at = current_timestamp(0)
                    WHERE id = $1
                    RETURNING id, chat_id, estimated_response_at, message, response, status AS "status: _", created_at, updated_at"#,
                    id,
                    response,
                    status
                )
                .fetch_one(&*self.pool)
                .await?;
        */
        Ok(chat_message)
    }

    pub async fn update_chat_message_full(
        &self,
        id: Uuid,
        estimated_response_at: DateTime<Utc>,
        message: &str,
        status: ChatMessageStatus,
        response: Option<String>,
    ) -> Result<ChatMessage> {
        let chat_message = sqlx::query_as::<_, ChatMessage>(
            "UPDATE chat_messages
            SET estimated_response_at = $2, message = $3, status = $4, response = $5, created_at = current_timestamp(0), updated_at = current_timestamp(0)
            WHERE id = $1
            RETURNING id, chat_id, estimated_response_at, message, response, status, created_at, updated_at",
        )
        .bind(id)
        .bind(estimated_response_at)
        .bind(message)
        .bind(status)
        .bind(response)
        .fetch_one(&*self.pool)
        .await?;

        Ok(chat_message)
    }

    pub async fn update_chat_picture(&self, id: Uuid, file_name: &str) -> Result<ChatPicture> {
        let chat = sqlx::query_as!(
            ChatPicture,
            "UPDATE chat_pictures
            SET file_name = $2, updated_at = current_timestamp(0)
            WHERE id = $1
            RETURNING id, chat_id, file_name, created_at, updated_at",
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
            RETURNING id, is_visible, priority, prompt, created_at, updated_at",
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
            RETURNING id, user_id, job_title, language, name, photo_file_name, text_size, created_at, updated_at",
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

    #[allow(dead_code)]
    pub async fn update_user_roles(&self, id: Uuid, roles: &[String]) -> Result<User> {
        let user = sqlx::query_as!(
            User,
            "UPDATE users
            SET roles = $2, updated_at = current_timestamp(0)
            WHERE id = $1
            RETURNING id, company_id, email, is_enabled, roles, created_at, updated_at",
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
            RETURNING id, company_id, user_id, name, type, created_at, updated_at",
        )
        .bind(id)
        .bind(name)
        .bind(r#type)
        .fetch_one(&*self.pool)
        .await?;

        Ok(workspace)
    }
}
