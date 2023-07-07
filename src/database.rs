use crate::{
    entity::{Chat, ChatPicture, Company, ExamplePrompt, Session, User},
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

    pub async fn get_chats_by_user_id(&self, user_id: Uuid) -> Result<Vec<Chat>> {
        let chats = sqlx::query_as!(
            Chat,
            "SELECT id, user_id, name, created_at, updated_at
            FROM chats
            WHERE user_id = $1",
            user_id
        )
        .fetch_all(&*self.pool)
        .await?;

        Ok(chats)
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

    pub async fn insert_chat(&self, user_id: Uuid) -> Result<Chat> {
        let chat = sqlx::query_as!(
            Chat,
            "INSERT INTO chats
            (user_id)
            VALUES ($1)
            RETURNING id, user_id, name, created_at, updated_at",
            user_id
        )
        .fetch_one(&*self.pool)
        .await?;

        Ok(chat)
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

    pub async fn try_delete_chat_by_id(&self, id: Uuid) -> Result<Option<Uuid>> {
        let chat = sqlx::query_scalar::<_, Uuid>("DELETE FROM chats WHERE id = $1 RETURNING id")
            .bind(id)
            .fetch_optional(&*self.pool)
            .await?;

        Ok(chat)
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
            "SELECT id, user_id, name, created_at, updated_at
            FROM chats
            WHERE id = $1",
            id
        )
        .fetch_optional(&*self.pool)
        .await?;

        Ok(chat)
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

    pub async fn try_get_user_roles_by_id(&self, id: Uuid) -> Result<Option<Vec<String>>> {
        let user_roles =
            sqlx::query_scalar::<_, Vec<String>>("SELECT roles FROM users WHERE id = $1")
                .bind(id)
                .fetch_optional(&*self.pool)
                .await?;

        Ok(user_roles)
    }

    pub async fn update_chat(&self, id: Uuid, name: &str) -> Result<Chat> {
        let chat = sqlx::query_as!(
            Chat,
            "UPDATE chats
            SET name = $2, updated_at = current_timestamp(0)
            WHERE id = $1
            RETURNING id, user_id, name, created_at, updated_at",
            id,
            name
        )
        .fetch_one(&*self.pool)
        .await?;

        Ok(chat)
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
}
