use crate::{
    entity::{Company, User},
    Result,
};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct OctopusDatabase {
    pool: PgPool,
}

impl OctopusDatabase {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
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
        .fetch_one(&self.pool)
        .await?;

        Ok(company)
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
        .fetch_one(&self.pool)
        .await?;

        Ok(user)
    }

    #[allow(dead_code)]
    pub async fn try_delete_company_by_id(&self, id: Uuid) -> Result<Option<Uuid>> {
        let company =
            sqlx::query_scalar::<_, Uuid>("DELETE FROM companies WHERE id = $1 RETURNING id")
                .bind(id)
                .fetch_optional(&self.pool)
                .await?;

        Ok(company)
    }

    pub async fn try_get_user_by_email(&self, email: &str) -> Result<Option<User>> {
        let user = sqlx::query_as!(
            User,
            "SELECT id, company_id, email, is_enabled, roles, created_at, updated_at
            FROM users
            WHERE email = $1",
            email
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(user)
    }
}
