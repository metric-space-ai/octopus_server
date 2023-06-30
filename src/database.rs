use sqlx::PgPool;

#[derive(Clone, Debug)]
pub struct OctopusDatabase {
    pool: PgPool,
}

impl OctopusDatabase {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}
