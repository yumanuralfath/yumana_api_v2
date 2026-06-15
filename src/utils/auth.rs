use crate::utils::errors::{AppError, AppResult};
use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use uuid::Uuid;

pub fn generate_secure_token(_len: usize) -> String {
    Uuid::new_v4().simple().to_string()
}

pub fn hash_password(password: &str) -> AppResult<String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    argon2
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|_| AppError::InternalServerError)
}

pub fn verify_password(password: &str, hash: &str) -> AppResult<bool> {
    let parsed = PasswordHash::new(hash).map_err(|_| AppError::InternalServerError)?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}

pub async fn get_second_last_check(db: &sqlx::PgPool) -> AppResult<Option<time::OffsetDateTime>> {
    let result: Option<time::OffsetDateTime> = sqlx::query_scalar!(
        r#"
        SELECT checked_at 
        FROM health_checks 
        ORDER BY checked_at DESC 
        LIMIT 1 OFFSET 1
        "#
    )
    .fetch_optional(db) // Gunakan fetch_optional karena baris kedua mungkin tidak ada
    .await
    .map_err(AppError::DatabaseError)?
    .expect("yeagh");

    Ok(result)
}
