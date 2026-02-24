use argon2::{
    Argon2,
    password_hash::{PasswordHasher, SaltString, rand_core::OsRng},
};
use sqlx::PgPool;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

pub struct CreatedUser {
    pub id: Uuid,
    pub email: String,
    pub username: String,
    pub password: String, // plaintext, untuk login
}

pub struct CreatedAdmin {
    pub id: Uuid,
    pub email: String,
    pub username: String,
    pub password: String,
}

fn hash_pw(password: &str) -> String {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .unwrap()
        .to_string()
}

/// Insert user biasa yang sudah terverifikasi
pub async fn create_verified_user(pool: &PgPool) -> CreatedUser {
    let email = format!(
        "user_{}@test.com",
        Uuid::new_v4().to_string().split('-').next().unwrap()
    );
    let username = format!(
        "user_{}",
        Uuid::new_v4().to_string().split('-').next().unwrap()
    );
    let password = "Password123!".to_string();
    let hash = hash_pw(&password);

    let row: (Uuid,) = sqlx::query_as(
        "INSERT INTO users (email, username, password_hash, is_verified)
         VALUES ($1, $2, $3, true)
         RETURNING id",
    )
    .bind(&email)
    .bind(&username)
    .bind(&hash)
    .fetch_one(pool)
    .await
    .expect("Gagal insert verified user");

    CreatedUser {
        id: row.0,
        email,
        username,
        password,
    }
}

/// Insert user yang belum diverifikasi
pub async fn create_unverified_user(pool: &PgPool) -> CreatedUser {
    let email = format!(
        "unverified_{}@test.com",
        Uuid::new_v4().to_string().split('-').next().unwrap()
    );
    let username = format!(
        "unverified_{}",
        Uuid::new_v4().to_string().split('-').next().unwrap()
    );
    let password = "Password123!".to_string();
    let hash = hash_pw(&password);

    let row: (Uuid,) = sqlx::query_as(
        "INSERT INTO users (email, username, password_hash, is_verified)
         VALUES ($1, $2, $3, false)
         RETURNING id",
    )
    .bind(&email)
    .bind(&username)
    .bind(&hash)
    .fetch_one(pool)
    .await
    .expect("Gagal insert unverified user");

    CreatedUser {
        id: row.0,
        email,
        username,
        password,
    }
}

/// Insert user yang dinonaktifkan admin
pub async fn create_inactive_user(pool: &PgPool) -> CreatedUser {
    let email = format!(
        "inactive_{}@test.com",
        Uuid::new_v4().to_string().split('-').next().unwrap()
    );
    let username = format!(
        "inactive_{}",
        Uuid::new_v4().to_string().split('-').next().unwrap()
    );
    let password = "Password123!".to_string();
    let hash = hash_pw(&password);

    let row: (Uuid,) = sqlx::query_as(
        "INSERT INTO users (email, username, password_hash, is_verified, is_active)
         VALUES ($1, $2, $3, true, false)
         RETURNING id",
    )
    .bind(&email)
    .bind(&username)
    .bind(&hash)
    .fetch_one(pool)
    .await
    .expect("Gagal insert inactive user");

    CreatedUser {
        id: row.0,
        email,
        username,
        password,
    }
}

/// Insert admin yang sudah terverifikasi
pub async fn create_admin_user(pool: &PgPool) -> CreatedAdmin {
    let email = format!(
        "admin_{}@test.com",
        Uuid::new_v4().to_string().split('-').next().unwrap()
    );
    let username = format!(
        "admin_{}",
        Uuid::new_v4().to_string().split('-').next().unwrap()
    );
    let password = "AdminPass123!".to_string();
    let hash = hash_pw(&password);

    let row: (Uuid,) = sqlx::query_as::<_, (Uuid,)>(
        "INSERT INTO users (email, username, password_hash, role, is_verified)
     VALUES ($1, $2, $3, 'admin', true)
     RETURNING id",
    )
    .bind(&email)
    .bind(&username)
    .bind(&hash)
    .fetch_one(pool)
    .await
    .expect("Gagal insert admin user");

    CreatedAdmin {
        id: row.0,
        email,
        username,
        password,
    }
}

/// Insert email verification token (valid, belum dipakai)
pub async fn create_verification_token(pool: &PgPool, user_id: Uuid) -> String {
    let token = format!(
        "verif_token_{}",
        Uuid::new_v4().to_string().replace('-', "")
    );
    let expires_at = OffsetDateTime::now_utc() + Duration::hours(24);

    sqlx::query("INSERT INTO email_verifications (user_id, token, expires_at) VALUES ($1, $2, $3)")
        .bind(user_id)
        .bind(&token)
        .bind(expires_at)
        .execute(pool)
        .await
        .expect("Gagal insert verification token");

    token
}

/// Insert verification token yang sudah expired
pub async fn create_expired_verification_token(pool: &PgPool, user_id: Uuid) -> String {
    let token = format!(
        "expired_verif_{}",
        Uuid::new_v4().to_string().replace('-', "")
    );
    let expires_at = OffsetDateTime::now_utc() - Duration::hours(1); // sudah lewat

    sqlx::query("INSERT INTO email_verifications (user_id, token, expires_at) VALUES ($1, $2, $3)")
        .bind(user_id)
        .bind(&token)
        .bind(expires_at)
        .execute(pool)
        .await
        .expect("Gagal insert expired token");

    token
}

/// Insert password reset token (valid)
pub async fn create_reset_token(pool: &PgPool, user_id: Uuid) -> String {
    let token = format!(
        "reset_token_{}",
        Uuid::new_v4().to_string().replace('-', "")
    );
    let expires_at = OffsetDateTime::now_utc() + Duration::hours(1);

    sqlx::query("INSERT INTO password_resets (user_id, token, expires_at) VALUES ($1, $2, $3)")
        .bind(user_id)
        .bind(&token)
        .bind(expires_at)
        .execute(pool)
        .await
        .expect("Gagal insert reset token");

    token
}

/// Insert refresh token aktif ke DB
pub async fn create_refresh_token(pool: &PgPool, user_id: Uuid, token: &str) {
    let expires_at = OffsetDateTime::now_utc() + Duration::days(7);

    sqlx::query("INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES ($1, $2, $3)")
        .bind(user_id)
        .bind(token)
        .bind(expires_at)
        .execute(pool)
        .await
        .expect("Gagal insert refresh token");
}
