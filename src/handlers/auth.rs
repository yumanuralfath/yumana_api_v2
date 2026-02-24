use axum::extract::Query;
use axum::{Json, extract::State};
use rand::RngExt;
use rand::distr::Alphanumeric;
use rand::rng;
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;
use validator::Validate;

use crate::{
    config::state::AppState,
    middleware::auth::CurrentUser,
    models::user::UserResponse,
    utils::{
        errors::{AppError, AppResult},
        response::{success, success_message},
    },
};
use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};

// ─── Request / Response DTOs ──────────────────────────────────────────────

#[derive(Debug, Deserialize, Validate)]
pub struct RegisterRequest {
    #[validate(length(min = 3, max = 50))]
    pub username: String,
    #[validate(email)]
    pub email: String,
    #[validate(length(min = 8, max = 128))]
    pub password: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

#[derive(Debug, Deserialize)]
pub struct VerifyEmailQuery {
    pub token: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct ForgotPasswordRequest {
    #[validate(email)]
    pub email: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct ResetPasswordRequest {
    pub token: String,
    #[validate(length(min = 8, max = 128))]
    pub new_password: String,
}

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub user: UserResponse,
}

// ─── Helpers ──────────────────────────────────────────────────────────────
fn generate_secure_token(len: usize) -> String {
    rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect()
}

fn hash_password(password: &str) -> AppResult<String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    argon2
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|_| AppError::InternalServerError)
}

fn verify_password(password: &str, hash: &str) -> AppResult<bool> {
    let parsed = PasswordHash::new(hash).map_err(|_| AppError::InternalServerError)?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}

// ─── Handlers ─────────────────────────────────────────────────────────────

/// POST /api/auth/register
pub async fn register(
    State(state): State<AppState>,
    Json(body): Json<RegisterRequest>,
) -> AppResult<impl axum::response::IntoResponse> {
    // Validate input
    body.validate()
        .map_err(|e| AppError::BadRequest(e.to_string()))?;

    // Check email exists
    let email_exists: bool = sqlx::query_scalar!(
        "SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)",
        body.email.to_lowercase()
    )
    .fetch_one(&state.db)
    .await?
    .unwrap_or(false);

    if email_exists {
        return Err(AppError::Conflict("Email already registered".to_string()));
    }

    // Check username exists
    let username_exists: bool = sqlx::query_scalar!(
        "SELECT EXISTS(SELECT 1 FROM users WHERE username = $1)",
        body.username.to_lowercase()
    )
    .fetch_one(&state.db)
    .await?
    .unwrap_or(false);

    if username_exists {
        return Err(AppError::Conflict("Username already taken".to_string()));
    }

    // Hash password
    let password_hash = hash_password(&body.password)?;

    // Create user
    let user = sqlx::query_as!(
        crate::models::user::User,
        r#"INSERT INTO users (email, username, password_hash)
           VALUES ($1, $2, $3)
           RETURNING id, email, username, password_hash,
                     role as "role: _", is_verified, is_active, created_at, updated_at"#,
        body.email.to_lowercase(),
        body.username.to_lowercase(),
        password_hash
    )
    .fetch_one(&state.db)
    .await?;

    // Create verification token (expires 24h)
    let token = generate_secure_token(64);
    let expires_at = OffsetDateTime::now_utc() + Duration::hours(24);

    sqlx::query!(
        "INSERT INTO email_verifications (user_id, token, expires_at) VALUES ($1, $2, $3)",
        user.id,
        token,
        expires_at
    )
    .execute(&state.db)
    .await?;

    // Send verification email (non-blocking, don't fail if email fails)
    let email_service = state.email.clone();
    let email = user.email.clone();
    let username = user.username.clone();
    let tkn = token.clone();
    tokio::spawn(async move {
        if let Err(e) = email_service
            .send_verification_email(&email, &username, &tkn)
            .await
        {
            tracing::error!("Failed to send verification email: {:?}", e);
        }
    });

    Ok(success(serde_json::json!({
        "message": "Registration successful! Please check your email to verify your account.",
        "user": UserResponse::from(user)
    })))
}

/// GET /api/auth/verify-email?token=xxx
pub async fn verify_email(
    State(state): State<AppState>,
    Query(query): Query<VerifyEmailQuery>,
) -> AppResult<impl axum::response::IntoResponse> {
    let now = OffsetDateTime::now_utc();

    // Find valid token
    let record = sqlx::query!(
        "SELECT id, user_id, expires_at, used_at FROM email_verifications
         WHERE token = $1",
        query.token
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::BadRequest("Invalid verification token".to_string()))?;

    if record.used_at.is_some() {
        return Err(AppError::BadRequest("Token already used".to_string()));
    }

    if record.expires_at < now {
        return Err(AppError::BadRequest(
            "Verification token expired".to_string(),
        ));
    }

    // Mark token as used + verify user
    let mut tx = state.db.begin().await?;

    sqlx::query!(
        "UPDATE email_verifications SET used_at = NOW() WHERE id = $1",
        record.id
    )
    .execute(&mut *tx)
    .await?;

    sqlx::query!(
        "UPDATE users SET is_verified = true WHERE id = $1",
        record.user_id
    )
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok(success_message(
        "Email verified successfully! You can now login.",
    ))
}

/// POST /api/auth/login
pub async fn login(
    State(state): State<AppState>,
    Json(body): Json<LoginRequest>,
) -> AppResult<impl axum::response::IntoResponse> {
    // Find user
    let user = sqlx::query_as::<_, crate::models::user::User>(
        r#"SELECT id, email, username, password_hash,
              role, is_verified, is_active, created_at, updated_at
       FROM users WHERE email = $1"#,
    )
    .bind(body.email.to_lowercase())
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::Unauthorized("Invalid email or password".to_string()))?;

    if !user.is_active {
        return Err(AppError::Forbidden("Account is deactivated".to_string()));
    }

    if !verify_password(&body.password, &user.password_hash)? {
        return Err(AppError::Unauthorized(
            "Invalid email or password".to_string(),
        ));
    }

    if !user.is_verified {
        return Err(AppError::Forbidden(
            "Please verify your email before logging in".to_string(),
        ));
    }

    // Generate tokens
    let access_token =
        state
            .jwt
            .generate_access_token(user.id, &user.email, &user.username, &user.role)?;

    let jti = Uuid::new_v4().to_string();
    let refresh_token_str = state.jwt.generate_refresh_token(user.id, &jti)?;

    // Store refresh token in DB
    let expires_at = OffsetDateTime::now_utc() + Duration::seconds(state.config.jwt_refresh_expiry);

    sqlx::query("INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES ($1, $2, $3)")
        .bind(user.id)
        .bind(&refresh_token_str)
        .bind(expires_at)
        .execute(&state.db)
        .await?;

    Ok(success(AuthResponse {
        access_token,
        refresh_token: refresh_token_str,
        token_type: "Bearer".to_string(),
        expires_in: state.config.jwt_access_expiry,
        user: UserResponse::from(user),
    }))
}

/// POST /api/auth/refresh
pub async fn refresh_token(
    State(state): State<AppState>,
    Json(body): Json<RefreshRequest>,
) -> AppResult<impl axum::response::IntoResponse> {
    // Verify JWT signature
    let claims = state.jwt.verify_refresh_token(&body.refresh_token)?;

    // Check if token exists and not revoked
    let stored = sqlx::query!(
        "SELECT id, user_id, expires_at, revoked_at FROM refresh_tokens WHERE token = $1",
        body.refresh_token
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::Unauthorized("Refresh token not found".to_string()))?;

    if stored.revoked_at.is_some() {
        return Err(AppError::Unauthorized("Refresh token revoked".to_string()));
    }

    if stored.expires_at < OffsetDateTime::now_utc() {
        return Err(AppError::Unauthorized("Refresh token expired".to_string()));
    }

    // Get user
    let user_id: Uuid = claims
        .sub
        .parse()
        .map_err(|_| AppError::Unauthorized("Invalid token".to_string()))?;
    let user = sqlx::query_as!(
        crate::models::user::User,
        r#"SELECT id, email, username, password_hash,
                  role as "role: _", is_verified, is_active, created_at, updated_at
           FROM users WHERE id = $1"#,
        user_id
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::Unauthorized("User not found".to_string()))?;

    if !user.is_active {
        return Err(AppError::Forbidden("Account is deactivated".to_string()));
    }

    // Rotate: revoke old token, issue new pair
    let mut tx = state.db.begin().await?;

    sqlx::query!(
        "UPDATE refresh_tokens SET revoked_at = NOW() WHERE id = $1",
        stored.id
    )
    .execute(&mut *tx)
    .await?;

    let new_access =
        state
            .jwt
            .generate_access_token(user.id, &user.email, &user.username, &user.role)?;
    let new_jti = Uuid::new_v4().to_string();
    let new_refresh = state.jwt.generate_refresh_token(user.id, &new_jti)?;
    let expires_at = OffsetDateTime::now_utc() + Duration::seconds(state.config.jwt_refresh_expiry);

    sqlx::query!(
        "INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES ($1, $2, $3)",
        user.id,
        new_refresh,
        expires_at
    )
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok(success(AuthResponse {
        access_token: new_access,
        refresh_token: new_refresh,
        token_type: "Bearer".to_string(),
        expires_in: state.config.jwt_access_expiry,
        user: UserResponse::from(user),
    }))
}

/// POST /api/auth/logout
pub async fn logout(
    State(state): State<AppState>,
    Json(body): Json<RefreshRequest>,
) -> AppResult<impl axum::response::IntoResponse> {
    sqlx::query!(
        "UPDATE refresh_tokens SET revoked_at = NOW() WHERE token = $1",
        body.refresh_token
    )
    .execute(&state.db)
    .await?;

    Ok(success_message("Logged out successfully"))
}

/// POST /api/auth/forgot-password
pub async fn forgot_password(
    State(state): State<AppState>,
    Json(body): Json<ForgotPasswordRequest>,
) -> AppResult<impl axum::response::IntoResponse> {
    body.validate()
        .map_err(|e| AppError::BadRequest(e.to_string()))?;

    // Always return success to prevent email enumeration
    let user = sqlx::query_as!(
        crate::models::user::User,
        r#"SELECT id, email, username, password_hash,
                  role as "role: _", is_verified, is_active, created_at, updated_at
           FROM users WHERE email = $1 AND is_active = true"#,
        body.email.to_lowercase()
    )
    .fetch_optional(&state.db)
    .await?;

    if let Some(user) = user {
        let token = generate_secure_token(64);
        let expires_at = OffsetDateTime::now_utc() + Duration::hours(1);

        sqlx::query!(
            "INSERT INTO password_resets (user_id, token, expires_at) VALUES ($1, $2, $3)",
            user.id,
            token,
            expires_at
        )
        .execute(&state.db)
        .await?;

        let email_service = state.email.clone();
        let email = user.email.clone();
        let username = user.username.clone();
        tokio::spawn(async move {
            if let Err(e) = email_service
                .send_password_reset_email(&email, &username, &token)
                .await
            {
                tracing::error!("Failed to send reset email: {:?}", e);
            }
        });
    }

    Ok(success_message(
        "If that email exists, you will receive a reset link shortly.",
    ))
}

/// POST /api/auth/reset-password
pub async fn reset_password(
    State(state): State<AppState>,
    Json(body): Json<ResetPasswordRequest>,
) -> AppResult<impl axum::response::IntoResponse> {
    body.validate()
        .map_err(|e| AppError::BadRequest(e.to_string()))?;

    let now = OffsetDateTime::now_utc();

    let record = sqlx::query!(
        "SELECT id, user_id, expires_at, used_at FROM password_resets WHERE token = $1",
        body.token
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::BadRequest("Invalid or expired reset token".to_string()))?;

    if record.used_at.is_some() {
        return Err(AppError::BadRequest("Reset token already used".to_string()));
    }

    if record.expires_at < now {
        return Err(AppError::BadRequest("Reset token expired".to_string()));
    }

    let new_hash = hash_password(&body.new_password)?;

    let mut tx = state.db.begin().await?;

    sqlx::query!(
        "UPDATE password_resets SET used_at = NOW() WHERE id = $1",
        record.id
    )
    .execute(&mut *tx)
    .await?;

    sqlx::query!(
        "UPDATE users SET password_hash = $1 WHERE id = $2",
        new_hash,
        record.user_id
    )
    .execute(&mut *tx)
    .await?;

    // Revoke all refresh tokens for this user
    sqlx::query!(
        "UPDATE refresh_tokens SET revoked_at = NOW()
         WHERE user_id = $1 AND revoked_at IS NULL",
        record.user_id
    )
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok(success_message(
        "Password reset successfully. Please login with your new password.",
    ))
}

/// GET /api/auth/me
pub async fn me(
    State(state): State<AppState>,
    CurrentUser(claims): CurrentUser,
) -> AppResult<impl axum::response::IntoResponse> {
    let user_id: Uuid = claims
        .sub
        .parse()
        .map_err(|_| AppError::Unauthorized("Invalid token".to_string()))?;

    let user = sqlx::query_as!(
        crate::models::user::User,
        r#"SELECT id, email, username, password_hash,
                  role as "role: _", is_verified, is_active, created_at, updated_at
           FROM users WHERE id = $1"#,
        user_id
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    Ok(success(UserResponse::from(user)))
}
