use axum::extract::Query;
use axum::{
    Json,
    extract::{Path, State},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::models::user::UserRole;
use crate::{
    config::state::AppState,
    models::user::UserResponse,
    utils::{
        errors::{AppError, AppResult},
        response::{paginated, success, success_message},
    },
};

// ─── DTOs ─────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ListUsersQuery {
    pub page: Option<i64>,
    pub per_page: Option<i64>,
    pub search: Option<String>,
    pub role: Option<String>,
    pub is_verified: Option<bool>,
    pub is_active: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateUserBody {
    pub is_active: Option<bool>,
    pub role: Option<UserRole>,
    pub is_verified: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct AdminUserResponse {
    pub id: Uuid,
    pub email: String,
    pub username: String,
    pub role: String,
    pub is_verified: bool,
    pub is_active: bool,
    pub created_at: String,
    pub refresh_token_count: i64,
}

// ─── Handlers ─────────────────────────────────────────────────────────────

/// GET /api/admin/users
pub async fn list_users(
    State(state): State<AppState>,
    Query(query): Query<ListUsersQuery>,
) -> AppResult<impl axum::response::IntoResponse> {
    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(20).clamp(1, 100);
    let offset = (page - 1) * per_page;

    let search_pattern = query
        .search
        .as_ref()
        .map(|s| format!("%{}%", s.to_lowercase()));

    // Total count
    let total: i64 = sqlx::query_scalar!(
        r#"SELECT COUNT(*) FROM users
           WHERE ($1::text IS NULL OR email ILIKE $1 OR username ILIKE $1)
             AND ($2::text IS NULL OR role::text = $2)
             AND ($3::bool IS NULL OR is_verified = $3)
             AND ($4::bool IS NULL OR is_active = $4)"#,
        search_pattern,
        query.role,
        query.is_verified,
        query.is_active,
    )
    .fetch_one(&state.db)
    .await?
    .unwrap_or(0);

    // Fetch users with refresh token count
    let rows = sqlx::query!(
        r#"SELECT
            u.id, u.email, u.username,
            u.role::text as role,
            u.is_verified, u.is_active,
            u.created_at,
            COUNT(rt.id) FILTER (WHERE rt.revoked_at IS NULL AND rt.expires_at > NOW()) as active_sessions
           FROM users u
           LEFT JOIN refresh_tokens rt ON rt.user_id = u.id
           WHERE ($1::text IS NULL OR u.email ILIKE $1 OR u.username ILIKE $1)
             AND ($2::text IS NULL OR u.role::text = $2)
             AND ($3::bool IS NULL OR u.is_verified = $3)
             AND ($4::bool IS NULL OR u.is_active = $4)
           GROUP BY u.id
           ORDER BY u.created_at DESC
           LIMIT $5 OFFSET $6"#,
        search_pattern,
        query.role,
        query.is_verified,
        query.is_active,
        per_page,
        offset
    )
    .fetch_all(&state.db)
    .await?;

    let users: Vec<AdminUserResponse> = rows
        .into_iter()
        .map(|r| AdminUserResponse {
            id: r.id,
            email: r.email,
            username: r.username,
            role: r.role.unwrap_or_else(|| "user".to_string()),
            is_verified: r.is_verified,
            is_active: r.is_active,
            created_at: r.created_at.to_string(),
            refresh_token_count: r.active_sessions.unwrap_or(0),
        })
        .collect();

    Ok((
        axum::http::StatusCode::OK,
        axum::Json(paginated(users, total, page, per_page)),
    ))
}

/// GET /api/admin/users/:id
pub async fn get_user(
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
) -> AppResult<impl axum::response::IntoResponse> {
    let user = sqlx::query_as!(
        crate::models::user::User,
        r#"SELECT id, email, username, password_hash,
                  role as "role: _", is_verified, is_active, created_at, updated_at
           FROM users WHERE id = $1"#,
        user_id
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::NotFound(format!("User {} not found", user_id)))?;

    Ok(success(UserResponse::from(user)))
}

/// PATCH /api/admin/users/:id
pub async fn update_user(
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
    Json(body): Json<UpdateUserBody>,
) -> AppResult<impl axum::response::IntoResponse> {
    // Check user exists
    let exists: bool =
        sqlx::query_scalar!("SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)", user_id)
            .fetch_one(&state.db)
            .await?
            .unwrap_or(false);

    if !exists {
        return Err(AppError::NotFound(format!("User {} not found", user_id)));
    }

    // Update fields dynamically
    if let Some(is_active) = body.is_active {
        sqlx::query!(
            "UPDATE users SET is_active = $1 WHERE id = $2",
            is_active,
            user_id
        )
        .execute(&state.db)
        .await?;

        // If deactivating, revoke all refresh tokens
        if !is_active {
            sqlx::query!(
                "UPDATE refresh_tokens SET revoked_at = NOW()
                 WHERE user_id = $1 AND revoked_at IS NULL",
                user_id
            )
            .execute(&state.db)
            .await?;
        }
    }

    if let Some(is_verified) = body.is_verified {
        sqlx::query!(
            "UPDATE users SET is_verified = $1 WHERE id = $2",
            is_verified,
            user_id
        )
        .execute(&state.db)
        .await?;
    }

    if let Some(role) = &body.role {
        if *role != UserRole::User && *role != UserRole::Admin {
            return Err(AppError::BadRequest(
                "Invalid role. Must be 'user' or 'admin'".to_string(),
            ));
        }
        sqlx::query!(
            "UPDATE users SET role = $1 WHERE id = $2",
            role as &UserRole,
            user_id
        )
        .execute(&state.db)
        .await?;
    }

    let user = sqlx::query_as!(
        crate::models::user::User,
        r#"SELECT id, email, username, password_hash,
                  role as "role: _", is_verified, is_active, created_at, updated_at
           FROM users WHERE id = $1"#,
        user_id
    )
    .fetch_one(&state.db)
    .await?;

    Ok(success(UserResponse::from(user)))
}

/// DELETE /api/admin/users/:id
pub async fn delete_user(
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
) -> AppResult<impl axum::response::IntoResponse> {
    let result = sqlx::query!("DELETE FROM users WHERE id = $1 RETURNING id", user_id)
        .fetch_optional(&state.db)
        .await?;

    if result.is_none() {
        return Err(AppError::NotFound(format!("User {} not found", user_id)));
    }

    Ok(success_message("User deleted successfully"))
}

/// POST /api/admin/users/:id/revoke-sessions
pub async fn revoke_user_sessions(
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
) -> AppResult<impl axum::response::IntoResponse> {
    let count = sqlx::query!(
        "UPDATE refresh_tokens SET revoked_at = NOW()
         WHERE user_id = $1 AND revoked_at IS NULL
         RETURNING id",
        user_id
    )
    .fetch_all(&state.db)
    .await?
    .len();

    Ok(success(serde_json::json!({
        "message": format!("Revoked {} active sessions", count),
        "revoked_count": count
    })))
}

/// GET /api/admin/stats
pub async fn get_stats(
    State(state): State<AppState>,
) -> AppResult<impl axum::response::IntoResponse> {
    let total_users: i64 = sqlx::query_scalar!("SELECT COUNT(*) FROM users")
        .fetch_one(&state.db)
        .await?
        .unwrap_or(0);

    let verified_users: i64 =
        sqlx::query_scalar!("SELECT COUNT(*) FROM users WHERE is_verified = true")
            .fetch_one(&state.db)
            .await?
            .unwrap_or(0);

    let active_users: i64 =
        sqlx::query_scalar!("SELECT COUNT(*) FROM users WHERE is_active = true")
            .fetch_one(&state.db)
            .await?
            .unwrap_or(0);

    let admin_users: i64 = sqlx::query_scalar!("SELECT COUNT(*) FROM users WHERE role = 'admin'")
        .fetch_one(&state.db)
        .await?
        .unwrap_or(0);

    let active_sessions: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) FROM refresh_tokens WHERE revoked_at IS NULL AND expires_at > NOW()"
    )
    .fetch_one(&state.db)
    .await?
    .unwrap_or(0);

    let new_today: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) FROM users WHERE created_at >= NOW() - INTERVAL '24 hours'"
    )
    .fetch_one(&state.db)
    .await?
    .unwrap_or(0);

    Ok(success(serde_json::json!({
        "total_users": total_users,
        "verified_users": verified_users,
        "unverified_users": total_users - verified_users,
        "active_users": active_users,
        "inactive_users": total_users - active_users,
        "admin_users": admin_users,
        "active_sessions": active_sessions,
        "new_users_today": new_today
    })))
}
