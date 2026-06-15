use axum::{
    body::Body,
    extract::{Request, State},
    http::header,
    middleware::Next,
    response::Response,
};

use crate::{
    config::state::AppState, models::user::UserRole, services::jwt::AccessTokenClaims,
    utils::errors::AppError,
};
use uuid::Uuid;

/// Extract Bearer token from Authorization header
pub fn extract_bearer_token(req: &Request) -> Option<String> {
    req.headers()
        .get(header::AUTHORIZATION)
        .and_then(|val| val.to_str().ok())
        .and_then(|val| val.strip_prefix("Bearer "))
        .map(|s| s.to_string())
}

/// Middleware: require valid JWT access token and active user
pub async fn require_auth(
    State(state): State<AppState>,
    mut req: Request<Body>,
    next: Next,
) -> Result<Response, AppError> {
    let token = extract_bearer_token(&req)
        .ok_or_else(|| AppError::Unauthorized("Missing Authorization header".to_string()))?;

    let claims = state.jwt.verify_access_token(&token)?;

    // Parse user_id from sub
    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| AppError::Unauthorized("Invalid token payload".to_string()))?;

    // Verify user status in DB
    let user_status: (bool,) = sqlx::query_as("SELECT is_active FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_optional(&state.db)
        .await
        .map_err(AppError::DatabaseError)?
        .ok_or_else(|| AppError::Unauthorized("User no longer exists".to_string()))?;

    if !user_status.0 {
        return Err(AppError::Forbidden("Account is deactivated".to_string()));
    }

    // Attach claims to request extensions
    req.extensions_mut().insert(claims);

    Ok(next.run(req).await)
}

/// Middleware: require admin role and active user
pub async fn require_admin(
    State(state): State<AppState>,
    mut req: Request<Body>,
    next: Next,
) -> Result<Response, AppError> {
    let token = extract_bearer_token(&req)
        .ok_or_else(|| AppError::Unauthorized("Missing Authorization header".to_string()))?;

    let claims = state.jwt.verify_access_token(&token)?;

    if claims.role != UserRole::Admin {
        return Err(AppError::Forbidden("Admin access required".to_string()));
    }

    // Parse user_id
    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| AppError::Unauthorized("Invalid token payload".to_string()))?;

    // Verify user status in DB
    let user_status: (bool,) = sqlx::query_as("SELECT is_active FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_optional(&state.db)
        .await
        .map_err(AppError::DatabaseError)?
        .ok_or_else(|| AppError::Unauthorized("User no longer exists".to_string()))?;

    if !user_status.0 {
        return Err(AppError::Forbidden("Account is deactivated".to_string()));
    }

    req.extensions_mut().insert(claims);

    Ok(next.run(req).await)
}

/// Helper extractor untuk current user claims di handler
pub struct CurrentUser(pub AccessTokenClaims);

impl<S> axum::extract::FromRequestParts<S> for CurrentUser
where
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<AccessTokenClaims>()
            .cloned()
            .map(CurrentUser)
            .ok_or_else(|| AppError::Unauthorized("Not authenticated".to_string()))
    }
}
