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

/// Extract Bearer token from Authorization header
fn extract_bearer_token(req: &Request) -> Option<String> {
    req.headers()
        .get(header::AUTHORIZATION)
        .and_then(|val| val.to_str().ok())
        .and_then(|val| val.strip_prefix("Bearer "))
        .map(|s| s.to_string())
}

/// Middleware: require valid JWT access token
pub async fn require_auth(
    State(state): State<AppState>,
    mut req: Request<Body>,
    next: Next,
) -> Result<Response, AppError> {
    let token = extract_bearer_token(&req)
        .ok_or_else(|| AppError::Unauthorized("Missing Authorization header".to_string()))?;

    let claims = state.jwt.verify_access_token(&token)?;

    // Attach claims to request extensions
    req.extensions_mut().insert(claims);

    Ok(next.run(req).await)
}

/// Middleware: require admin role
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
