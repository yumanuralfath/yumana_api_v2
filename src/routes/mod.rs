use axum::{
    Router, middleware,
    routing::{delete, get, patch, post},
};

use crate::{
    config::state::AppState,
    handlers::{admin, auth},
    middleware::auth::{require_admin, require_auth},
};

pub fn create_router(state: AppState) -> Router {
    let auth_routes = Router::new()
        .route("/register", post(auth::register))
        .route("/verify-email", get(auth::verify_email))
        .route("/login", post(auth::login))
        .route("/refresh", post(auth::refresh_token))
        .route("/logout", post(auth::logout))
        .route("/forgot-password", post(auth::forgot_password))
        .route("/reset-password", post(auth::reset_password))
        // Protected: require login
        .route(
            "/me",
            get(auth::me).layer(middleware::from_fn_with_state(state.clone(), require_auth)),
        );

    let admin_routes = Router::new()
        .route("/stats", get(admin::get_stats))
        .route("/users", get(admin::list_users))
        .route("/users/{id}", get(admin::get_user))
        .route("/users/{id}", patch(admin::update_user))
        .route("/users/{id}", delete(admin::delete_user))
        .route(
            "/users/{id}/revoke-sessions",
            post(admin::revoke_user_sessions),
        )
        .layer(middleware::from_fn_with_state(state.clone(), require_admin));

    Router::new()
        .nest("/api/auth", auth_routes)
        .nest("/api/admin", admin_routes)
        .route("/health", get(health_check))
        .with_state(state)
}

async fn health_check() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "status": "ok",
        "service": "yumana_api_v2"
    }))
}
