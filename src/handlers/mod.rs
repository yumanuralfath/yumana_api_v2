use axum::response::IntoResponse;
use serde_json::json;

pub mod admin;
pub mod auth;

pub async fn home_route() -> impl IntoResponse {
    crate::utils::response::success(json!({
        "message": "Hello",
        "version": env!("CARGO_PKG_VERSION")
    }))
}
