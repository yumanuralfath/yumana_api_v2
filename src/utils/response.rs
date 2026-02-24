use axum::{Json, http::StatusCode, response::IntoResponse};
use serde::Serialize;
use serde_json::{Value, json};

pub fn success<T: Serialize>(data: T) -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(json!({
            "success": true,
            "data": data
        })),
    )
}

pub fn success_with_status<T: Serialize>(status: StatusCode, data: T) -> impl IntoResponse {
    (
        status,
        Json(json!({
            "success": true,
            "data": data
        })),
    )
}

pub fn success_message(message: &str) -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(json!({
            "success": true,
            "message": message
        })),
    )
}

pub fn paginated<T: Serialize>(data: Vec<T>, total: i64, page: i64, per_page: i64) -> Value {
    json!({
        "success": true,
        "data": data,
        "pagination": {
            "total": total,
            "page": page,
            "per_page": per_page,
            "total_pages": (total as f64 / per_page as f64).ceil() as i64
        }
    })
}
