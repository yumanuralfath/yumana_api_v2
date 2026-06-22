use axum::response::IntoResponse;
use yumana_api_v2::utils::errors::AppError;

// Helper: ambil status code dari AppError response
fn status_of(err: AppError) -> u16 {
    let resp = err.into_response();
    resp.status().as_u16()
}

#[test]
fn test_not_found_returns_404() {
    assert_eq!(status_of(AppError::NotFound("test".to_string())), 404);
}

#[test]
fn test_unauthorized_returns_401() {
    assert_eq!(status_of(AppError::Unauthorized("test".to_string())), 401);
}

#[test]
fn test_forbidden_returns_403() {
    assert_eq!(status_of(AppError::Forbidden("test".to_string())), 403);
}

#[test]
fn test_bad_request_returns_400() {
    assert_eq!(status_of(AppError::BadRequest("test".to_string())), 400);
}

#[test]
fn test_conflict_returns_409() {
    assert_eq!(status_of(AppError::Conflict("test".to_string())), 409);
}

#[test]
fn test_internal_server_error_returns_500() {
    assert_eq!(status_of(AppError::InternalServerError), 500);
}

#[test]
fn test_error_response_has_success_false() {
    use axum::body::to_bytes;
    use serde_json::Value;

    let resp = AppError::NotFound("test".to_string()).into_response();
    let body = tokio::runtime::Runtime::new().unwrap().block_on(async {
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice::<Value>(&bytes).unwrap()
    });

    assert_eq!(body["success"], false);
    assert!(body["error"].is_string());
    assert!(body["code"].is_number());
}

#[test]
fn test_error_message_preserved() {
    use axum::body::to_bytes;
    use serde_json::Value;

    let msg = "pesan error spesifik ini".to_string();
    let resp = AppError::BadRequest(msg.clone()).into_response();

    let body = tokio::runtime::Runtime::new().unwrap().block_on(async {
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice::<Value>(&bytes).unwrap()
    });

    assert!(body["error"].as_str().unwrap().contains(&msg));
}
