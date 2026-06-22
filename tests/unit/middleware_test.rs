use axum::body::Body;
use axum::extract::Request;
use axum::http::header;
use yumana_api_v2::auth::extract_bearer_token;

#[test]
fn test_extract_bearer_token_success() {
    let req = Request::builder()
        .header(header::AUTHORIZATION, "Bearer my-token")
        .body(Body::empty())
        .unwrap();

    assert_eq!(extract_bearer_token(&req), Some("my-token".to_string()));
}

#[test]
fn test_extract_bearer_token_missing_header() {
    let req = Request::builder().body(Body::empty()).unwrap();
    assert_eq!(extract_bearer_token(&req), None);
}

#[test]
fn test_extract_bearer_token_invalid_prefix() {
    let req = Request::builder()
        .header(header::AUTHORIZATION, "Basic abc")
        .body(Body::empty())
        .unwrap();
    assert_eq!(extract_bearer_token(&req), None);
}

#[test]
fn test_extract_bearer_token_empty_token() {
    let req = Request::builder()
        .header(header::AUTHORIZATION, "Bearer ")
        .body(Body::empty())
        .unwrap();
    assert_eq!(extract_bearer_token(&req), Some("".to_string()));
}
