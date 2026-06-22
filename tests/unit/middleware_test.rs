use axum::body::Body;
use axum::extract::Request;
use axum::http::header;
use yumana_api_v2::middleware::auth::extract_bearer_token;

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

#[tokio::test]
async fn test_current_user_extractor_success() {
    use axum::extract::FromRequestParts;
    use yumana_api_v2::services::jwt::AccessTokenClaims;
    use yumana_api_v2::models::user::UserRole;
    use yumana_api_v2::middleware::auth::CurrentUser;
    use axum::http::Request;

    let claims = AccessTokenClaims {
        sub: "550e8400-e29b-41d4-a716-446655440000".to_string(),
        email: "test@test.com".to_string(),
        username: "testuser".to_string(),
        role: UserRole::User,
        token_type: "access".to_string(),
        exp: 10000000000,
        iat: 10000000000,
        jti: "test-jti".to_string(),
    };

    let mut req = Request::builder().body(()).unwrap();
    req.extensions_mut().insert(claims.clone());
    let (mut parts, _) = req.into_parts();

    let extracted = CurrentUser::from_request_parts(&mut parts, &()).await;
    assert!(extracted.is_ok());
    let current_user = extracted.unwrap();
    assert_eq!(current_user.0.sub, claims.sub);
    assert_eq!(current_user.0.email, claims.email);
}

#[tokio::test]
async fn test_current_user_extractor_missing() {
    use axum::extract::FromRequestParts;
    use yumana_api_v2::middleware::auth::CurrentUser;
    use axum::http::Request;

    let req = Request::builder().body(()).unwrap();
    let (mut parts, _) = req.into_parts();

    let extracted = CurrentUser::from_request_parts(&mut parts, &()).await;
    assert!(extracted.is_err());
}


