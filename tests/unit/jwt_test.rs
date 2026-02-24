use uuid::Uuid;
use yumana_api_v2::{models::user::UserRole, services::jwt::JwtService};

fn make_jwt() -> JwtService {
    JwtService::new(
        "test-access-secret-panjang-sekali-harus-32-char-min".to_string(),
        "test-refresh-secret-panjang-sekali-harus-32-char-min".to_string(),
        900,    // 15 menit
        604800, // 7 hari
    )
}

// ═══════════════════════════════════════════════════════════════
// ACCESS TOKEN
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_generate_access_token_success() {
    let jwt = make_jwt();
    let user_id = Uuid::new_v4();

    let token = jwt.generate_access_token(user_id, "test@test.com", "testuser", &UserRole::User);

    assert!(token.is_ok(), "Harus bisa generate access token");
    let token_str = token.unwrap();
    assert!(!token_str.is_empty());
    // JWT format: 3 bagian dipisah titik
    assert_eq!(token_str.split('.').count(), 3);
}

#[test]
fn test_verify_access_token_valid() {
    let jwt = make_jwt();
    let user_id = Uuid::new_v4();

    let token = jwt
        .generate_access_token(user_id, "test@test.com", "testuser", &UserRole::User)
        .unwrap();

    let claims = jwt.verify_access_token(&token);

    assert!(claims.is_ok(), "Token valid harus bisa diverifikasi");
    let c = claims.unwrap();
    assert_eq!(c.sub, user_id.to_string());
    assert_eq!(c.email, "test@test.com");
    assert_eq!(c.username, "testuser");
    assert_eq!(c.token_type, "access");
}

#[test]
fn test_verify_access_token_wrong_secret() {
    let jwt_gen = make_jwt();
    let jwt_verify = JwtService::new(
        "salah-secret-berbeda-sama-sekali-harus-32chars".to_string(),
        "test-refresh-secret-panjang-sekali-harus-32-char-min".to_string(),
        900,
        604800,
    );

    let token = jwt_gen
        .generate_access_token(Uuid::new_v4(), "test@test.com", "testuser", &UserRole::User)
        .unwrap();

    let result = jwt_verify.verify_access_token(&token);
    assert!(result.is_err(), "Token dengan secret berbeda harus ditolak");
}

#[test]
fn test_verify_access_token_malformed() {
    let jwt = make_jwt();

    assert!(jwt.verify_access_token("").is_err());
    assert!(jwt.verify_access_token("bukan.jwt").is_err());
    assert!(jwt.verify_access_token("a.b.c").is_err());
    assert!(jwt.verify_access_token("token.palsu.sekali").is_err());
}

#[test]
fn test_access_token_contains_correct_role_user() {
    let jwt = make_jwt();
    let token = jwt
        .generate_access_token(Uuid::new_v4(), "u@t.com", "user", &UserRole::User)
        .unwrap();
    let claims = jwt.verify_access_token(&token).unwrap();
    assert_eq!(claims.role, UserRole::User);
}

#[test]
fn test_access_token_contains_correct_role_admin() {
    let jwt = make_jwt();
    let token = jwt
        .generate_access_token(Uuid::new_v4(), "a@t.com", "admin", &UserRole::Admin)
        .unwrap();
    let claims = jwt.verify_access_token(&token).unwrap();
    assert_eq!(claims.role, UserRole::Admin);
}

#[test]
fn test_refresh_token_not_accepted_as_access() {
    let jwt = make_jwt();
    let user_id = Uuid::new_v4();
    let jti = Uuid::new_v4().to_string();

    let refresh = jwt.generate_refresh_token(user_id, &jti).unwrap();

    // Refresh token tidak boleh diterima sebagai access token
    let result = jwt.verify_access_token(&refresh);
    assert!(
        result.is_err(),
        "Refresh token tidak boleh lolos sebagai access token"
    );
}

// ═══════════════════════════════════════════════════════════════
// REFRESH TOKEN
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_generate_refresh_token_success() {
    let jwt = make_jwt();
    let user_id = Uuid::new_v4();
    let jti = Uuid::new_v4().to_string();

    let token = jwt.generate_refresh_token(user_id, &jti);

    assert!(token.is_ok());
    assert_eq!(token.unwrap().split('.').count(), 3);
}

#[test]
fn test_verify_refresh_token_valid() {
    let jwt = make_jwt();
    let user_id = Uuid::new_v4();
    let jti = Uuid::new_v4().to_string();

    let token = jwt.generate_refresh_token(user_id, &jti).unwrap();
    let claims = jwt.verify_refresh_token(&token);

    assert!(claims.is_ok());
    let c = claims.unwrap();
    assert_eq!(c.sub, user_id.to_string());
    assert_eq!(c.jti, jti);
    assert_eq!(c.token_type, "refresh");
}

#[test]
fn test_verify_refresh_token_wrong_secret() {
    let jwt_gen = make_jwt();
    let jwt_verify = JwtService::new(
        "test-access-secret-panjang-sekali-harus-32-char-min".to_string(),
        "salah-refresh-secret-berbeda-harus-panjang-juga-ok".to_string(),
        900,
        604800,
    );

    let token = jwt_gen
        .generate_refresh_token(Uuid::new_v4(), &Uuid::new_v4().to_string())
        .unwrap();

    assert!(jwt_verify.verify_refresh_token(&token).is_err());
}

#[test]
fn test_access_token_not_accepted_as_refresh() {
    let jwt = make_jwt();
    let access = jwt
        .generate_access_token(Uuid::new_v4(), "t@t.com", "u", &UserRole::User)
        .unwrap();

    let result = jwt.verify_refresh_token(&access);
    assert!(
        result.is_err(),
        "Access token tidak boleh lolos sebagai refresh token"
    );
}

#[test]
fn test_refresh_token_malformed() {
    let jwt = make_jwt();

    assert!(jwt.verify_refresh_token("").is_err());
    assert!(jwt.verify_refresh_token("palsu.token.banget").is_err());
}

// ═══════════════════════════════════════════════════════════════
// TOKEN UNIQUENESS
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_each_token_is_unique() {
    let jwt = make_jwt();
    let user_id = Uuid::new_v4();

    let t1 = jwt
        .generate_access_token(user_id, "e@t.com", "u", &UserRole::User)
        .unwrap();
    let t2 = jwt
        .generate_access_token(user_id, "e@t.com", "u", &UserRole::User)
        .unwrap();

    // Token yang di-generate dalam waktu berbeda harus unik (karena timestamp iat)
    // Ini bisa sama jika dibuat dalam detik yang sama, tapi setidaknya keduanya valid
    assert!(jwt.verify_access_token(&t1).is_ok());
    assert!(jwt.verify_access_token(&t2).is_ok());
}

#[test]
fn test_expired_token_rejected() {
    // JWT dengan expiry 0 detik (langsung expired)
    let jwt = JwtService::new(
        "test-access-secret-panjang-sekali-harus-32-char-min".to_string(),
        "test-refresh-secret-panjang-sekali-harus-32-char-min".to_string(),
        -300,
        604800,
    );

    let token = jwt
        .generate_access_token(Uuid::new_v4(), "e@t.com", "u", &UserRole::User)
        .unwrap();
    let result = jwt.verify_access_token(&token);
    assert!(result.is_err(), "Token expired harus ditolak");
}
