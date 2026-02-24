use crate::integrattion::helpers::app::{TestApp, auth_header};
use crate::integrattion::helpers::fixtures::*;
use serde_json::{Value, json};

// ═══════════════════════════════════════════════════════════════
// REGISTER
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_register_success() {
    let app = TestApp::new().await;

    let res = app
        .server
        .post("/api/auth/register")
        .json(&json!({
            "username": "newuser",
            "email": "newuser@test.com",
            "password": "Password123!"
        }))
        .await;

    assert_eq!(res.status_code(), 200);

    let body: Value = res.json();
    assert_eq!(body["success"], true);
    assert!(body["data"]["user"]["id"].is_string());
    assert_eq!(body["data"]["user"]["email"], "newuser@test.com");
    assert_eq!(body["data"]["user"]["is_verified"], false); // belum verifikasi email
}

#[tokio::test]
async fn test_register_duplicate_email() {
    let app = TestApp::new().await;
    let user = create_verified_user(&app.db.pool).await;

    let res = app
        .server
        .post("/api/auth/register")
        .json(&json!({
            "username": "otherusername",
            "email": user.email,
            "password": "Password123!"
        }))
        .await;

    assert_eq!(res.status_code(), 409);
    let body: Value = res.json();
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .to_lowercase()
            .contains("email")
    );
}

#[tokio::test]
async fn test_register_duplicate_username() {
    let app = TestApp::new().await;
    let user = create_verified_user(&app.db.pool).await;

    let res = app
        .server
        .post("/api/auth/register")
        .json(&json!({
            "username": user.username,
            "email": "different@test.com",
            "password": "Password123!"
        }))
        .await;

    assert_eq!(res.status_code(), 409);
    let body: Value = res.json();
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .to_lowercase()
            .contains("username")
    );
}

#[tokio::test]
async fn test_register_invalid_email() {
    let app = TestApp::new().await;

    let res = app
        .server
        .post("/api/auth/register")
        .json(&json!({
            "username": "validuser",
            "email": "bukan-email",
            "password": "Password123!"
        }))
        .await;

    assert_eq!(res.status_code(), 400);
}

#[tokio::test]
async fn test_register_password_too_short() {
    let app = TestApp::new().await;

    let res = app
        .server
        .post("/api/auth/register")
        .json(&json!({
            "username": "validuser",
            "email": "valid@test.com",
            "password": "short"
        }))
        .await;

    assert_eq!(res.status_code(), 400);
}

#[tokio::test]
async fn test_register_username_too_short() {
    let app = TestApp::new().await;

    let res = app
        .server
        .post("/api/auth/register")
        .json(&json!({
            "username": "ab",
            "email": "valid@test.com",
            "password": "Password123!"
        }))
        .await;

    assert_eq!(res.status_code(), 400);
}

// ═══════════════════════════════════════════════════════════════
// VERIFY EMAIL
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_verify_email_success() {
    let app = TestApp::new().await;
    let user = create_unverified_user(&app.db.pool).await;
    let token = create_verification_token(&app.db.pool, user.id).await;

    let res = app
        .server
        .get(&format!("/api/auth/verify-email?token={}", token))
        .await;

    assert_eq!(res.status_code(), 200);
    let body: Value = res.json();
    assert_eq!(body["success"], true);

    // Pastikan user sekarang terverifikasi di DB
    let is_verified: bool = sqlx::query_scalar("SELECT is_verified FROM users WHERE id = $1")
        .bind(user.id)
        .fetch_one(&app.db.pool)
        .await
        .unwrap();

    assert!(is_verified, "User harus terverifikasi setelah klik link");
}

#[tokio::test]
async fn test_verify_email_invalid_token() {
    let app = TestApp::new().await;

    let res = app
        .server
        .get("/api/auth/verify-email?token=tokenpalsu123")
        .await;

    assert_eq!(res.status_code(), 400);
}

#[tokio::test]
async fn test_verify_email_expired_token() {
    let app = TestApp::new().await;
    let user = create_unverified_user(&app.db.pool).await;
    let token = create_expired_verification_token(&app.db.pool, user.id).await;

    let res = app
        .server
        .get(&format!("/api/auth/verify-email?token={}", token))
        .await;

    assert_eq!(res.status_code(), 400);
    let body: Value = res.json();
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .to_lowercase()
            .contains("expired")
    );
}

#[tokio::test]
async fn test_verify_email_token_already_used() {
    let app = TestApp::new().await;
    let user = create_unverified_user(&app.db.pool).await;
    let token = create_verification_token(&app.db.pool, user.id).await;

    // Pakai pertama kali — sukses
    app.server
        .get(&format!("/api/auth/verify-email?token={}", token))
        .await;

    // Pakai kedua kali — gagal
    let res = app
        .server
        .get(&format!("/api/auth/verify-email?token={}", token))
        .await;

    assert_eq!(res.status_code(), 400);
    let body: Value = res.json();
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .to_lowercase()
            .contains("used")
            || body["error"]
                .as_str()
                .unwrap()
                .to_lowercase()
                .contains("already")
    );
}

// ═══════════════════════════════════════════════════════════════
// LOGIN
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_login_success() {
    let app = TestApp::new().await;
    let user = create_verified_user(&app.db.pool).await;

    let res = app
        .server
        .post("/api/auth/login")
        .json(&json!({
            "email": user.email,
            "password": user.password
        }))
        .await;

    assert_eq!(res.status_code(), 200);
    let body: Value = res.json();
    assert_eq!(body["success"], true);
    assert!(body["data"]["access_token"].is_string());
    assert!(body["data"]["refresh_token"].is_string());
    assert_eq!(body["data"]["token_type"], "Bearer");
    assert_eq!(body["data"]["user"]["email"], user.email);
}

#[tokio::test]
async fn test_login_wrong_password() {
    let app = TestApp::new().await;
    let user = create_verified_user(&app.db.pool).await;

    let res = app
        .server
        .post("/api/auth/login")
        .json(&json!({
            "email": user.email,
            "password": "WrongPassword!"
        }))
        .await;

    assert_eq!(res.status_code(), 401);
}

#[tokio::test]
async fn test_login_email_not_found() {
    let app = TestApp::new().await;

    let res = app
        .server
        .post("/api/auth/login")
        .json(&json!({
            "email": "tidakada@test.com",
            "password": "Password123!"
        }))
        .await;

    assert_eq!(res.status_code(), 401);
}

#[tokio::test]
async fn test_login_unverified_user() {
    let app = TestApp::new().await;
    let user = create_unverified_user(&app.db.pool).await;

    let res = app
        .server
        .post("/api/auth/login")
        .json(&json!({
            "email": user.email,
            "password": user.password
        }))
        .await;

    assert_eq!(res.status_code(), 403);
    let body: Value = res.json();
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .to_lowercase()
            .contains("verify")
    );
}

#[tokio::test]
async fn test_login_inactive_user() {
    let app = TestApp::new().await;
    let user = create_inactive_user(&app.db.pool).await;

    let res = app
        .server
        .post("/api/auth/login")
        .json(&json!({
            "email": user.email,
            "password": user.password
        }))
        .await;

    assert_eq!(res.status_code(), 403);
    let body: Value = res.json();
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .to_lowercase()
            .contains("deactivated")
    );
}

// ═══════════════════════════════════════════════════════════════
// REFRESH TOKEN
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_refresh_token_success() {
    let app = TestApp::new().await;
    let user = create_verified_user(&app.db.pool).await;

    // Login dulu untuk dapat refresh token
    let login_res = app
        .server
        .post("/api/auth/login")
        .json(&json!({"email": user.email, "password": user.password}))
        .await;
    let login_body: Value = login_res.json();
    let refresh_token = login_body["data"]["refresh_token"].as_str().unwrap();
    let old_access = login_body["data"]["access_token"]
        .as_str()
        .unwrap()
        .to_string();

    // Refresh
    let res = app
        .server
        .post("/api/auth/refresh")
        .json(&json!({"refresh_token": refresh_token}))
        .await;

    assert_eq!(res.status_code(), 200);
    let body: Value = res.json();
    assert!(body["data"]["access_token"].is_string());
    assert!(body["data"]["refresh_token"].is_string());
    // Token baru harus berbeda (rotasi)
    assert_ne!(body["data"]["access_token"].as_str().unwrap(), old_access);
    assert_ne!(
        body["data"]["refresh_token"].as_str().unwrap(),
        refresh_token
    );
}

#[tokio::test]
async fn test_refresh_token_reuse_revoked() {
    let app = TestApp::new().await;
    let user = create_verified_user(&app.db.pool).await;

    let login_res = app
        .server
        .post("/api/auth/login")
        .json(&json!({"email": user.email, "password": user.password}))
        .await;
    let login_body: Value = login_res.json();
    let refresh_token = login_body["data"]["refresh_token"].as_str().unwrap();

    // Refresh pertama — sukses, token lama direvoke
    app.server
        .post("/api/auth/refresh")
        .json(&json!({"refresh_token": refresh_token}))
        .await;

    // Coba pakai token lama lagi — harus ditolak
    let res = app
        .server
        .post("/api/auth/refresh")
        .json(&json!({"refresh_token": refresh_token}))
        .await;

    assert_eq!(res.status_code(), 401);
    let body: Value = res.json();
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .to_lowercase()
            .contains("revoked")
            || body["error"]
                .as_str()
                .unwrap()
                .to_lowercase()
                .contains("invalid")
    );
}

#[tokio::test]
async fn test_refresh_token_invalid() {
    let app = TestApp::new().await;

    let res = app
        .server
        .post("/api/auth/refresh")
        .json(&json!({"refresh_token": "token.palsu.sekali"}))
        .await;

    assert_eq!(res.status_code(), 401);
}

// ═══════════════════════════════════════════════════════════════
// LOGOUT
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_logout_success() {
    let app = TestApp::new().await;
    let user = create_verified_user(&app.db.pool).await;

    let login_res = app
        .server
        .post("/api/auth/login")
        .json(&json!({"email": user.email, "password": user.password}))
        .await;
    let login_body: Value = login_res.json();
    let refresh_token = login_body["data"]["refresh_token"].as_str().unwrap();

    // Logout
    let res = app
        .server
        .post("/api/auth/logout")
        .json(&json!({"refresh_token": refresh_token}))
        .await;

    assert_eq!(res.status_code(), 200);

    // Coba refresh setelah logout — harus gagal
    let refresh_res = app
        .server
        .post("/api/auth/refresh")
        .json(&json!({"refresh_token": refresh_token}))
        .await;

    assert_eq!(refresh_res.status_code(), 401);
}

// ═══════════════════════════════════════════════════════════════
// FORGOT PASSWORD
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_forgot_password_known_email() {
    let app = TestApp::new().await;
    let user = create_verified_user(&app.db.pool).await;

    let res = app
        .server
        .post("/api/auth/forgot-password")
        .json(&json!({"email": user.email}))
        .await;

    // Selalu 200 (anti-enumeration)
    assert_eq!(res.status_code(), 200);
    assert_eq!(res.json::<Value>()["success"], true);

    // Pastikan token tersimpan di DB
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM password_resets WHERE user_id = $1")
        .bind(user.id)
        .fetch_one(&app.db.pool)
        .await
        .unwrap();

    assert_eq!(count, 1, "Reset token harus tersimpan di DB");
}

#[tokio::test]
async fn test_forgot_password_unknown_email() {
    let app = TestApp::new().await;

    let res = app
        .server
        .post("/api/auth/forgot-password")
        .json(&json!({"email": "tidakada@test.com"}))
        .await;

    // Tetap 200 — tidak boleh reveal apakah email ada
    assert_eq!(res.status_code(), 200);
}

#[tokio::test]
async fn test_forgot_password_invalid_email_format() {
    let app = TestApp::new().await;

    let res = app
        .server
        .post("/api/auth/forgot-password")
        .json(&json!({"email": "bukan-email"}))
        .await;

    assert_eq!(res.status_code(), 400);
}

// ═══════════════════════════════════════════════════════════════
// RESET PASSWORD
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_reset_password_success() {
    let app = TestApp::new().await;
    let user = create_verified_user(&app.db.pool).await;
    let token = create_reset_token(&app.db.pool, user.id).await;

    let res = app
        .server
        .post("/api/auth/reset-password")
        .json(&json!({
            "token": token,
            "new_password": "NewPassword456!"
        }))
        .await;

    assert_eq!(res.status_code(), 200);

    // Login dengan password baru harus sukses
    let login_res = app
        .server
        .post("/api/auth/login")
        .json(&json!({
            "email": user.email,
            "password": "NewPassword456!"
        }))
        .await;

    assert_eq!(
        login_res.status_code(),
        200,
        "Login dengan password baru harus berhasil"
    );
}

#[tokio::test]
async fn test_reset_password_revokes_sessions() {
    let app = TestApp::new().await;
    let user = create_verified_user(&app.db.pool).await;

    // Login dulu untuk dapat refresh token aktif
    let login_res = app
        .server
        .post("/api/auth/login")
        .json(&json!({"email": user.email, "password": user.password}))
        .await;
    let old_refresh = login_res.json::<Value>()["data"]["refresh_token"]
        .as_str()
        .unwrap()
        .to_string();

    let token = create_reset_token(&app.db.pool, user.id).await;

    // Reset password
    app.server
        .post("/api/auth/reset-password")
        .json(&json!({"token": token, "new_password": "NewPassword456!"}))
        .await;

    // Refresh token lama harus direvoke
    let res = app
        .server
        .post("/api/auth/refresh")
        .json(&json!({"refresh_token": old_refresh}))
        .await;

    assert_eq!(
        res.status_code(),
        401,
        "Semua sesi lama harus direvoke setelah reset password"
    );
}

#[tokio::test]
async fn test_reset_password_invalid_token() {
    let app = TestApp::new().await;

    let res = app
        .server
        .post("/api/auth/reset-password")
        .json(&json!({"token": "tokenpalsu", "new_password": "NewPassword456!"}))
        .await;

    assert_eq!(res.status_code(), 400);
}

#[tokio::test]
async fn test_reset_password_too_short() {
    let app = TestApp::new().await;
    let user = create_verified_user(&app.db.pool).await;
    let token = create_reset_token(&app.db.pool, user.id).await;

    let res = app
        .server
        .post("/api/auth/reset-password")
        .json(&json!({"token": token, "new_password": "short"}))
        .await;

    assert_eq!(res.status_code(), 400);
}

// ═══════════════════════════════════════════════════════════════
// ME (current user)
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_me_authenticated() {
    let app = TestApp::new().await;
    let user = create_verified_user(&app.db.pool).await;

    let login_res = app
        .server
        .post("/api/auth/login")
        .json(&json!({"email": user.email, "password": user.password}))
        .await;
    let access_token = login_res.json::<Value>()["data"]["access_token"]
        .as_str()
        .unwrap()
        .to_string();

    let res = app
        .server
        .get("/api/auth/me")
        .add_header("Authorization", auth_header(&access_token))
        .await;

    assert_eq!(res.status_code(), 200);
    let body: Value = res.json();
    assert_eq!(body["data"]["email"], user.email);
    assert_eq!(body["data"]["username"], user.username);
    // Password tidak boleh bocor
    assert!(body["data"]["password_hash"].is_null() || body["data"].get("password_hash").is_none());
}

#[tokio::test]
async fn test_me_without_token() {
    let app = TestApp::new().await;

    let res = app.server.get("/api/auth/me").await;
    assert_eq!(res.status_code(), 401);
}

#[tokio::test]
async fn test_me_invalid_token() {
    let app = TestApp::new().await;
    let invalid_bear_token = "BearerTokentidakvalid";

    let res = app
        .server
        .get("/api/auth/me")
        .add_header("Authorization", auth_header(invalid_bear_token))
        .await;

    assert_eq!(res.status_code(), 401);
}

// ═══════════════════════════════════════════════════════════════
// HEALTH CHECK
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_health_check() {
    let app = TestApp::new().await;

    let res = app.server.get("/health").await;
    assert_eq!(res.status_code(), 200);

    let body: Value = res.json();
    assert_eq!(body["status"], "ok");
}
