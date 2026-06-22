use crate::integrattion::helpers::app::{TestApp, auth_header};
use crate::integrattion::helpers::fixtures::*;
use serde_json::{Value, json};
use uuid::Uuid;

// ═══════════════════════════════════════════════════════════════
// REGISTER FLOWS
// ═══════════════════════════════════════════════════════════════
#[tokio::test]
async fn test_register_flow() {
    let app = TestApp::new().await;

    // 1. Success case
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

    // 2. Duplicate email case (using same email as register success)
    let res = app
        .server
        .post("/api/auth/register")
        .json(&json!({
            "username": "otherusername",
            "email": "newuser@test.com",
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

    // 3. Duplicate username case (using same username as register success)
    let res = app
        .server
        .post("/api/auth/register")
        .json(&json!({
            "username": "newuser",
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

    // 4. Invalid email case
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

    // 5. Password too short
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

    // 6. Username too short
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
// VERIFY EMAIL FLOWS
// ═══════════════════════════════════════════════════════════════
#[tokio::test]
async fn test_verify_email_flow() {
    let app = TestApp::new().await;

    // 1. Success case
    let user = create_unverified_user(&app.db.pool).await;
    let token = create_verification_token(&app.db.pool, user.id).await;

    let res = app
        .server
        .get(&format!("/api/auth/verify-email?token={}", token))
        .await;

    assert_eq!(res.status_code(), 200);
    let html = res.text();
    assert!(html.contains("Verifikasi Berhasil"));

    // Pastikan user sekarang terverifikasi di DB
    let is_verified: bool = sqlx::query_scalar("SELECT is_verified FROM users WHERE id = $1")
        .bind(user.id)
        .fetch_one(&app.db.pool)
        .await
        .unwrap();
    assert!(is_verified, "User harus terverifikasi setelah klik link");

    // 2. Token already used case (using same token)
    let res = app
        .server
        .get(&format!("/api/auth/verify-email?token={}", token))
        .await;

    assert_eq!(res.status_code(), 200);
    let html = res.text();
    assert!(html.contains("Sudah Terverifikasi"));

    // 3. Invalid token case
    let res = app
        .server
        .get("/api/auth/verify-email?token=tokenpalsu123")
        .await;

    assert_eq!(res.status_code(), 200); // UI result page is 200
    let html = res.text();
    assert!(html.contains("Link Tidak Valid"));

    // 4. Expired token case
    let user_exp = create_unverified_user(&app.db.pool).await;
    let token_exp = create_expired_verification_token(&app.db.pool, user_exp.id).await;

    let res = app
        .server
        .get(&format!("/api/auth/verify-email?token={}", token_exp))
        .await;

    assert_eq!(res.status_code(), 200);
    let html = res.text();
    assert!(html.contains("Link Kadaluarsa"));
}

// ═══════════════════════════════════════════════════════════════
// LOGIN FLOWS
// ═══════════════════════════════════════════════════════════════
#[tokio::test]
async fn test_login_flow() {
    let app = TestApp::new().await;
    let user = create_verified_user(&app.db.pool).await;

    // 1. Success login
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

    // 2. Wrong password
    let res = app
        .server
        .post("/api/auth/login")
        .json(&json!({
            "email": user.email,
            "password": "WrongPassword!"
        }))
        .await;
    assert_eq!(res.status_code(), 401);

    // 3. Email not found
    let res = app
        .server
        .post("/api/auth/login")
        .json(&json!({
            "email": "tidakada@test.com",
            "password": "Password123!"
        }))
        .await;
    assert_eq!(res.status_code(), 401);

    // 4. Unverified user
    let user_unverified = create_unverified_user(&app.db.pool).await;
    let res = app
        .server
        .post("/api/auth/login")
        .json(&json!({
            "email": user_unverified.email,
            "password": user_unverified.password
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

    // 5. Inactive user
    let user_inactive = create_inactive_user(&app.db.pool).await;
    let res = app
        .server
        .post("/api/auth/login")
        .json(&json!({
            "email": user_inactive.email,
            "password": user_inactive.password
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
// REFRESH & LOGOUT FLOWS
// ═══════════════════════════════════════════════════════════════
#[tokio::test]
async fn test_refresh_and_logout_flow() {
    let app = TestApp::new().await;
    let user = create_verified_user(&app.db.pool).await;

    // 1. Success login
    let login_res = app
        .server
        .post("/api/auth/login")
        .json(&json!({"email": user.email, "password": user.password}))
        .await;
    let login_body: Value = login_res.json();
    let old_refresh = login_body["data"]["refresh_token"].as_str().unwrap().to_string();
    let old_access = login_body["data"]["access_token"].as_str().unwrap().to_string();

    // 2. Success refresh
    let new_jti = Uuid::new_v4().to_string();
    let res = app
        .server
        .post("/api/auth/refresh")
        .json(&json!({"refresh_token": old_refresh, "jti": new_jti}))
        .await;

    assert_eq!(res.status_code(), 200);
    let body: Value = res.json();
    let new_refresh = body["data"]["refresh_token"].as_str().unwrap().to_string();
    assert_ne!(body["data"]["access_token"].as_str().unwrap(), old_access);
    assert_ne!(new_refresh, old_refresh);

    // 3. Reuse revoked token (old_refresh has been replaced, so it is revoked)
    let res = app
        .server
        .post("/api/auth/refresh")
        .json(&json!({"refresh_token": old_refresh}))
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

    // 4. Invalid token format
    let res = app
        .server
        .post("/api/auth/refresh")
        .json(&json!({"refresh_token": "token.palsu.sekali"}))
        .await;
    assert_eq!(res.status_code(), 401);

    // 5. Success logout (using the active new_refresh token)
    let res = app
        .server
        .post("/api/auth/logout")
        .json(&json!({"refresh_token": new_refresh}))
        .await;
    assert_eq!(res.status_code(), 200);

    // 6. Refresh after logout should fail
    let refresh_res = app
        .server
        .post("/api/auth/refresh")
        .json(&json!({"refresh_token": new_refresh}))
        .await;
    assert_eq!(refresh_res.status_code(), 401);
}

// ═══════════════════════════════════════════════════════════════
// FORGOT & RESET PASSWORD FLOWS
// ═══════════════════════════════════════════════════════════════
#[tokio::test]
async fn test_forgot_and_reset_password_flow() {
    let app = TestApp::new().await;
    let user = create_verified_user(&app.db.pool).await;

    // 1. Forgot password known email
    let res = app
        .server
        .post("/api/auth/forgot-password")
        .json(&json!({"email": user.email}))
        .await;
    assert_eq!(res.status_code(), 200);
    assert_eq!(res.json::<Value>()["success"], true);

    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM password_resets WHERE user_id = $1")
        .bind(user.id)
        .fetch_one(&app.db.pool)
        .await
        .unwrap();
    assert_eq!(count, 1, "Reset token harus tersimpan di DB");

    // 2. Forgot password unknown email (anti-enumeration: still 200)
    let res = app
        .server
        .post("/api/auth/forgot-password")
        .json(&json!({"email": "tidakada@test.com"}))
        .await;
    assert_eq!(res.status_code(), 200);

    // 3. Forgot password invalid email format
    let res = app
        .server
        .post("/api/auth/forgot-password")
        .json(&json!({"email": "bukan-email"}))
        .await;
    assert_eq!(res.status_code(), 400);

    // 4. Reset password - invalid token
    let res = app
        .server
        .post("/api/auth/reset-password")
        .json(&json!({"token": "tokenpalsu", "new_password": "NewPassword456!"}))
        .await;
    assert_eq!(res.status_code(), 400);

    // 5. Reset password - too short
    let token = create_reset_token(&app.db.pool, user.id).await;
    let res = app
        .server
        .post("/api/auth/reset-password")
        .json(&json!({"token": token, "new_password": "short"}))
        .await;
    assert_eq!(res.status_code(), 400);

    // 6. Reset password success
    let token2 = create_reset_token(&app.db.pool, user.id).await;
    let res = app
        .server
        .post("/api/auth/reset-password")
        .json(&json!({
            "token": token2,
            "new_password": "NewPassword456!"
        }))
        .await;
    assert_eq!(res.status_code(), 200);

    // 7. Login with new password success
    let login_res = app
        .server
        .post("/api/auth/login")
        .json(&json!({
            "email": user.email,
            "password": "NewPassword456!"
        }))
        .await;
    assert_eq!(login_res.status_code(), 200);
    let old_refresh = login_res.json::<Value>()["data"]["refresh_token"].as_str().unwrap().to_string();

    // 8. Reset password again should revoke all sessions
    let token3 = create_reset_token(&app.db.pool, user.id).await;
    app.server
        .post("/api/auth/reset-password")
        .json(&json!({"token": token3, "new_password": "FinalPassword789!"}))
        .await;

    // Refresh with old token should fail now
    let res = app
        .server
        .post("/api/auth/refresh")
        .json(&json!({"refresh_token": old_refresh}))
        .await;
    assert_eq!(res.status_code(), 401);
}

// ═══════════════════════════════════════════════════════════════
// CURRENT USER ME FLOWS & DEACTIVATION INVALIDATION
// ═══════════════════════════════════════════════════════════════
#[tokio::test]
async fn test_me_flow() {
    let app = TestApp::new().await;
    let user = create_verified_user(&app.db.pool).await;

    // 1. Get access token
    let login_res = app
        .server
        .post("/api/auth/login")
        .json(&json!({"email": user.email, "password": user.password}))
        .await;
    let access_token = login_res.json::<Value>()["data"]["access_token"]
        .as_str()
        .unwrap()
        .to_string();

    // 2. Get /me authenticated
    let res = app
        .server
        .get("/api/auth/me")
        .add_header("Authorization", auth_header(&access_token))
        .await;

    assert_eq!(res.status_code(), 200);
    let body: Value = res.json();
    assert_eq!(body["data"]["email"], user.email);
    assert_eq!(body["data"]["username"], user.username);
    assert!(body["data"]["password_hash"].is_null() || body["data"].get("password_hash").is_none());

    // 3. Get /me without token
    let res = app.server.get("/api/auth/me").await;
    assert_eq!(res.status_code(), 401);

    // 4. Get /me invalid token
    let res = app
        .server
        .get("/api/auth/me")
        .add_header("Authorization", auth_header("BearerTokentidakvalid"))
        .await;
    assert_eq!(res.status_code(), 401);

    // 5. Deactivated user token invalidation test
    // Nonaktifkan user di DB secara paksa
    sqlx::query("UPDATE users SET is_active = false WHERE id = $1")
        .bind(user.id)
        .execute(&app.db.pool)
        .await
        .unwrap();

    // Coba akses /me dengan token yang sebelumnya valid — harus 403
    let res_after = app
        .server
        .get("/api/auth/me")
        .add_header("Authorization", auth_header(&access_token))
        .await;
    assert_eq!(res_after.status_code(), 403);
}

// ═══════════════════════════════════════════════════════════════
// HEALTH CHECK
// ═══════════════════════════════════════════════════════════════
#[tokio::test]
async fn test_health_check() {
    let app = TestApp::new().await;

    let res = app.server.get("/api/auth/health").await;
    assert_eq!(res.status_code(), 200);

    let body: Value = res.json();
    assert_eq!(body["data"]["status"], "OK");
}

#[tokio::test]
async fn test_home_route() {
    let app = TestApp::new().await;

    let res = app.server.get("/").await;
    assert_eq!(res.status_code(), 200);

    let body: Value = res.json();
    assert_eq!(body["success"], true);
    assert_eq!(body["data"]["message"], "Hello");
    assert_eq!(body["data"]["version"], env!("CARGO_PKG_VERSION"));
}

