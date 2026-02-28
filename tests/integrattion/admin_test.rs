use crate::integrattion::helpers::app::{TestApp, auth_header};
use crate::integrattion::helpers::db::run_test;
use crate::integrattion::helpers::fixtures::{
    create_admin_user, create_inactive_user, create_unverified_user, create_verified_user,
};
use serde_json::{Value, json};

/// Helper: login dan ambil access token
async fn login_as(app: &TestApp, email: &str, password: &str) -> String {
    let res = app
        .server
        .post("/api/auth/login")
        .json(&json!({"email": email, "password": password}))
        .await;

    let body: Value = res.json();

    body["data"]["access_token"]
        .as_str()
        .expect("Gagal ambil access_token dari login response")
        .to_string()
}

// ═══════════════════════════════════════════════════════════════
// STATS
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_admin_stats_success() {
    run_test(|app| async move {
        let admin = create_admin_user(&app.db.pool).await;
        let token = login_as(&app, &admin.email, &admin.password).await;

        // Buat beberapa user untuk data stats
        create_verified_user(&app.db.pool).await;
        create_unverified_user(&app.db.pool).await;
        create_inactive_user(&app.db.pool).await;

        let res = app
            .server
            .get("/api/admin/stats")
            .add_header("Authorization", auth_header(&token))
            .await;

        assert_eq!(res.status_code(), 200);
        let body: Value = res.json();
        assert!(body["data"]["total_users"].as_i64().unwrap() >= 4); // 3 + 1 admin
        assert!(body["data"]["verified_users"].is_number());
        assert!(body["data"]["active_sessions"].is_number());
        assert!(body["data"]["new_users_today"].is_number());
        app
    })
    .await;
}

#[tokio::test]
async fn test_admin_stats_forbidden_for_user() {
    let app = TestApp::new().await;
    let user = create_verified_user(&app.db.pool).await;
    let token = login_as(&app, &user.email, &user.password).await;

    let res = app
        .server
        .get("/api/admin/stats")
        .add_header("Authorization", auth_header(&token))
        .await;

    assert_eq!(res.status_code(), 403);
    app.db.cleanup().await;
}

#[tokio::test]
async fn test_admin_stats_unauthorized_no_token() {
    let app = TestApp::new().await;

    let res = app.server.get("/api/admin/stats").await;
    assert_eq!(res.status_code(), 401);
    app.db.cleanup().await;
}

// ═══════════════════════════════════════════════════════════════
// LIST USERS
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_admin_list_users_success() {
    let app = TestApp::new().await;
    let admin = create_admin_user(&app.db.pool).await;
    let token = login_as(&app, &admin.email, &admin.password).await;

    create_verified_user(&app.db.pool).await;
    create_verified_user(&app.db.pool).await;

    let res = app
        .server
        .get("/api/admin/users")
        .add_header("Authorization", auth_header(&token))
        .await;

    assert_eq!(res.status_code(), 200);
    let body: Value = res.json();
    assert!(body["data"].is_array());
    assert!(body["pagination"]["total"].as_i64().unwrap() >= 2);
    assert_eq!(body["pagination"]["page"], 1);
    app.db.cleanup().await;
}

#[tokio::test]
async fn test_admin_list_users_pagination() {
    let app = TestApp::new().await;
    let admin = create_admin_user(&app.db.pool).await;
    let token = login_as(&app, &admin.email, &admin.password).await;

    // Buat 5 user
    for _ in 0..5 {
        create_verified_user(&app.db.pool).await;
    }

    let res = app
        .server
        .get("/api/admin/users?page=1&per_page=2")
        .add_header("Authorization", auth_header(&token))
        .await;

    assert_eq!(res.status_code(), 200);
    let body: Value = res.json();
    assert_eq!(body["data"].as_array().unwrap().len(), 2);
    assert_eq!(body["pagination"]["per_page"], 2);
    app.db.cleanup().await;
}

#[tokio::test]
async fn test_admin_list_users_filter_by_role() {
    let app = TestApp::new().await;
    let admin = create_admin_user(&app.db.pool).await;
    let token = login_as(&app, &admin.email, &admin.password).await;

    create_verified_user(&app.db.pool).await;
    create_admin_user(&app.db.pool).await;

    let res = app
        .server
        .get("/api/admin/users?role=admin")
        .add_header("Authorization", auth_header(&token))
        .await;

    assert_eq!(res.status_code(), 200);
    let body: Value = res.json();
    let users = body["data"].as_array().unwrap();
    // Semua user yang dikembalikan harus admin
    for u in users {
        assert_eq!(u["role"], "admin");
    }
    app.db.cleanup().await;
}

#[tokio::test]
async fn test_admin_list_users_filter_unverified() {
    let app = TestApp::new().await;
    let admin = create_admin_user(&app.db.pool).await;
    let token = login_as(&app, &admin.email, &admin.password).await;

    create_unverified_user(&app.db.pool).await;
    create_unverified_user(&app.db.pool).await;

    let res = app
        .server
        .get("/api/admin/users?is_verified=false")
        .add_header("Authorization", auth_header(&token))
        .await;

    assert_eq!(res.status_code(), 200);
    let body: Value = res.json();
    let users = body["data"].as_array().unwrap();
    for u in users {
        assert_eq!(u["is_verified"], false);
    }
    app.db.cleanup().await;
}

#[tokio::test]
async fn test_admin_list_users_search() {
    let app = TestApp::new().await;
    let admin = create_admin_user(&app.db.pool).await;
    let token = login_as(&app, &admin.email, &admin.password).await;

    // Insert user dengan email spesifik
    let user = create_verified_user(&app.db.pool).await;
    let search_term = &user.username[..5]; // 5 karakter pertama username

    let res = app
        .server
        .get(&format!("/api/admin/users?search={}", search_term))
        .add_header("Authorization", auth_header(&token))
        .await;

    assert_eq!(res.status_code(), 200);
    let body: Value = res.json();
    let users = body["data"].as_array().unwrap();
    // Harus ketemu setidaknya 1 user
    assert!(!users.is_empty());
    app.db.cleanup().await;
}

// ═══════════════════════════════════════════════════════════════
// GET USER BY ID
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_admin_get_user_success() {
    let app = TestApp::new().await;
    let admin = create_admin_user(&app.db.pool).await;
    let token = login_as(&app, &admin.email, &admin.password).await;
    let user = create_verified_user(&app.db.pool).await;

    let res = app
        .server
        .get(&format!("/api/admin/users/{}", user.id))
        .add_header("Authorization", auth_header(&token))
        .await;

    assert_eq!(res.status_code(), 200);
    let body: Value = res.json();
    assert_eq!(body["data"]["id"], user.id.to_string());
    assert_eq!(body["data"]["email"], user.email);
    app.db.cleanup().await;
}

#[tokio::test]
async fn test_admin_get_user_not_found() {
    let app = TestApp::new().await;
    let admin = create_admin_user(&app.db.pool).await;
    let token = login_as(&app, &admin.email, &admin.password).await;

    let fake_id = uuid::Uuid::new_v4();
    let res = app
        .server
        .get(&format!("/api/admin/users/{}", fake_id))
        .add_header("Authorization", auth_header(&token))
        .await;

    assert_eq!(res.status_code(), 404);
    app.db.cleanup().await;
}

// ═══════════════════════════════════════════════════════════════
// UPDATE USER
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_admin_update_user_deactivate() {
    let app = TestApp::new().await;
    let admin = create_admin_user(&app.db.pool).await;
    let token = login_as(&app, &admin.email, &admin.password).await;
    let user = create_verified_user(&app.db.pool).await;

    let res = app
        .server
        .patch(&format!("/api/admin/users/{}", user.id))
        .add_header("Authorization", auth_header(&token))
        .json(&json!({"is_active": false}))
        .await;

    assert_eq!(res.status_code(), 200);
    let body: Value = res.json();
    assert_eq!(body["data"]["is_active"], false);

    // Pastikan user tidak bisa login lagi
    let login_res = app
        .server
        .post("/api/auth/login")
        .json(&json!({"email": user.email, "password": user.password}))
        .await;
    assert_eq!(login_res.status_code(), 403);
    app.db.cleanup().await;
}

#[tokio::test]
async fn test_admin_update_user_promote_to_admin() {
    let app = TestApp::new().await;
    let admin = create_admin_user(&app.db.pool).await;
    let token = login_as(&app, &admin.email, &admin.password).await;
    let user = create_verified_user(&app.db.pool).await;

    let res = app
        .server
        .patch(&format!("/api/admin/users/{}", user.id))
        .add_header("Authorization", auth_header(&token))
        .json(&json!({"role": "admin"}))
        .await;

    assert_eq!(res.status_code(), 200);
    let body: Value = res.json();
    assert_eq!(body["data"]["role"], "admin");
    app.db.cleanup().await;
}

#[tokio::test]
async fn test_admin_update_user_verify_manually() {
    let app = TestApp::new().await;
    let admin = create_admin_user(&app.db.pool).await;
    let token = login_as(&app, &admin.email, &admin.password).await;
    let user = create_unverified_user(&app.db.pool).await;

    let res = app
        .server
        .patch(&format!("/api/admin/users/{}", user.id))
        .add_header("Authorization", auth_header(&token))
        .json(&json!({"is_verified": true}))
        .await;

    assert_eq!(res.status_code(), 200);
    assert_eq!(res.json::<Value>()["data"]["is_verified"], true);
    app.db.cleanup().await;
}

#[tokio::test]
async fn test_admin_update_user_invalid_role() {
    let app = TestApp::new().await;
    let admin = create_admin_user(&app.db.pool).await;
    let token = login_as(&app, &admin.email, &admin.password).await;
    let user = create_verified_user(&app.db.pool).await;

    let res = app
        .server
        .patch(&format!("/api/admin/users/{}", user.id))
        .add_header("Authorization", auth_header(&token))
        .json(&json!({"role": "superadmin"}))
        .await;

    assert_eq!(res.status_code(), 422);

    app.db.cleanup().await;
}

#[tokio::test]
async fn test_admin_update_user_not_found() {
    let app = TestApp::new().await;
    let admin = create_admin_user(&app.db.pool).await;
    let token = login_as(&app, &admin.email, &admin.password).await;

    let res = app
        .server
        .patch(&format!("/api/admin/users/{}", uuid::Uuid::new_v4()))
        .add_header("Authorization", auth_header(&token))
        .json(&json!({"is_active": false}))
        .await;

    assert_eq!(res.status_code(), 404);

    app.db.cleanup().await;
}

// ═══════════════════════════════════════════════════════════════
// DELETE USER
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_admin_delete_user_success() {
    let app = TestApp::new().await;
    let admin = create_admin_user(&app.db.pool).await;
    let token = login_as(&app, &admin.email, &admin.password).await;
    let user = create_verified_user(&app.db.pool).await;

    let res = app
        .server
        .delete(&format!("/api/admin/users/{}", user.id))
        .add_header("Authorization", auth_header(&token))
        .await;

    assert_eq!(res.status_code(), 200);

    // Pastikan user benar-benar terhapus dari DB
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)")
        .bind(user.id)
        .fetch_one(&app.db.pool)
        .await
        .unwrap();

    assert!(!exists, "User harus terhapus dari database");

    app.db.cleanup().await;
}

#[tokio::test]
async fn test_admin_delete_user_not_found() {
    let app = TestApp::new().await;
    let admin = create_admin_user(&app.db.pool).await;
    let token = login_as(&app, &admin.email, &admin.password).await;

    let res = app
        .server
        .delete(&format!("/api/admin/users/{}", uuid::Uuid::new_v4()))
        .add_header("Authorization", auth_header(&token))
        .await;

    assert_eq!(res.status_code(), 404);

    app.db.cleanup().await;
}

#[tokio::test]
async fn test_admin_delete_user_forbidden_for_user() {
    let app = TestApp::new().await;
    let user1 = create_verified_user(&app.db.pool).await;
    let user2 = create_verified_user(&app.db.pool).await;
    let token = login_as(&app, &user1.email, &user1.password).await;

    let res = app
        .server
        .delete(&format!("/api/admin/users/{}", user2.id))
        .add_header("Authorization", auth_header(&token))
        .await;

    assert_eq!(res.status_code(), 403);

    app.db.cleanup().await;
}

// ═══════════════════════════════════════════════════════════════
// REVOKE SESSIONS
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_admin_revoke_user_sessions() {
    let app = TestApp::new().await;
    let admin = create_admin_user(&app.db.pool).await;
    let admin_token = login_as(&app, &admin.email, &admin.password).await;

    // User login dua kali (dua sesi)
    let user = create_verified_user(&app.db.pool).await;
    let login1 = app
        .server
        .post("/api/auth/login")
        .json(&json!({"email": user.email, "password": user.password}))
        .await;
    let refresh1 = login1.json::<Value>()["data"]["refresh_token"]
        .as_str()
        .unwrap()
        .to_string();

    // Revoke semua sesi user ini
    let res = app
        .server
        .post(&format!("/api/admin/users/{}/revoke-sessions", user.id))
        .add_header("Authorization", auth_header(&admin_token))
        .await;

    assert_eq!(res.status_code(), 200);
    let body: Value = res.json();
    assert!(body["data"]["revoked_count"].as_i64().unwrap() >= 1);

    // Refresh token lama harus invalid
    let refresh_res = app
        .server
        .post("/api/auth/refresh")
        .json(&json!({"refresh_token": refresh1}))
        .await;

    assert_eq!(
        refresh_res.status_code(),
        401,
        "Sesi yang direvoke admin harus tidak bisa refresh"
    );

    app.db.cleanup().await;
}
