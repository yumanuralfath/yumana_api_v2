use crate::integrattion::helpers::app::{TestApp, auth_header};
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
// ADMIN STATS FLOW
// ═══════════════════════════════════════════════════════════════
#[tokio::test]
async fn test_admin_stats_flow() {
    let app = TestApp::new().await;

    // 1. Success case as admin
    let admin = create_admin_user(&app.db.pool).await;
    let admin_token = login_as(&app, &admin.email, &admin.password).await;

    create_verified_user(&app.db.pool).await;
    create_unverified_user(&app.db.pool).await;
    create_inactive_user(&app.db.pool).await;

    let res = app
        .server
        .get("/api/admin/stats")
        .add_header("Authorization", auth_header(&admin_token))
        .await;

    assert_eq!(res.status_code(), 200);
    let body: Value = res.json();
    assert!(body["data"]["total_users"].as_i64().unwrap() >= 4);
    assert!(body["data"]["verified_users"].is_number());
    assert!(body["data"]["active_sessions"].is_number());
    assert!(body["data"]["new_users_today"].is_number());

    // 2. Forbidden for regular user
    let user = create_verified_user(&app.db.pool).await;
    let user_token = login_as(&app, &user.email, &user.password).await;

    let res = app
        .server
        .get("/api/admin/stats")
        .add_header("Authorization", auth_header(&user_token))
        .await;
    assert_eq!(res.status_code(), 403);

    // 3. Unauthorized for anonymous
    let res = app.server.get("/api/admin/stats").await;
    assert_eq!(res.status_code(), 401);
}

// ═══════════════════════════════════════════════════════════════
// ADMIN LIST USERS FLOW
// ═══════════════════════════════════════════════════════════════
#[tokio::test]
async fn test_admin_list_users_flow() {
    let app = TestApp::new().await;
    let admin = create_admin_user(&app.db.pool).await;
    let token = login_as(&app, &admin.email, &admin.password).await;

    // Seed database for testing filters/search/pagination
    let user_verified = create_verified_user(&app.db.pool).await;
    create_verified_user(&app.db.pool).await;
    create_admin_user(&app.db.pool).await;
    create_unverified_user(&app.db.pool).await;
    create_unverified_user(&app.db.pool).await;

    // 1. Success list users
    let res = app
        .server
        .get("/api/admin/users")
        .add_header("Authorization", auth_header(&token))
        .await;
    assert_eq!(res.status_code(), 200);
    let body: Value = res.json();
    assert!(body["data"].is_array());
    assert!(body["pagination"]["total"].as_i64().unwrap() >= 5);

    // 2. Pagination test
    let res = app
        .server
        .get("/api/admin/users?page=1&per_page=2")
        .add_header("Authorization", auth_header(&token))
        .await;
    assert_eq!(res.status_code(), 200);
    let body: Value = res.json();
    assert_eq!(body["data"].as_array().unwrap().len(), 2);
    assert_eq!(body["pagination"]["per_page"], 2);

    // 3. Filter by role
    let res = app
        .server
        .get("/api/admin/users?role=admin")
        .add_header("Authorization", auth_header(&token))
        .await;
    assert_eq!(res.status_code(), 200);
    let body: Value = res.json();
    for u in body["data"].as_array().unwrap() {
        assert_eq!(u["role"], "admin");
    }

    // 4. Filter by is_verified
    let res = app
        .server
        .get("/api/admin/users?is_verified=false")
        .add_header("Authorization", auth_header(&token))
        .await;
    assert_eq!(res.status_code(), 200);
    let body: Value = res.json();
    for u in body["data"].as_array().unwrap() {
        assert_eq!(u["is_verified"], false);
    }

    // 5. Search test
    let search_term = &user_verified.username[..5];
    let res = app
        .server
        .get(&format!("/api/admin/users?search={}", search_term))
        .add_header("Authorization", auth_header(&token))
        .await;
    assert_eq!(res.status_code(), 200);
    let body: Value = res.json();
    let users = body["data"].as_array().unwrap();
    assert!(!users.is_empty());
}

// ═══════════════════════════════════════════════════════════════
// ADMIN GET USER BY ID FLOW
// ═══════════════════════════════════════════════════════════════
#[tokio::test]
async fn test_admin_get_user_flow() {
    let app = TestApp::new().await;
    let admin = create_admin_user(&app.db.pool).await;
    let token = login_as(&app, &admin.email, &admin.password).await;
    let user = create_verified_user(&app.db.pool).await;

    // 1. Success
    let res = app
        .server
        .get(&format!("/api/admin/users/{}", user.id))
        .add_header("Authorization", auth_header(&token))
        .await;
    assert_eq!(res.status_code(), 200);
    let body: Value = res.json();
    assert_eq!(body["data"]["id"], user.id.to_string());
    assert_eq!(body["data"]["email"], user.email);

    // 2. Not found
    let fake_id = uuid::Uuid::new_v4();
    let res = app
        .server
        .get(&format!("/api/admin/users/{}", fake_id))
        .add_header("Authorization", auth_header(&token))
        .await;
    assert_eq!(res.status_code(), 404);
}

// ═══════════════════════════════════════════════════════════════
// ADMIN UPDATE USER FLOW
// ═══════════════════════════════════════════════════════════════
#[tokio::test]
async fn test_admin_update_user_flow() {
    let app = TestApp::new().await;
    let admin = create_admin_user(&app.db.pool).await;
    let token = login_as(&app, &admin.email, &admin.password).await;

    // 1. Deactivate user and verify they cannot login
    let user_to_deactivate = create_verified_user(&app.db.pool).await;
    let res = app
        .server
        .patch(&format!("/api/admin/users/{}", user_to_deactivate.id))
        .add_header("Authorization", auth_header(&token))
        .json(&json!({"is_active": false}))
        .await;
    assert_eq!(res.status_code(), 200);
    assert_eq!(res.json::<Value>()["data"]["is_active"], false);

    let login_res = app
        .server
        .post("/api/auth/login")
        .json(&json!({"email": user_to_deactivate.email, "password": user_to_deactivate.password}))
        .await;
    assert_eq!(login_res.status_code(), 403);

    // 2. Promote user to admin
    let user_to_promote = create_verified_user(&app.db.pool).await;
    let res = app
        .server
        .patch(&format!("/api/admin/users/{}", user_to_promote.id))
        .add_header("Authorization", auth_header(&token))
        .json(&json!({"role": "admin"}))
        .await;
    assert_eq!(res.status_code(), 200);
    assert_eq!(res.json::<Value>()["data"]["role"], "admin");

    // 3. Verify user manually
    let user_unverified = create_unverified_user(&app.db.pool).await;
    let res = app
        .server
        .patch(&format!("/api/admin/users/{}", user_unverified.id))
        .add_header("Authorization", auth_header(&token))
        .json(&json!({"is_verified": true}))
        .await;
    assert_eq!(res.status_code(), 200);
    assert_eq!(res.json::<Value>()["data"]["is_verified"], true);

    // 4. Invalid role
    let user_invalid_role = create_verified_user(&app.db.pool).await;
    let res = app
        .server
        .patch(&format!("/api/admin/users/{}", user_invalid_role.id))
        .add_header("Authorization", auth_header(&token))
        .json(&json!({"role": "superadmin"}))
        .await;
    assert_eq!(res.status_code(), 422);

    // 5. Not found
    let res = app
        .server
        .patch(&format!("/api/admin/users/{}", uuid::Uuid::new_v4()))
        .add_header("Authorization", auth_header(&token))
        .json(&json!({"is_active": false}))
        .await;
    assert_eq!(res.status_code(), 404);
}

// ═══════════════════════════════════════════════════════════════
// ADMIN DELETE USER FLOW
// ═══════════════════════════════════════════════════════════════
#[tokio::test]
async fn test_admin_delete_user_flow() {
    let app = TestApp::new().await;
    let admin = create_admin_user(&app.db.pool).await;
    let token = login_as(&app, &admin.email, &admin.password).await;

    // 1. Success delete
    let user = create_verified_user(&app.db.pool).await;
    let res = app
        .server
        .delete(&format!("/api/admin/users/{}", user.id))
        .add_header("Authorization", auth_header(&token))
        .await;
    assert_eq!(res.status_code(), 200);

    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)")
        .bind(user.id)
        .fetch_one(&app.db.pool)
        .await
        .unwrap();
    assert!(!exists, "User harus terhapus dari database");

    // 2. Not found
    let res = app
        .server
        .delete(&format!("/api/admin/users/{}", uuid::Uuid::new_v4()))
        .add_header("Authorization", auth_header(&token))
        .await;
    assert_eq!(res.status_code(), 404);

    // 3. Forbidden for user
    let user_forbidden = create_verified_user(&app.db.pool).await;
    let user_forbidden_token = login_as(&app, &user_forbidden.email, &user_forbidden.password).await;
    let user_to_delete = create_verified_user(&app.db.pool).await;

    let res = app
        .server
        .delete(&format!("/api/admin/users/{}", user_to_delete.id))
        .add_header("Authorization", auth_header(&user_forbidden_token))
        .await;
    assert_eq!(res.status_code(), 403);
}

// ═══════════════════════════════════════════════════════════════
// ADMIN REVOKE SESSIONS
// ═══════════════════════════════════════════════════════════════
#[tokio::test]
async fn test_admin_revoke_user_sessions_flow() {
    let app = TestApp::new().await;
    let admin = create_admin_user(&app.db.pool).await;
    let admin_token = login_as(&app, &admin.email, &admin.password).await;

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

    let res = app
        .server
        .post(&format!("/api/admin/users/{}/revoke-sessions", user.id))
        .add_header("Authorization", auth_header(&admin_token))
        .await;

    assert_eq!(res.status_code(), 200);
    let body: Value = res.json();
    assert!(body["data"]["revoked_count"].as_i64().unwrap() >= 1);

    let refresh_res = app
        .server
        .post("/api/auth/refresh")
        .json(&json!({"refresh_token": refresh1}))
        .await;
    assert_eq!(refresh_res.status_code(), 401);
}

// ═══════════════════════════════════════════════════════════════
// ADMIN DELETE EMAIL (ZOHO)
// ═══════════════════════════════════════════════════════════════
#[tokio::test]
async fn test_admin_delete_email_permissions() {
    let app = TestApp::new().await;

    // 1. Unauthorized for anonymous
    let res = app.server.delete("/api/admin/emails?folder_id=123&message_id=456").await;
    assert_eq!(res.status_code(), 401);

    // 2. Forbidden for regular user
    let user = create_verified_user(&app.db.pool).await;
    let user_token = login_as(&app, &user.email, &user.password).await;

    let res = app
        .server
        .delete("/api/admin/emails?folder_id=123&message_id=456")
        .add_header("Authorization", auth_header(&user_token))
        .await;
    assert_eq!(res.status_code(), 403);

    // 3. BadRequest/Failure (from mock Zoho/fake auth token) for admin, showing it hits the handler
    let admin = create_admin_user(&app.db.pool).await;
    let admin_token = login_as(&app, &admin.email, &admin.password).await;

    let res = app
        .server
        .delete("/api/admin/emails?folder_id=123&message_id=456")
        .add_header("Authorization", auth_header(&admin_token))
        .await;
    // Since access token is dummy/empty/invalid in test environment, Zoho API will return an error, causing a 400 BadRequest.
    assert_eq!(res.status_code(), 400);
}
