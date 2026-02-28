use axum::http::HeaderValue;
use axum_test::TestServer;
use std::sync::Arc;

use sqlx::postgres::PgPoolOptions;

use yumana_api_v2::{
    config::{Config, state::AppState},
    routes::create_router,
    services::{email::EmailService, jwt::JwtService},
};

use super::db::TestDb;

/// Config test — semua value hardcode, SMTP dummy port tidak akan connect
pub fn test_config(database_url: &str) -> Config {
    Config {
        domain_url: Some("test_website.com".to_string()),
        host: "127.0.0.1".to_string(),
        port: 8080,
        database_url: database_url.to_string(),
        jwt_access_secret: "test-access-secret-panjang-sekali-harus-32-char-min".to_string(),
        jwt_refresh_secret: "test-refresh-secret-panjang-sekali-harus-32-char-min".to_string(),
        jwt_access_expiry: 900,
        jwt_refresh_expiry: 604800,
        // Port 9999 — tidak ada server SMTP di sini, email tidak benar-benar dikirim
        smtp_host: "127.0.0.1".to_string(),
        smtp_port: 9999,
        smtp_username: "test@test.com".to_string(),
        smtp_password: "dummy".to_string(),
        smtp_from_name: "TestApp".to_string(),
        smtp_from_email: "test@test.com".to_string(),
        app_url: "http://localhost:8080".to_string(),
        frontend_url: "http://localhost:3000".to_string(),
    }
}

#[derive(Debug)]
pub struct TestApp {
    pub server: TestServer,
    pub db: TestDb,
}

impl TestApp {
    pub async fn new() -> Self {
        let db = TestDb::new().await;

        // Buat URL dengan schema test
        let base_url = std::env::var("DATABASE_URL").expect("DATABASE_URL harus ada di .env.test");
        let schema_url = format!("{}?options=-csearch_path%3D\"{}\"", base_url, db.schema);
        let config = test_config(&schema_url);

        // Pool yang mengarah ke schema test
        let test_pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(&schema_url)
            .await
            .expect("Gagal connect ke test schema pool");

        let jwt = Arc::new(JwtService::new(
            config.jwt_access_secret.clone(),
            config.jwt_refresh_secret.clone(),
            config.jwt_access_expiry,
            config.jwt_refresh_expiry,
        ));

        // EmailService dengan SMTP dummy — init akan sukses, pengiriman gagal saat runtime
        // karena test server spawn email di background task (tokio::spawn), kegagalan ini
        // tidak crash handler, hanya log error
        let email = Arc::new(EmailService::new(&config).expect("Gagal init EmailService"));

        let state = AppState {
            db: test_pool,
            jwt,
            email,
            config: Arc::new(config),
        };

        let router = create_router(state);
        let server = TestServer::new(router).expect("Gagal buat TestServer");

        Self { server, db }
    }
}

pub fn auth_header(token: &str) -> HeaderValue {
    HeaderValue::from_str(&format!("Bearer {}", token)).unwrap()
}
