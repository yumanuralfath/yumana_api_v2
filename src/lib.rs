pub mod config;
pub mod handlers;
pub mod middleware;
pub mod models;
pub mod routes;
pub mod services;
pub mod utils;

use crate::config::Config;
use std::sync::Arc;
use std::time::Duration;

use sqlx::postgres::PgPoolOptions;
use tower_http::cors::{Any, CorsLayer};

use services::{email::EmailService, jwt::JwtService};

pub fn init_tracing_env() {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "yumana_api_v2=debug,tower_http=debug".into()),
        )
        .init();
}

pub async fn init_db(database_url: &str) -> anyhow::Result<sqlx::PgPool> {
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .min_connections(1)
        .acquire_timeout(Duration::from_secs(10))
        .idle_timeout(Duration::from_secs(300))
        .connect(database_url)
        .await?;

    tracing::info!("Database connected");
    Ok(pool)
}

pub fn init_services(config: &Config) -> (Arc<JwtService>, Arc<EmailService>) {
    let jwt = Arc::new(JwtService::new(
        config.jwt_access_secret.clone(),
        config.jwt_refresh_secret.clone(),
        config.jwt_access_expiry,
        config.jwt_refresh_expiry,
    ));

    let email = Arc::new(EmailService::new(config).expect("Email init failed"));

    (jwt, email)
}

pub fn init_cors() -> CorsLayer {
    CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any)
}
