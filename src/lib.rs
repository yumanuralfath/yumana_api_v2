pub mod config;
pub mod handlers;
pub mod middleware;
pub mod models;
pub mod routes;
pub mod services;
pub mod utils;

use crate::config::Config;
use axum::http;
use http::HeaderValue;
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;
use std::time::Duration;
use tower_http::cors::CorsLayer;

use axum::http::request::Parts;
use tower_http::cors::AllowOrigin;
use tower_http::cors::Any;

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

pub fn init_cors(config: &Config) -> CorsLayer {
    if cfg!(debug_assertions) {
        CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers(Any)
    } else {
        let base_domain = config
            .domain_url
            .as_ref()
            .expect("DOMAIN_URL harus diset di release build")
            .to_string();

        CorsLayer::new()
            .allow_origin(AllowOrigin::predicate(
                move |origin: &HeaderValue, _parts: &Parts| {
                    if let Ok(origin_str) = origin.to_str() {
                        // origin format biasanya: https://auth.yumana.my.id
                        if let Some(host) = origin_str
                            .strip_prefix("https://")
                            .or_else(|| origin_str.strip_prefix("http://"))
                        {
                            return host == base_domain
                                || host.ends_with(&format!(".{}", base_domain));
                        }
                    }
                    false
                },
            ))
            .allow_methods(Any)
            .allow_headers(Any)
            .allow_credentials(true)
    }
}
