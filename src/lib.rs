pub mod config;
pub mod handlers;
pub mod middleware;
pub mod models;
pub mod routes;
pub mod services;
pub mod utils;

use crate::config::Config;
use crate::services::mailer::SharedZoho;
use crate::services::mailer::ZohoData;
use crate::services::mailer::method::ZohoMailer;
use axum::http;
use http::HeaderValue;
use sqlx::postgres::PgPoolOptions;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tower_http::cors::CorsLayer;

use axum::http::request::Parts;
use tower_http::cors::AllowOrigin;
use tower_http::cors::Any;

use services::jwt::JwtService;

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

pub fn init_services(config: &Config) -> (Arc<JwtService>, Arc<ZohoMailer>) {
    let jwt = Arc::new(JwtService::new(
        config.jwt_access_secret.clone(),
        config.jwt_refresh_secret.clone(),
        config.jwt_access_expiry,
        config.jwt_refresh_expiry,
    ));

    let zoho_state: SharedZoho = Arc::new(Mutex::new(ZohoData {
        access_token: "".into(),
        refresh_token: config.zoho_refresh_token.clone(),
        client_id: config.client_id.clone(),
        client_secret: config.client_secret.clone(),
        api_domain: "https://www.zohoapis.com".into(),
        token_type: "Bearer".into(),
        expires_in: 3600,
        account_id: config.account_id.clone(),
    }));

    let email = Arc::new(ZohoMailer::new(zoho_state).expect("Email init failed"));

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
    }
}

pub async fn run_migrations(db: &sqlx::PgPool) -> anyhow::Result<()> {
    sqlx::migrate!("./migrations").run(db).await?;
    Ok(())
}
