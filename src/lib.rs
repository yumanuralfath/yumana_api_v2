mod config;
mod handlers;
mod middleware;
mod models;
mod routes;
mod services;
mod utils;

pub use crate::config::{Config, state::AppState};
pub use crate::middleware::auth;
pub use crate::models::user;
pub use crate::routes::create_router;
pub use crate::services::{jwt, mailer};
pub use crate::utils::{auth as utils_auth, errors, response, ui, validation};

use axum::http::{HeaderValue, request::Parts};
use sqlx::postgres::PgPoolOptions;
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tower_http::cors::{AllowOrigin, Any, CorsLayer};

pub fn init_tracing_env() {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "yumana_api_v2=debug,tower_http=debug".into()),
        )
        .init();
}

pub async fn init_db(database_url: &str) -> Result<sqlx::PgPool, Box<dyn std::error::Error>> {
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

pub fn init_services(config: &Config) -> (Arc<jwt::JwtService>, Arc<mailer::method::ZohoMailer>) {
    let jwt = Arc::new(jwt::JwtService::new(
        config.jwt_access_secret.clone(),
        config.jwt_refresh_secret.clone(),
        config.jwt_access_expiry,
        config.jwt_refresh_expiry,
    ));

    let zoho_state: mailer::SharedZoho = Arc::new(Mutex::new(mailer::ZohoData {
        access_token: "".into(),
        refresh_token: config.zoho_refresh_token.clone(),
        client_id: config.client_id.clone(),
        client_secret: config.client_secret.clone(),
        api_domain: "https://www.zohoapis.com".into(),
        token_type: "Bearer".into(),
        expires_in: 3600,
        account_id: config.account_id.clone(),
    }));

    let email = Arc::new(mailer::method::ZohoMailer::new(zoho_state).expect("Email init failed"));

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

pub async fn run_migrations(db: &sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    sqlx::migrate!("./migrations").run(db).await?;
    Ok(())
}
