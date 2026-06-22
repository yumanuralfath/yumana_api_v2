use sqlx::PgPool;
use std::sync::Arc;

use crate::config::Config;
use crate::services::jwt::JwtService;
use crate::services::mailer::method::ZohoMailer;
use crate::bootstrap;

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub jwt: Arc<JwtService>,
    pub email: Arc<ZohoMailer>,
    pub config: Arc<Config>,
}

impl AppState {
    pub async fn new(config: Config) -> Result<Self, Box<dyn std::error::Error>> {
        let db = bootstrap::init_db(&config.database_url).await?;
        bootstrap::run_migrations(&db).await?;

        let (jwt, email) = bootstrap::init_services(&config);

        // Spawn background task zoho token refresh secara otomatis
        let refresh_state = email.state.clone();
        tokio::spawn(async move {
            crate::services::mailer::callback::refresh_auth(refresh_state).await;
        });

        Ok(Self {
            db,
            jwt,
            email,
            config: Arc::new(config),
        })
    }
}
