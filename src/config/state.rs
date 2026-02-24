use sqlx::PgPool;
use std::sync::Arc;

use crate::config::Config;
use crate::services::{email::EmailService, jwt::JwtService};

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub jwt: Arc<JwtService>,
    pub email: Arc<EmailService>,
    pub config: Arc<Config>,
}
