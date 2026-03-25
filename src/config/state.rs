use sqlx::PgPool;
use std::sync::Arc;

use crate::config::Config;
use crate::services::jwt::JwtService;
use crate::services::mailer::method::ZohoMailer;

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub jwt: Arc<JwtService>,
    pub email: Arc<ZohoMailer>,
    pub config: Arc<Config>,
}
