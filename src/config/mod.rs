pub mod state;
use std::env;

#[derive(Debug, Clone)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub database_url: String,
    pub jwt_access_secret: String,
    pub jwt_refresh_secret: String,
    pub jwt_access_expiry: i64,
    pub jwt_refresh_expiry: i64,
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_username: String,
    pub smtp_password: String,
    pub smtp_from_name: String,
    pub smtp_from_email: String,
    pub app_url: String,
    pub frontend_url: String,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        let domain_url = env::var("DOMAIN_URL").ok();

        let app_url = if let Some(domain) = &domain_url {
            format!("https://{}", domain)
        } else {
            env::var("APP_URL").unwrap_or_else(|_| "http://localhost:8080".to_string())
        };

        let frontend_url = if let Some(domain) = &domain_url {
            format!("https://www.{}", domain)
        } else {
            env::var("FRONTEND_URL").unwrap_or_else(|_| "http://localhost:3000".to_string())
        };
        Ok(Config {
            host: env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string()),
            port: env::var("PORT")
                .unwrap_or_else(|_| "8080".to_string())
                .parse()?,
            database_url: env::var("DATABASE_URL")?,
            jwt_access_secret: env::var("JWT_ACCESS_SECRET")?,
            jwt_refresh_secret: env::var("JWT_REFRESH_SECRET")?,
            jwt_access_expiry: env::var("JWT_ACCESS_EXPIRY")
                .unwrap_or_else(|_| "900".to_string())
                .parse()?,
            jwt_refresh_expiry: env::var("JWT_REFRESH_EXPIRY")
                .unwrap_or_else(|_| "604800".to_string())
                .parse()?,
            smtp_host: env::var("SMTP_HOST").unwrap_or_else(|_| "smtp.zoho.com".to_string()),
            smtp_port: env::var("SMTP_PORT")
                .unwrap_or_else(|_| "465".to_string())
                .parse()?,
            smtp_username: env::var("SMTP_USERNAME")?,
            smtp_password: env::var("SMTP_PASSWORD")?,
            smtp_from_name: env::var("SMTP_FROM_NAME").unwrap_or_else(|_| "Yumana".to_string()),
            smtp_from_email: env::var("SMTP_FROM_EMAIL")?,
            app_url,
            frontend_url,
        })
    }
}
