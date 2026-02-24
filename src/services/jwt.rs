use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::models::user::UserRole;
use crate::utils::errors::{AppError, AppResult};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AccessTokenClaims {
    pub sub: String, // user id
    pub email: String,
    pub username: String,
    pub role: UserRole,
    pub jti: String,
    pub exp: i64,
    pub iat: i64,
    pub token_type: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RefreshTokenClaims {
    pub sub: String, // user id
    pub jti: String, // unique token id
    pub exp: i64,
    pub iat: i64,
    pub token_type: String,
}

pub struct JwtService {
    access_secret: String,
    refresh_secret: String,
    access_expiry: i64,
    refresh_expiry: i64,
}

impl JwtService {
    pub fn new(
        access_secret: String,
        refresh_secret: String,
        access_expiry: i64,
        refresh_expiry: i64,
    ) -> Self {
        Self {
            access_secret,
            refresh_secret,
            access_expiry,
            refresh_expiry,
        }
    }

    pub fn generate_access_token(
        &self,
        user_id: Uuid,
        email: &str,
        username: &str,
        role: &UserRole,
    ) -> AppResult<String> {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let claims = AccessTokenClaims {
            sub: user_id.to_string(),
            email: email.to_string(),
            username: username.to_string(),
            role: role.clone(),
            exp: now + self.access_expiry,
            iat: now,
            token_type: "access".to_string(),
            jti: Uuid::new_v4().to_string(),
        };

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.access_secret.as_bytes()),
        )
        .map_err(AppError::JwtError)
    }

    pub fn generate_refresh_token(&self, user_id: Uuid, jti: &str) -> AppResult<String> {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let claims = RefreshTokenClaims {
            sub: user_id.to_string(),
            jti: jti.to_string(),
            exp: now + self.refresh_expiry,
            iat: now,
            token_type: "refresh".to_string(),
        };

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.refresh_secret.as_bytes()),
        )
        .map_err(AppError::JwtError)
    }

    pub fn verify_access_token(&self, token: &str) -> AppResult<AccessTokenClaims> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = true;
        validation.required_spec_claims.insert("exp".to_string());

        let token_data = decode::<AccessTokenClaims>(
            token,
            &DecodingKey::from_secret(self.access_secret.as_bytes()),
            &validation,
        )
        .map_err(|_| AppError::Unauthorized("Invalid or expired access token".to_string()))?;

        if token_data.claims.token_type != "access" {
            return Err(AppError::Unauthorized("Invalid token type".to_string()));
        }

        Ok(token_data.claims)
    }

    pub fn verify_refresh_token(&self, token: &str) -> AppResult<RefreshTokenClaims> {
        let token_data = decode::<RefreshTokenClaims>(
            token,
            &DecodingKey::from_secret(self.refresh_secret.as_bytes()),
            &Validation::default(),
        )
        .map_err(|_| AppError::Unauthorized("Invalid or expired refresh token".to_string()))?;

        if token_data.claims.token_type != "refresh" {
            return Err(AppError::Unauthorized("Invalid token type".to_string()));
        }

        Ok(token_data.claims)
    }
}
