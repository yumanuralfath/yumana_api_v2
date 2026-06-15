use crate::utils::errors::{AppError, AppResult};
use regex::Regex;
use std::sync::LazyLock;

static EMAIL_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$").unwrap()
});

pub fn validate_email(email: &str) -> AppResult<()> {
    if email.is_empty() {
        return Err(AppError::BadRequest("Email cannot be empty".to_string()));
    }
    if !EMAIL_REGEX.is_match(email) {
        return Err(AppError::BadRequest("Invalid email format".to_string()));
    }
    Ok(())
}

pub fn validate_length(field: &str, value: &str, min: usize, max: usize) -> AppResult<()> {
    let len = value.chars().count();
    if len < min || len > max {
        return Err(AppError::BadRequest(format!(
            "{} must be between {} and {} characters",
            field, min, max
        )));
    }
    Ok(())
}
