use askama::Template;
use axum::response::{Html, IntoResponse};
use axum::http::StatusCode;

#[derive(Template)]
#[template(path = "verify_result.html")]
pub struct VerifyResultTemplate<'a> {
    pub title: &'a str,
    pub message: &'a str,
    pub success: bool,
    pub action_url: &'a str,
    pub action_text: &'a str,
}

pub fn render_verify_result(
    title: &str,
    message: &str,
    is_success: bool,
    action_url: &str,
    action_text: &str,
) -> impl IntoResponse {
    let template = VerifyResultTemplate {
        title,
        message,
        success: is_success,
        action_url,
        action_text,
    };

    match template.render() {
        Ok(html) => (StatusCode::OK, Html(html)).into_response(),
        Err(e) => {
            tracing::error!("Template rendering error: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error").into_response()
        }
    }
}

#[derive(Template)]
#[template(path = "reset_password.html")]
pub struct ResetPasswordPageTemplate<'a> {
    pub token: &'a str,
    pub is_valid: bool,
    pub error_msg: Option<&'a str>,
    pub action_url: &'a str,
}

pub fn render_reset_password_page(
    token: &str,
    is_valid: bool,
    error_msg: Option<&str>,
    action_url: &str,
) -> impl IntoResponse {
    let template = ResetPasswordPageTemplate {
        token,
        is_valid,
        error_msg,
        action_url,
    };

    match template.render() {
        Ok(html) => (StatusCode::OK, Html(html)).into_response(),
        Err(e) => {
            tracing::error!("Template rendering error: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error").into_response()
        }
    }
}

