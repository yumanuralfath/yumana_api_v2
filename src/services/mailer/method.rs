use crate::{config::Config, services::mailer::SharedZoho};
use askama::Template;
use reqwest::Client;
use tracing::{error, info};

#[derive(Template)]
#[template(path = "mail_verify.html")]
struct VerifyEmailTemplate<'a> {
    username: &'a str,
    verify_url: &'a str,
    app_name: &'a str,
    subject: &'a str,
}

#[derive(Template)]
#[template(path = "mail_reset_password.html")]
struct ResetPasswordTemplate<'a> {
    username: &'a str,
    reset_url: &'a str,
    app_name: &'a str,
    subject: &'a str,
}

pub struct ZohoMailer {
    client: Client,
    pub state: SharedZoho,
    config: Config,
}

impl ZohoMailer {
    pub fn new(state: SharedZoho) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            client: Client::new(),
            config: Config::from_env()?,
            state,
        })
    }

    pub async fn send_email(
        &self,
        to_email: &str,
        subject: &str,
        html_body: String,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let data = self.state.lock().unwrap().clone();

        tracing::info!("ACCOUNT_ID: {}", data.account_id);
        tracing::info!("API_DOMAIN: {}", data.api_domain);
        tracing::info!("ACCESS_TOKEN: {}", data.access_token);

        let url = format!(
            "https://mail.zoho.com/api/accounts/{}/messages",
            data.account_id
        );

        let payload = serde_json::json!({
            "fromAddress": self.config.smtp_from_email,
            "toAddress": to_email,
            "subject": subject,
            "content": html_body,
            "askReceipt": "no"
        });

        let res = self
            .client
            .post(url)
            .header(
                "Authorization",
                format!("Zoho-oauthtoken {}", data.access_token),
            )
            .json(&payload)
            .send()
            .await?;

        if !res.status().is_success() {
            let text = res.text().await.unwrap_or_default();
            error!("Zoho send email failed: {}", text);
            return Err("Failed to send email".into());
        }

        info!("Email sent successfully via Zoho!");
        Ok(())
    }

    pub async fn send_verification_email(
        &self,
        to_email: &str,
        username: &str,
        token: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let verify_url = format!(
            "{}/api/auth/verify-email?token={}",
            self.config.app_url, token
        );

        let subject = format!("Verifikasi Email - {}", self.config.smtp_from_name);
        let template = VerifyEmailTemplate {
            username,
            verify_url: &verify_url,
            app_name: &self.config.smtp_from_name,
            subject: &subject,
        };

        let html = template.render().map_err(|e| {
            error!("Failed to render verification email template: {:?}", e);
            e
        })?;

        self.send_email(to_email, &subject, html).await
    }

    pub async fn send_password_reset_email(
        &self,
        to_email: &str,
        username: &str,
        token: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let reset_url = format!(
            "{}/reset-password?token={}",
            self.config.frontend_url, token
        );

        let subject = format!("Reset Password - {}", self.config.smtp_from_name);
        let template = ResetPasswordTemplate {
            username,
            reset_url: &reset_url,
            app_name: &self.config.smtp_from_name,
            subject: &subject,
        };

        let html = template.render().map_err(|e| {
            error!("Failed to render password reset template: {:?}", e);
            e
        })?;

        self.send_email(to_email, &subject, html).await
    }
}

// pub async fn get_access_token(
//     code: &str,
//     state: &SharedZoho,
// ) -> Result<(), Box<dyn std::error::Error>> {
//     let client = Client::new();
//     let config = Config::from_env()?;
//
//     let params = [
//         ("code", code),
//         ("client_id", &config.client_id),
//         ("client_secret", &config.client_secret),
//         ("redirect_uri", &config.redirect_url),
//         ("grant_type", "authorization_code"),
//     ];
//
//     let res = client
//         .post("https://accounts.zoho.com/oauth/v2/token")
//         .form(&params)
//         .send()
//         .await?;
//
//     let json: serde_json::Value = res.json().await?;
//
//     let access_token = json["access_token"]
//         .as_str()
//         .ok_or("missing access_token")?;
//
//     let mut data = state.lock().unwrap();
//     data.access_token = access_token.to_string();
//
//     Ok(())
// }
