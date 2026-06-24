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
            "{}/api/auth/reset-password?token={}",
            self.config.app_url.trim_end_matches('/'), token
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

    pub async fn delete_email(
        &self,
        folder_id: &str,
        message_id: &str,
        expunge: Option<bool>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let data = self.state.lock().unwrap().clone();
        let mut url = format!(
            "https://mail.zoho.com/api/accounts/{}/folders/{}/messages/{}",
            data.account_id, folder_id, message_id
        );
        if let Some(expunge) = expunge {
            url.push_str(&format!("?expunge={}", expunge));
        }

        let res = self
            .client
            .delete(&url)
            .header(
                "Authorization",
                format!("Zoho-oauthtoken {}", data.access_token),
            )
            .send()
            .await?;

        if !res.status().is_success() {
            let text = res.text().await.unwrap_or_default();
            error!("Zoho delete email failed: {}", text);
            return Err(format!("Failed to delete email from Zoho: {}", text).into());
        }

        info!("Email deleted successfully via Zoho!");
        Ok(())
    }

    pub async fn delete_all_sent_emails(&self) -> Result<usize, Box<dyn std::error::Error>> {
        let data = self.state.lock().unwrap().clone();

        let mut total_deleted_count = 0;
        let mut start_index = 1;
        let mut loop_count = 0;

        // Limit to 20 iterations (max 4000 emails) to avoid potential infinite loops
        while loop_count < 20 {
            loop_count += 1;

            let search_url = format!(
                "https://mail.zoho.com/api/accounts/{}/messages/search?searchKey=from:{}&limit=200&start={}",
                data.account_id, self.config.smtp_from_email, start_index
            );
            let res = self
                .client
                .get(&search_url)
                .header(
                    "Authorization",
                    format!("Zoho-oauthtoken {}", data.access_token),
                )
                .send()
                .await?;

            if !res.status().is_success() {
                let text = res.text().await.unwrap_or_default();
                error!("Zoho search messages failed: {}", text);
                return Err(format!("Failed to search messages from Zoho: {}", text).into());
            }

            let messages_json: serde_json::Value = res.json().await?;
            let messages = match messages_json["data"].as_array() {
                Some(arr) if !arr.is_empty() => arr,
                _ => break, // No more matching messages
            };

            let mut batch_deleted = 0;
            let mut skip_count = 0;
            for msg in messages {
                let message_id = match &msg["messageId"] {
                    serde_json::Value::String(s) => s.clone(),
                    serde_json::Value::Number(n) => n.to_string(),
                    _ => {
                        skip_count += 1;
                        continue;
                    }
                };

                let folder_id = match &msg["folderId"] {
                    serde_json::Value::String(s) => s.clone(),
                    serde_json::Value::Number(n) => n.to_string(),
                    _ => {
                        skip_count += 1;
                        continue;
                    }
                };

                // expunge: true deletes permanently to prevent space from filling up
                if let Err(e) = self.delete_email(&folder_id, &message_id, Some(true)).await {
                    error!("Failed to delete message {}: {:?}", message_id, e);
                    skip_count += 1;
                } else {
                    batch_deleted += 1;
                }
            }

            total_deleted_count += batch_deleted;

            // If no messages were deleted and no messages were skipped, we have reached the end
            if batch_deleted == 0 && skip_count == 0 {
                break;
            }

            // Increment start_index by the number of messages skipped in this batch
            start_index += skip_count;
        }

        info!("Deleted {} sent emails successfully", total_deleted_count);
        Ok(total_deleted_count)
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
