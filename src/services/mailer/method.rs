use crate::{config::Config, services::mailer::SharedZoho};
use reqwest::Client;
use tera::Tera;
use tracing::{error, info};

pub struct ZohoMailer {
    client: Client,
    tera: Tera,
    pub state: SharedZoho,
    config: Config,
}

impl ZohoMailer {
    pub fn new(state: SharedZoho) -> Result<Self, Box<dyn std::error::Error>> {
        let tera = Tera::new(concat!(env!("CARGO_MANIFEST_DIR"), "/templates/**/*"))?;

        Ok(Self {
            client: Client::new(),
            tera,
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

        let mut context = tera::Context::new();
        context.insert("username", username);
        context.insert("verify_url", &verify_url);
        context.insert("app_name", &self.config.smtp_from_name);

        let html = self
            .tera
            .render("mail_verify.html", &context)
            .map_err(|e| {
                error!("Failed to render verification email template: {:?}", e);
                e
            })?;

        self.send_email(
            to_email,
            &format!("Verifikasi Email - {}", self.config.smtp_from_name),
            html,
        )
        .await
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
        let mut context = tera::Context::new();
        context.insert("username", username);
        context.insert("reset_url", &reset_url);
        context.insert("app_name", &self.config.smtp_from_name);
        context.insert("subject", "Reset Password");

        let html = self.tera.render("mail_reset_password.html", &context)?;

        self.send_email(
            to_email,
            &format!("Reset Password - {}", self.config.smtp_from_name),
            html,
        )
        .await
    }
}

pub async fn get_access_token(
    code: &str,
    state: &SharedZoho,
) -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new();
    let config = Config::from_env()?;

    let params = [
        ("code", code),
        ("client_id", &config.client_id),
        ("client_secret", &config.client_secret),
        ("redirect_uri", &config.redirect_url),
        ("grant_type", "authorization_code"),
    ];

    let res = client
        .post("https://accounts.zoho.com/oauth/v2/token")
        .form(&params)
        .send()
        .await?;

    let json: serde_json::Value = res.json().await?;

    let access_token = json["access_token"]
        .as_str()
        .ok_or("missing access_token")?;

    let mut data = state.lock().unwrap();
    data.access_token = access_token.to_string();

    Ok(())
}

// pub async fn get_account_id(state: &SharedZoho) -> Result<(), Box<dyn std::error::Error>> {
//     let client = Client::new();
//     let token = { state.lock().unwrap().access_token.clone() };
//
//     let res = client
//         .get("https://mail.zoho.com/api/accounts")
//         .header("Authorization", format!("Zoho-oauthtoken {}", token))
//         .send()
//         .await?;
//
//     // ← Tambahkan ini untuk lihat response aslinya
//     let body = res.text().await?;
//     tracing::info!("Zoho accounts response: {}", body);
//
//     let json: serde_json::Value = serde_json::from_str(&body)?;
//
//     let account_id = json["data"][0]["accountId"] // ← coba "accountId" bukan "account_id"
//         .as_str()
//         .ok_or("missing account_id")?;
//
//     let mut data = state.lock().unwrap();
//     data.account_id = account_id.to_string();
//
//     Ok(())
// }
