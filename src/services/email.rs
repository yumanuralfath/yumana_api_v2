use anyhow::{Ok, Result};
use lettre::{
    Message, SmtpTransport, Transport,
    message::{Mailbox, header::ContentType},
    transport::smtp::authentication::Credentials,
};
use tera::{Context, Tera};
use tracing::{error, info};

use crate::config::Config;

pub struct EmailService {
    mailer: SmtpTransport,
    tera: Tera,
    from_name: String,
    from_email: String,
    app_url: String,
    frontend_url: String,
}

impl EmailService {
    pub fn new(config: &Config) -> anyhow::Result<Self> {
        let creds = Credentials::new(config.smtp_username.clone(), config.smtp_password.clone());

        // change not use AsyncSmtpTransport
        // let mailer = AsyncSmtpTransport::<Tokio1Executor>::relay(&config.smtp_host)?
        //     .port(config.smtp_port)
        //     .credentials(creds)
        //     .build();

        let mailer = SmtpTransport::relay(&config.smtp_host)?
            .credentials(creds)
            .build();
        // info!("mailer: {:?}", mailer);

        let tera = Tera::new("templates/**/*")?;
        // info!("Loaded tera template: {:#?}", tera);

        Ok(Self {
            mailer,
            tera,
            from_name: config.smtp_from_name.clone(),
            from_email: config.smtp_from_email.clone(),
            app_url: config.app_url.clone(),
            frontend_url: config.frontend_url.clone(),
        })
    }

    async fn send_email(
        &self,
        to_email: &str,
        to_name: &str,
        subject: &str,
        html_body: String,
    ) -> Result<()> {
        let from = Mailbox::new(Some(self.from_name.clone()), self.from_email.parse()?);

        let to = Mailbox::new(Some(to_name.to_string()), to_email.parse()?);

        let email = Message::builder()
            .from(from)
            .to(to)
            .subject(subject)
            .header(ContentType::TEXT_HTML)
            .body(html_body)?;

        self.mailer.send(&email).map_err(|e| {
            error!("Could not send email: {e:?}");
            e
        })?;

        info!("Email sent successfully!");
        Ok(())
    }

    pub async fn send_verification_email(
        &self,
        to_email: &str,
        username: &str,
        token: &str,
    ) -> Result<()> {
        let verify_url = format!("{}/api/auth/verify-email?token={}", self.app_url, token);

        let mut context = Context::new();
        context.insert("username", username);
        context.insert("verify_url", &verify_url);
        context.insert("app_name", &self.from_name);
        context.insert("subject", "Verifikasi Email");

        let html = self.tera.render("mail_verify.html", &context)?;

        self.send_email(
            to_email,
            username,
            &format!("Verifikasi Email - {}", self.from_name),
            html,
        )
        .await
    }

    pub async fn send_password_reset_email(
        &self,
        to_email: &str,
        username: &str,
        token: &str,
    ) -> Result<()> {
        let reset_url = format!("{}/reset-password?token={}", self.frontend_url, token);
        let mut context = Context::new();
        context.insert("username", username);
        context.insert("reset_url", &reset_url);
        context.insert("app_name", &self.from_name);
        context.insert("subject", "Reset Password");

        let html = self.tera.render("mail_reset_password.html", &context)?;

        self.send_email(
            to_email,
            username,
            &format!("Reset Password - {}", self.from_name),
            html,
        )
        .await
    }
}

// Use template engine tera instead use html in rust wkwwk;
// fn email_template_verification(username: &str, verify_url: &str, app_name: &str) -> String {
//     format!(
//         r#"<!DOCTYPE html>
// <html>
// <head>
//   <meta charset="UTF-8">
//   <meta name="viewport" content="width=device-width, initial-scale=1.0">
// </head>
// <body style="margin:0;padding:0;background:#f4f4f5;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;">
//   <table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f4f5;padding:40px 20px;">
//     <tr><td align="center">
//       <table width="520" cellpadding="0" cellspacing="0" style="background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 2px 12px rgba(0,0,0,0.08);">
//         <!-- Header -->
//         <tr><td style="background:linear-gradient(135deg,#6366f1,#8b5cf6);padding:36px;text-align:center;">
//           <h1 style="color:#fff;margin:0;font-size:28px;font-weight:700;letter-spacing:-0.5px">{app_name}</h1>
//         </td></tr>
//         <!-- Body -->
//         <tr><td style="padding:40px 36px;">
//           <h2 style="color:#111827;margin:0 0 12px;font-size:22px;">Halo, {username}! 👋</h2>
//           <p style="color:#6b7280;line-height:1.6;margin:0 0 28px;">
//             Terima kasih sudah mendaftar. Klik tombol di bawah untuk memverifikasi email kamu dan mengaktifkan akun.
//           </p>
//           <table cellpadding="0" cellspacing="0" width="100%">
//             <tr><td align="center" style="padding:8px 0 28px;">
//               <a href="{verify_url}" style="display:inline-block;background:linear-gradient(135deg,#6366f1,#8b5cf6);color:#fff;text-decoration:none;padding:14px 36px;border-radius:8px;font-weight:600;font-size:15px;">
//                 Verifikasi Email Saya
//               </a>
//             </td></tr>
//           </table>
//           <p style="color:#9ca3af;font-size:13px;margin:0 0 8px;">Link berlaku selama <strong>24 jam</strong>.</p>
//           <p style="color:#9ca3af;font-size:12px;margin:0;">Jika kamu tidak mendaftar, abaikan email ini.</p>
//         </td></tr>
//         <!-- Footer -->
//         <tr><td style="background:#f9fafb;padding:20px 36px;text-align:center;border-top:1px solid #e5e7eb;">
//           <p style="color:#9ca3af;font-size:12px;margin:0;">&copy; 2026 {app_name}. All rights reserved.</p>
//         </td></tr>
//       </table>
//     </td></tr>
//   </table>
// </body>
// </html>"#,
//         username = username,
//         verify_url = verify_url,
//         app_name = app_name,
//     )
// }
//
// fn email_template_reset_password(username: &str, reset_url: &str, app_name: &str) -> String {
//     format!(
//         r#"<!DOCTYPE html>
// <html>
// <head>
//   <meta charset="UTF-8">
//   <meta name="viewport" content="width=device-width, initial-scale=1.0">
// </head>
// <body style="margin:0;padding:0;background:#f4f4f5;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;">
//   <table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f4f5;padding:40px 20px;">
//     <tr><td align="center">
//       <table width="520" cellpadding="0" cellspacing="0" style="background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 2px 12px rgba(0,0,0,0.08);">
//         <!-- Header -->
//         <tr><td style="background:linear-gradient(135deg,#ef4444,#f97316);padding:36px;text-align:center;">
//           <h1 style="color:#fff;margin:0;font-size:28px;font-weight:700;letter-spacing:-0.5px">{app_name}</h1>
//         </td></tr>
//         <!-- Body -->
//         <tr><td style="padding:40px 36px;">
//           <h2 style="color:#111827;margin:0 0 12px;font-size:22px;">Reset Password 🔐</h2>
//           <p style="color:#6b7280;line-height:1.6;margin:0 0 8px;">Halo, <strong>{username}</strong>.</p>
//           <p style="color:#6b7280;line-height:1.6;margin:0 0 28px;">
//             Kami menerima permintaan reset password untuk akun kamu. Klik tombol di bawah untuk membuat password baru.
//           </p>
//           <table cellpadding="0" cellspacing="0" width="100%">
//             <tr><td align="center" style="padding:8px 0 28px;">
//               <a href="{reset_url}" style="display:inline-block;background:linear-gradient(135deg,#ef4444,#f97316);color:#fff;text-decoration:none;padding:14px 36px;border-radius:8px;font-weight:600;font-size:15px;">
//                 Reset Password Saya
//               </a>
//             </td></tr>
//           </table>
//           <p style="color:#9ca3af;font-size:13px;margin:0 0 8px;">Link berlaku selama <strong>1 jam</strong>.</p>
//           <p style="color:#9ca3af;font-size:12px;margin:0;">Jika kamu tidak meminta reset password, abaikan email ini. Akun kamu tetap aman.</p>
//         </td></tr>
//         <!-- Footer -->
//         <tr><td style="background:#f9fafb;padding:20px 36px;text-align:center;border-top:1px solid #e5e7eb;">
//           <p style="color:#9ca3af;font-size:12px;margin:0;">&copy; 2026 {app_name}. All rights reserved.</p>
//         </td></tr>
//       </table>
//     </td></tr>
//   </table>
// </body>
// </html>"#,
//         username = username,
//         reset_url = reset_url,
//         app_name = app_name,
//     )
// }
