use crate::services::mailer::SharedZoho;

pub async fn refresh_auth(state: SharedZoho) {
    let client = reqwest::Client::new();

    loop {
        let (refresh_token, client_id, client_secret) = {
            let data = state.lock().unwrap();
            (
                data.refresh_token.clone(),
                data.client_id.clone(),
                data.client_secret.clone(),
            )
        };

        let params = [
            ("refresh_token", refresh_token.as_str()),
            ("client_id", client_id.as_str()),
            ("client_secret", client_secret.as_str()),
            ("grant_type", "refresh_token"),
        ];

        let res = match client
            .post("https://accounts.zoho.com/oauth/v2/token")
            .form(&params)
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::error!("Refresh request failed: {:?}", e);
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                continue;
            }
        };

        let json: serde_json::Value = match res.json().await {
            Ok(j) => j,
            Err(e) => {
                tracing::error!("Parse failed: {:?}", e);
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                continue;
            }
        };

        if let Some(token) = json["access_token"].as_str() {
            let expires_in = json["expires_in"].as_u64().unwrap_or(3600);

            {
                let mut data = state.lock().unwrap();
                data.access_token = token.to_string();
                data.expires_in = expires_in;
            }

            tracing::info!("Zoho token refreshed");

            tokio::time::sleep(std::time::Duration::from_secs(expires_in - 60)).await;
        } else {
            tracing::error!("Refresh failed: {:?}", json);
            tokio::time::sleep(std::time::Duration::from_secs(120)).await;
        }
    }
}
