use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
pub mod callback;
pub mod method;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ZohoData {
    pub access_token: String,
    pub refresh_token: String,
    pub client_id: String,
    pub client_secret: String,
    pub api_domain: String,
    pub token_type: String,
    pub expires_in: u64,
    pub account_id: String,
}

pub type SharedZoho = Arc<Mutex<ZohoData>>;
