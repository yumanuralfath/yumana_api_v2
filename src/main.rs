use tower_http::trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer};
use tracing::{Level, info};

use yumana_api_v2::{
    AppState, Config, create_router,
    bootstrap::{init_cors, init_tracing_env},
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing_env();

    let config = Config::from_env()?;
    info!(
        "Starting {} on {}:{}",
        env!("CARGO_PKG_NAME"),
        config.host,
        config.port
    );

    // Inisialisasi app state lengkap secara terenkapsulasi
    let app_state = AppState::new(config.clone()).await?;

    let app = create_router(app_state)
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::new().level(Level::INFO))
                .on_response(DefaultOnResponse::new().level(Level::INFO)),
        )
        .layer(init_cors(&config));

    let addr = format!("{}:{}", config.host, config.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    info!("Listening on {}", addr);

    axum::serve(listener, app).await?;

    Ok(())
}
