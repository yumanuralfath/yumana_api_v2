use std::sync::Arc;
use tower_http::trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer};
use tracing::Level;

use yumana_api_v2::{
    config::{Config, state::AppState},
    init_cors, init_db, init_services, init_tracing_env, routes,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing_env();

    let config = Config::from_env()?;
    tracing::info!(
        "Starting {} on {}:{}",
        env!("CARGO_PKG_NAME"),
        config.host,
        config.port
    );

    let db = init_db(&config.database_url).await?;
    let (jwt, email) = init_services(&config);

    let app_state = AppState {
        db,
        jwt,
        email,
        config: Arc::new(config.clone()),
    };

    let app = routes::create_router(app_state)
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::new().level(Level::INFO))
                .on_response(DefaultOnResponse::new().level(Level::INFO)),
        )
        .layer(init_cors(&config));

    let addr = format!("{}:{}", config.host, config.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("Listening on {}", addr);

    axum::serve(listener, app).await?;

    Ok(())
}
