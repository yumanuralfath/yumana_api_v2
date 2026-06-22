use std::sync::Arc;
use tower_http::trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer};
use tracing::{Level, error, info};

use yumana_api_v2::{
    AppState, Config, create_router, init_cors, init_db, init_services, init_tracing_env,
    mailer::callback, run_migrations,
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

    let db = init_db(&config.database_url).await?;
    info!("url db: {}", &config.database_url);

    // Auto Migration
    run_migrations(&db).await.map_err(|e| {
        error!("Migration Failed: {:?}", e);
        e
    })?;
    info!("Database migration success");

    let (jwt, email) = init_services(&config);

    let refresh_state = email.state.clone();

    tokio::spawn(async move {
        callback::refresh_auth(refresh_state).await;
    });

    let app_state = AppState {
        db,
        jwt,
        email,
        config: Arc::new(config.clone()),
    };

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
