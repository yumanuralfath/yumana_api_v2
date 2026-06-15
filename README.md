# Yumana API (v2)

![Rust CI](https://github.com/yourusername/yumana_api_V2/actions/workflows/ci.yml/badge.svg)

Personal API built with Rust using the Axum framework. This is an upgraded version of `api.yumana.my.id`, migrating from Rocket (v1) to Axum.

## Tech Stack

- **Language:** Rust (Edition 2024)
- **Web Framework:** [Axum](https://github.com/tokio-rs/axum)
- **Database:** [PostgreSQL](https://www.postgresql.org/) with [SQLx](https://github.com/launchbadge/sqlx)
- **Runtime:** [Tokio](https://tokio.rs/)
- **Authentication:** JWT (JSON Web Tokens) with Argon2 password hashing
- **Templating:** [Askama](https://github.com/djc/askama) for mail templates
- **Testing:** [axum-test](https://github.com/joseph-p/axum-test) for integration tests

## Features

- User Authentication (Login, Register, Password Reset)
- Email Verification
- Admin Handlers
- Health Checks
- SQLx for type-safe database queries

## Prerequisites

- [Rust](https://www.rust-lang.org/tools/install) (latest stable)
- [Docker](https://www.docker.com/) (for running PostgreSQL)
- [SQLx CLI](https://github.com/launchbadge/sqlx/tree/main/sqlx-cli)

## Getting Started

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/yourusername/yumana_api_V2.git
    cd yumana_api_V2
    ```

2.  **Environment Setup:**
    Copy `.env.test` to `.env` and configure your database URL and other secrets.
    ```bash
    cp .env.test .env
    ```

3.  **Database Migration:**
    ```bash
    sqlx database create
    sqlx migrate run
    ```

4.  **Run the application:**
    ```bash
    cargo run
    ```

## Testing

Run the tests using cargo:
```bash
cargo test
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
