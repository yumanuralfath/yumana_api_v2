# 🚀 Yumana API v2

[![Rust](https://img.shields.io/badge/rust-v1.81+-orange.svg)](https://www.rust-lang.org)
[![Framework](https://img.shields.io/badge/framework-Axum-blue.svg)](https://github.com/tokio-rs/axum)
[![Database](https://img.shields.io/badge/database-PostgreSQL-336791.svg)](https://www.postgresql.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**Yumana API v2** is a high-performance, secure personal API built with Rust. This is a complete rewrite and upgrade from the original Rocket-based version to the more modern and flexible **Axum** framework.

---

## ✨ Features

- 🔐 **Secure Auth:** JWT-based authentication with Argon2 password hashing.
- 📧 **Mail System:** Integrated email verification and password reset flows using Askama templates.
- 🛡️ **Admin Panel:** Specialized handlers for administrative tasks.
- 🚦 **Reliability:** Built-in health checks and comprehensive integration testing.
- 🗃️ **Type-Safe DB:** Leveraging SQLx for compile-time verified queries.

## 🛠 Tech Stack

| Component        | Technology                                               |
| :--------------- | :------------------------------------------------------- |
| **Language**     | Rust (Edition 2024)                                      |
| **Framework**    | [Axum](https://github.com/tokio-rs/axum)                 |
| **Runtime**      | [Tokio](https://tokio.rs/)                               |
| **ORM/Database** | [SQLx](https://github.com/launchbadge/sqlx) (PostgreSQL) |
| **Templating**   | [Askama](https://github.com/askama-rs/askama)            |
| **Testing**      | [axum-test](https://github.com/JosephLenton/axum-test)   |

---

## 🚀 Getting Started

### 📋 Prerequisites

- **Rust:** Install via [rustup](https://rustup.rs/)
- **Docker:** For running the PostgreSQL instance
- **SQLx CLI:** `cargo install sqlx-cli`

### ⚙️ Setup

1. **Clone & Enter:**

   ```bash
   git clone https://github.com/yumanuralfath/yumana_api_V2.git
   cd yumana_api_V2
   ```

2. **Environment Configuration:**

   ```bash
   cp .env.test .env
   # Edit .env with your specific secrets
   ```

3. **Database Initialization:**

   ```bash
   sqlx database create
   sqlx migrate run
   ```

4. **Install Local Git Hooks:**
   We enforce quality control locally. Run this to ensure tests pass before every push:

   ```bash
   chmod +x scripts/setup-hooks.sh
   ./scripts/setup-hooks.sh
   ```

5. **Run Development Server:**

   ```bash
   cargo run
   ```

---

## 🧪 Testing & Quality Assurance

This project follows a **Local-First CI** approach. Instead of relying on remote runners, we use a Git `pre-push` hook to ensure the codebase is always stable.

### Manual Testing

```bash
cargo test
```

---

## Deploy to Vercel (without CLI)

1. Push this repository to GitHub, GitLab, or Bitbucket.
2. In the [Vercel Dashboard](https://vercel.com/dashboard), choose **Add New... → Project**, import the repository, and keep the project root at the repository root.
3. Add the environment variables listed below under **Settings → Environment Variables**. Set them for Production and Preview as needed.
4. Deploy from the dashboard. Future pushes to the connected branch create deployments automatically.

The repository's `vercel.json` routes all paths to the container built from `Dockerfile.vercel`. The existing `Dockerfile` remains unchanged. The Vercel image defaults to port `80`, and the app reads Vercel's `PORT` and binds to `0.0.0.0`. No Vercel CLI configuration or local Vercel linking is required.

Required runtime variables:

- `DATABASE_URL`
- `JWT_ACCESS_SECRET` and `JWT_REFRESH_SECRET`
- `SMTP_USERNAME`, `SMTP_PASSWORD`, and `SMTP_FROM_EMAIL`
- `APP_URL`
- `CLIENT_ID`, `CLIENT_SECRET`, `REDIRECT_URL`, `ZOHO_REFRESH_TOKEN`, and `ACCOUNT_ID`

Set `APP_ENV=release` in Vercel. Optional settings include `FRONTEND_URL` (or `DOMAIN_URL`), `SMTP_HOST`, `SMTP_PORT`, `SMTP_FROM_NAME`, `JWT_ACCESS_EXPIRY`, and `JWT_REFRESH_EXPIRY`. `HOST` defaults to `0.0.0.0`; Vercel supplies `PORT`. Use a PostgreSQL database reachable from Vercel. The app runs SQLx migrations during startup, so its database credentials must allow migrations.

### Pre-push Hook

The installed hook will automatically run `cargo test` whenever you try to `git push`. If any test fails, the push will be aborted, keeping the remote repository clean.

---

## 📄 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

<p align="center">Made with ❤️ by <a href="https://github.com/yumanuralfath">Yuma</a></p>
