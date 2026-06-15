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

### Pre-push Hook

The installed hook will automatically run `cargo test` whenever you try to `git push`. If any test fails, the push will be aborted, keeping the remote repository clean.

---

## 📄 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

<p align="center">Made with ❤️ by <a href="https://github.com/yumanuralfath">Yuma</a></p>
