use sqlx::{PgPool, postgres::PgPoolOptions};
use uuid::Uuid;

/// Satu test DB context — tiap test punya schema sendiri
#[derive(Debug)]
pub struct TestDb {
    pub pool: PgPool,
    pub schema: String,
    /// Pool ke DB utama (untuk DROP SCHEMA saat cleanup)
    root_pool: PgPool,
}

impl TestDb {
    /// Buat schema baru, jalankan migrasi, kembalikan TestDb
    pub async fn new() -> Self {
        // Load .env.test
        dotenvy::from_filename(".env.test").ok();
        dotenvy::dotenv().ok();

        let base_url = std::env::var("DATABASE_URL").expect("DATABASE_URL harus ada di .env.test");

        // Connect ke root DB untuk buat/hapus schema
        let root_pool = PgPoolOptions::new()
            .max_connections(2)
            .connect(&base_url)
            .await
            .expect("Gagal connect ke PostgreSQL lokal");

        // Schema unik per test: test_<uuid_tanpa_dash>
        let schema = format!("test_{}", Uuid::new_v4().to_string().replace('-', ""));

        // Buat schema
        sqlx::query(&format!("CREATE SCHEMA \"{}\"", schema))
            .execute(&root_pool)
            .await
            .expect("Gagal buat test schema");

        // Connect ke schema tersebut
        let schema_url = format!("{}?options=-csearch_path%3D\"{}\",public", base_url, schema);
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(&schema_url)
            .await
            .expect("Gagal connect ke test schema");

        let db = Self {
            pool,
            schema,
            root_pool,
        };
        db.run_migrations().await;
        db
    }

    /// Jalankan semua DDL migration
    async fn run_migrations(&self) {
        let sql_steps = vec![
            // UUID extension
            "CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\"",
            // Enum role
            "CREATE TYPE user_role AS ENUM ('user', 'admin')",
            // Tabel users
            "CREATE TABLE users (
                id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                email VARCHAR(255) UNIQUE NOT NULL,
                username VARCHAR(50) UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role user_role NOT NULL DEFAULT 'user',
                is_verified BOOLEAN NOT NULL DEFAULT false,
                is_active BOOLEAN NOT NULL DEFAULT true,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )",
            // Tabel email_verifications
            "CREATE TABLE email_verifications (
                id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                token TEXT UNIQUE NOT NULL,
                expires_at TIMESTAMPTZ NOT NULL,
                used_at TIMESTAMPTZ,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )",
            // Tabel password_resets
            "CREATE TABLE password_resets (
                id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                token TEXT UNIQUE NOT NULL,
                expires_at TIMESTAMPTZ NOT NULL,
                used_at TIMESTAMPTZ,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )",
            // Tabel refresh_tokens
            "CREATE TABLE refresh_tokens (
                id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                token TEXT UNIQUE NOT NULL,               
                expires_at TIMESTAMPTZ NOT NULL,
                revoked_at TIMESTAMPTZ,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )",
            // Indexes
            "CREATE INDEX idx_users_email ON users(email)",
            "CREATE INDEX idx_users_username ON users(username)",
            "CREATE INDEX idx_ev_token ON email_verifications(token)",
            "CREATE INDEX idx_pr_token ON password_resets(token)",
            "CREATE INDEX idx_rt_token ON refresh_tokens(token)",
            "CREATE INDEX idx_rt_user ON refresh_tokens(user_id)",
            // Trigger updated_at
            "CREATE OR REPLACE FUNCTION update_updated_at_column()
             RETURNS TRIGGER AS $$
             BEGIN NEW.updated_at = NOW(); RETURN NEW; END;
             $$ language 'plpgsql'",
            "CREATE TRIGGER update_users_updated_at
             BEFORE UPDATE ON users
             FOR EACH ROW EXECUTE FUNCTION update_updated_at_column()",
        ];

        for sql in sql_steps {
            sqlx::query(sql)
                .execute(&self.pool)
                .await
                .unwrap_or_else(|e| panic!("Migration gagal:\nSQL: {}\nError: {}", sql, e));
        }
    }

    /// Hapus seluruh schema (dipanggil di Drop)
    pub async fn cleanup(&self) {
        if let Err(e) = sqlx::query(&format!("DROP SCHEMA \"{}\" CASCADE", self.schema))
            .execute(&self.root_pool)
            .await
        {
            eprintln!("Warning: gagal cleanup schema {}: {}", self.schema, e);
        }
    }
}

// Auto cleanup ketika TestDb keluar dari scope
impl Drop for TestDb {
    fn drop(&mut self) {
        // Spawn blocking untuk cleanup async dari sync Drop
        let schema = self.schema.clone();
        let root_url = std::env::var("DATABASE_URL").unwrap_or_default();

        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                if let Ok(pool) = PgPoolOptions::new()
                    .max_connections(1)
                    .connect(&root_url)
                    .await
                {
                    let _ = sqlx::query(&format!("DROP SCHEMA \"{}\" CASCADE", schema))
                        .execute(&pool)
                        .await;
                }
            });
        });
    }
}
