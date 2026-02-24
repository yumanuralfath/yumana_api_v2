ALTER TABLE refresh_tokens ALTER COLUMN token TYPE TEXT;
ALTER TABLE email_verifications ALTER COLUMN token TYPE TEXT;
ALTER TABLE password_resets ALTER COLUMN token TYPE TEXT;
