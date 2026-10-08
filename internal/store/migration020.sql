ALTER TABLE sessions ALTER COLUMN expires_at DROP NOT NULL;
ALTER TABLE sessions ADD COLUMN cookie_renewed_at timestamptz NOT NULL DEFAULT 'epoch';
CREATE INDEX sessions_user_id ON sessions(user_id);

-- Preserve valid existing logins; expired sessions must never be revived.
UPDATE sessions SET expires_at=NULL WHERE expires_at>now();

INSERT INTO schema_version VALUES (20);
