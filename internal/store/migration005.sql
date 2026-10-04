ALTER TABLE site_settings ADD COLUMN config jsonb NOT NULL DEFAULT '{}';
ALTER TABLE site_settings ADD COLUMN api_key_hash text NOT NULL DEFAULT '';
ALTER TABLE site_settings ADD COLUMN api_key_user_id bigint REFERENCES users(id);
CREATE TABLE node_install_tickets (
 token_hash text PRIMARY KEY,
 node_id bigint NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
 expires_at timestamptz NOT NULL,
 used_at timestamptz,
 config jsonb NOT NULL
);
CREATE INDEX node_install_tickets_expiry ON node_install_tickets(expires_at);
INSERT INTO schema_version VALUES(5);
