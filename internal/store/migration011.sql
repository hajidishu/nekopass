ALTER TABLE nodes DROP CONSTRAINT nodes_tunnel_protocol_check;
ALTER TABLE nodes ADD CONSTRAINT nodes_tunnel_protocol_check CHECK(tunnel_protocol IN ('plain_tcp','tls_h2'));
ALTER TABLE nodes DROP CONSTRAINT nodes_tunnel_listen_port_check;
ALTER TABLE nodes ADD CONSTRAINT nodes_tunnel_listen_port_check CHECK(tunnel_listen_port=0 OR tunnel_listen_port BETWEEN 1 AND 65535);
ALTER TABLE nodes ADD COLUMN tls_config jsonb NOT NULL DEFAULT '{}';
ALTER TABLE nodes ADD COLUMN tls_certificate text NOT NULL DEFAULT '';
ALTER TABLE nodes ADD COLUMN tls_private_key text NOT NULL DEFAULT '';
ALTER TABLE nodes ADD COLUMN tls_ca text NOT NULL DEFAULT '';
ALTER TABLE nodes ADD COLUMN tls_status text NOT NULL DEFAULT 'unconfigured';
ALTER TABLE nodes ADD COLUMN tls_error text NOT NULL DEFAULT '';
ALTER TABLE nodes ADD COLUMN tls_not_after timestamptz;
ALTER TABLE nodes ADD COLUMN tls_generation bigint NOT NULL DEFAULT 0;
ALTER TABLE nodes ADD COLUMN protocol_version integer NOT NULL DEFAULT 0;
ALTER TABLE nodes ADD COLUMN acme_ack bigint NOT NULL DEFAULT 0;
CREATE TABLE node_acme_challenges (
 node_id bigint NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
 domain text NOT NULL, token text NOT NULL, key_authorization text NOT NULL,
 expires_at timestamptz NOT NULL, revision bigint NOT NULL,
 PRIMARY KEY(node_id,token)
);
CREATE TABLE node_acme_accounts (
 node_id bigint PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,
 directory_url text NOT NULL, email text NOT NULL, private_key text NOT NULL,
 registration jsonb NOT NULL DEFAULT '{}'
);
INSERT INTO schema_version VALUES(11);
