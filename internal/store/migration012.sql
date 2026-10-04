CREATE TABLE node_ddns (
 node_id bigint PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,
 config jsonb NOT NULL DEFAULT '{}',
 generation bigint NOT NULL DEFAULT 0,
 status jsonb NOT NULL DEFAULT '{}',
 status_received_at timestamptz
);
INSERT INTO schema_version VALUES(12);
