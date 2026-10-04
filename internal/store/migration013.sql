ALTER TABLE nodes ADD COLUMN agent_version text NOT NULL DEFAULT '';
ALTER TABLE nodes ADD COLUMN update_supported boolean NOT NULL DEFAULT false;
CREATE TABLE node_updates (
 node_id bigint PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,
 generation bigint NOT NULL DEFAULT 1,
 version text NOT NULL,
 state text NOT NULL DEFAULT 'queued',
 error text NOT NULL DEFAULT '',
 requested_at timestamptz NOT NULL DEFAULT now(),
 updated_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO schema_version VALUES(13);
