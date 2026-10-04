CREATE TABLE IF NOT EXISTS schema_version (version integer PRIMARY KEY);
INSERT INTO schema_version VALUES (1) ON CONFLICT DO NOTHING;
CREATE TABLE IF NOT EXISTS users (
 id bigserial PRIMARY KEY,
 username text NOT NULL UNIQUE,
 password_hash text NOT NULL,
 is_admin boolean NOT NULL DEFAULT false,
 enabled boolean NOT NULL DEFAULT true,
 expires_at timestamptz,
 speed_bps bigint NOT NULL DEFAULT 62500000 CHECK(speed_bps > 0),
 quota_bytes bigint NOT NULL DEFAULT 10737418240 CHECK(quota_bytes >= 0),
 max_rules integer NOT NULL DEFAULT 10 CHECK(max_rules > 0),
 max_connections bigint NOT NULL DEFAULT 1000 CHECK(max_connections > 0),
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS sessions (
 token_hash text PRIMARY KEY, user_id bigint NOT NULL REFERENCES users(id),
 expires_at timestamptz NOT NULL
);
CREATE TABLE IF NOT EXISTS nodes (
 id bigserial PRIMARY KEY, name text NOT NULL UNIQUE,
 token_hash text NOT NULL UNIQUE, instance_id text NOT NULL DEFAULT '',
 last_seen timestamptz, applied_revision bigint NOT NULL DEFAULT 0,
 sync_error text NOT NULL DEFAULT '', active_connections bigint NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS user_nodes (
 user_id bigint NOT NULL REFERENCES users(id), node_id bigint NOT NULL REFERENCES nodes(id),
 PRIMARY KEY(user_id,node_id)
);
CREATE TABLE IF NOT EXISTS rules (
 id bigserial PRIMARY KEY, user_id bigint NOT NULL REFERENCES users(id),
 node_id bigint NOT NULL REFERENCES nodes(id), listen_host text NOT NULL DEFAULT '0.0.0.0',
 listen_port integer NOT NULL CHECK(listen_port BETWEEN 1024 AND 65535),
 target_host text NOT NULL, target_port integer NOT NULL CHECK(target_port BETWEEN 1 AND 65535),
 enabled boolean NOT NULL DEFAULT true,
 UNIQUE(node_id,listen_port)
);
CREATE TABLE IF NOT EXISTS grants (
 node_id bigint NOT NULL REFERENCES nodes(id), user_id bigint NOT NULL REFERENCES users(id),
 issued bigint NOT NULL DEFAULT 0, spent bigint NOT NULL DEFAULT 0,
 released bigint NOT NULL DEFAULT 0, traffic bigint NOT NULL DEFAULT 0,
 PRIMARY KEY(node_id,user_id),
 CHECK(spent >= 0 AND released >= 0 AND traffic >= 0 AND spent+released<=issued AND traffic<=spent)
);
CREATE TABLE IF NOT EXISTS rule_usage (
 node_id bigint NOT NULL REFERENCES nodes(id), rule_id bigint NOT NULL,
 user_id bigint NOT NULL REFERENCES users(id), traffic bigint NOT NULL DEFAULT 0,
 PRIMARY KEY(node_id,rule_id)
);
CREATE TABLE IF NOT EXISTS usage_events (
 id bigserial PRIMARY KEY, node_id bigint NOT NULL, user_id bigint NOT NULL,
 traffic_bytes bigint NOT NULL CHECK(traffic_bytes > 0), created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS usage_events_user_time ON usage_events(user_id,created_at);
CREATE TABLE IF NOT EXISTS revision (id integer PRIMARY KEY CHECK(id=1), value bigint NOT NULL);
INSERT INTO revision VALUES(1,1) ON CONFLICT DO NOTHING;
