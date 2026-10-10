CREATE TABLE telegram_state (
 id integer PRIMARY KEY CHECK(id=1), bot_id bigint NOT NULL DEFAULT 0,
 update_offset bigint NOT NULL DEFAULT 0 CHECK(update_offset>=0),last_update_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO telegram_state(id) VALUES(1);
CREATE TABLE node_ip_state (
 node_id bigint PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,
 generation bigint NOT NULL DEFAULT 0, checked_unix bigint NOT NULL DEFAULT 0,
 ipv4 text NOT NULL DEFAULT '',ipv6 text NOT NULL DEFAULT '',
 ddns_state text NOT NULL DEFAULT ''
);
INSERT INTO node_ip_state(node_id,generation,checked_unix,ipv4,ipv6,ddns_state)
 SELECT node_id,generation,COALESCE((status->>'checked_unix')::bigint,0),
 COALESCE(status->>'ipv4',''),COALESCE(status->>'ipv6',''),COALESCE(status->>'state','') FROM node_ddns;
CREATE TABLE node_ip_events (
 id bigserial PRIMARY KEY,node_id bigint NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
 kind text NOT NULL CHECK(kind IN ('ip_change','ddns_error','ddns_recovered')),
 old_ipv4 text NOT NULL DEFAULT '',new_ipv4 text NOT NULL DEFAULT '',
 old_ipv6 text NOT NULL DEFAULT '',new_ipv6 text NOT NULL DEFAULT '',
 record_name text NOT NULL,ddns_state text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX node_ip_events_recent ON node_ip_events(node_id,created_at) WHERE kind='ip_change';
CREATE TABLE telegram_deliveries (
 event_id bigint NOT NULL REFERENCES node_ip_events(id) ON DELETE CASCADE,
 chat_id bigint NOT NULL,config_hash text NOT NULL,
 state text NOT NULL DEFAULT 'queued' CHECK(state IN ('queued','sent','failed','canceled')),
 attempts integer NOT NULL DEFAULT 0,next_attempt_at timestamptz NOT NULL DEFAULT now(),
 created_at timestamptz NOT NULL DEFAULT now(),PRIMARY KEY(event_id,chat_id)
);
CREATE INDEX telegram_deliveries_pending ON telegram_deliveries(next_attempt_at) WHERE state='queued';
INSERT INTO schema_version VALUES(23);
