ALTER TABLE nodes ADD COLUMN first_connected_at timestamptz;

CREATE TABLE node_probe_counters (
 node_id bigint PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,
 boot_id text NOT NULL,
 sampled_at bigint NOT NULL,
 received_at timestamptz NOT NULL,
 counters jsonb NOT NULL
);
CREATE TABLE node_probe_traffic_daily (
 node_id bigint NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
 day date NOT NULL,
 rx_bytes bigint NOT NULL DEFAULT 0 CHECK(rx_bytes>=0),
 tx_bytes bigint NOT NULL DEFAULT 0 CHECK(tx_bytes>=0),
 PRIMARY KEY(node_id,day)
);
CREATE TABLE node_probe_history (
 node_id bigint NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
 reported_at timestamptz NOT NULL,
 cpu_percent double precision,
 memory_percent double precision,
 disk_percent double precision,
 PRIMARY KEY(node_id,reported_at)
);
INSERT INTO schema_version VALUES(34);
