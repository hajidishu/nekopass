CREATE TABLE node_probe_traffic_hourly (
 node_id bigint NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
 bucket_at timestamptz NOT NULL,
 rx_bytes bigint NOT NULL DEFAULT 0 CHECK(rx_bytes>=0),
 tx_bytes bigint NOT NULL DEFAULT 0 CHECK(tx_bytes>=0),
 observed_ns bigint NOT NULL CHECK(observed_ns>0 AND observed_ns<=3600000000000),
 PRIMARY KEY(node_id,bucket_at)
);
CREATE INDEX node_probe_traffic_hourly_bucket ON node_probe_traffic_hourly(bucket_at);
CREATE INDEX dashboard_paid_recharges ON shop_orders(paid_at) WHERE kind='recharge' AND status='paid';
INSERT INTO schema_version VALUES(40);
