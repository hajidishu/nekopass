-- Preserve zero-byte quotas; -1 explicitly means unlimited traffic.
ALTER TABLE plans DROP CONSTRAINT plans_speed_bps_check;
ALTER TABLE plans ADD CONSTRAINT plans_speed_bps_check CHECK(speed_bps=0 OR speed_bps BETWEEN 125000 AND 12500000000);
ALTER TABLE plans DROP CONSTRAINT plans_quota_bytes_check;
ALTER TABLE plans ADD CONSTRAINT plans_quota_bytes_check CHECK(quota_bytes>=-1);
ALTER TABLE plans DROP CONSTRAINT plans_max_rules_check;
ALTER TABLE plans ADD CONSTRAINT plans_max_rules_check CHECK(max_rules BETWEEN 0 AND 10000);
ALTER TABLE plans DROP CONSTRAINT plans_max_connections_check;
ALTER TABLE plans ADD CONSTRAINT plans_max_connections_check CHECK(max_connections BETWEEN 0 AND 1000000);
ALTER TABLE nodes DROP CONSTRAINT nodes_max_connections_check;
ALTER TABLE nodes ADD CONSTRAINT nodes_max_connections_check CHECK(max_connections BETWEEN 0 AND 1000000);
ALTER TABLE grants ADD COLUMN unlimited_spent bigint NOT NULL DEFAULT 0;
ALTER TABLE grants ADD COLUMN unlimited_open boolean NOT NULL DEFAULT false;
CREATE INDEX grants_user_id_idx ON grants(user_id);
ALTER TABLE grants DROP CONSTRAINT grants_check;
ALTER TABLE grants ADD CONSTRAINT grants_check CHECK(spent>=0 AND released>=0 AND traffic>=0 AND unlimited_spent>=0 AND spent+released<=issued AND traffic::numeric<=spent::numeric+unlimited_spent::numeric);
UPDATE revision SET value=value+1;
INSERT INTO schema_version VALUES(4);
