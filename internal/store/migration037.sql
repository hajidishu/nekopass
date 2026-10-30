ALTER TABLE nodes ADD COLUMN bandwidth_up_mbps bigint NOT NULL DEFAULT 0 CHECK(bandwidth_up_mbps BETWEEN 0 AND 1000000);
ALTER TABLE nodes ADD COLUMN bandwidth_down_mbps bigint NOT NULL DEFAULT 0 CHECK(bandwidth_down_mbps BETWEEN 0 AND 1000000);
ALTER TABLE nodes ADD COLUMN brutal_enabled boolean NOT NULL DEFAULT false;
INSERT INTO schema_version VALUES(37);
