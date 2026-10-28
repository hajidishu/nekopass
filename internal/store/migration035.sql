ALTER TABLE node_probe_history ADD COLUMN disk_read_bytes_per_second double precision;
ALTER TABLE node_probe_history ADD COLUMN disk_write_bytes_per_second double precision;
INSERT INTO schema_version VALUES(35);
