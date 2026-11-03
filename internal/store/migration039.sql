ALTER TABLE nodes ADD COLUMN mux_config jsonb NOT NULL DEFAULT '{"enabled":false,"max_connections":0,"max_streams":128,"idle_timeout_seconds":60}';
INSERT INTO schema_version(version) VALUES (39);
