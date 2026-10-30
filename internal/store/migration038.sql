ALTER TABLE nodes ADD COLUMN client_tcp_brutal_enabled boolean NOT NULL DEFAULT false;
INSERT INTO schema_version VALUES(38);
