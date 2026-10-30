ALTER TABLE nodes ADD COLUMN deny_udp_ingress_creation boolean NOT NULL DEFAULT false;
INSERT INTO schema_version VALUES(36);
