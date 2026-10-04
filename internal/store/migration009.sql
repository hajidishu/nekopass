ALTER TABLE nodes ADD COLUMN ingress_enabled boolean NOT NULL DEFAULT true;
UPDATE revision SET value=value+1;
INSERT INTO schema_version VALUES(9);
