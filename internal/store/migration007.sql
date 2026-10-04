ALTER TABLE nodes ADD COLUMN token text NOT NULL DEFAULT '';
UPDATE site_settings SET config=config-'installer_sha256'-'amd64_sha256'-'arm64_sha256';
INSERT INTO schema_version VALUES(7);
