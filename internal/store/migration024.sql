ALTER TABLE site_settings ADD COLUMN telegram_generation bigint NOT NULL DEFAULT 0;

-- Preserve the active state of installations that previously used a filled token.
UPDATE site_settings SET config=jsonb_set(config,'{telegram,enabled}',
 to_jsonb(COALESCE(config#>>'{telegram,token}','')<>''),true)
 WHERE jsonb_typeof(config->'telegram')='object' AND NOT (config->'telegram' ? 'enabled');
INSERT INTO schema_version VALUES(24);
