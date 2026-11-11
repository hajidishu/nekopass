DROP INDEX node_ip_recovery_active_instance;
CREATE UNIQUE INDEX node_ip_recovery_active_instance ON node_ip_recovery
 ((config->>'instance_type'),(config->>'account_id'),(config->>'region_name'),(config->>'instance_id'))
 WHERE config->>'enabled'='true' AND COALESCE(config->>'binding_mode','instance')<>'profile';
CREATE UNIQUE INDEX node_ip_recovery_active_profile ON node_ip_recovery
 ((config->>'instance_type'),(config->>'profile_id'))
 WHERE config->>'enabled'='true' AND config->>'binding_mode'='profile';
INSERT INTO schema_version VALUES(41);
