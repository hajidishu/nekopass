-- Snapshot current entitlements before switching from shared plan limits.
ALTER TABLE users ADD COLUMN speed_bps bigint NOT NULL DEFAULT 0 CHECK(speed_bps BETWEEN 0 AND 12500000000);
ALTER TABLE users ADD COLUMN quota_bytes bigint NOT NULL DEFAULT 0 CHECK(quota_bytes BETWEEN -1 AND 1152921504606846976);
ALTER TABLE users ADD COLUMN max_rules integer NOT NULL DEFAULT 0 CHECK(max_rules BETWEEN 0 AND 10000);
ALTER TABLE users ADD COLUMN max_connections bigint NOT NULL DEFAULT 0 CHECK(max_connections BETWEEN 0 AND 1000000);
ALTER TABLE users ADD COLUMN ip_limit integer NOT NULL DEFAULT 0 CHECK(ip_limit BETWEEN 0 AND 1000000);
ALTER TABLE users ADD COLUMN rule_speed_bps bigint NOT NULL DEFAULT 0 CHECK(rule_speed_bps BETWEEN 0 AND 12500000000);
ALTER TABLE users ADD COLUMN rule_ip_limit integer NOT NULL DEFAULT 0 CHECK(rule_ip_limit BETWEEN 0 AND 1000000);
ALTER TABLE users ADD COLUMN rule_connection_limit integer NOT NULL DEFAULT 0 CHECK(rule_connection_limit BETWEEN 0 AND 1000000);
ALTER TABLE users ADD COLUMN resource_expires_at timestamptz;
ALTER TABLE users ADD COLUMN traffic_base_bytes bigint NOT NULL DEFAULT 0 CHECK(traffic_base_bytes BETWEEN 0 AND 1152921504606846976);
ALTER TABLE users ADD COLUMN resources_revision bigint NOT NULL DEFAULT 0 CHECK(resources_revision>=0);
UPDATE users u SET speed_bps=e.speed_bps,quota_bytes=e.quota_bytes,max_rules=e.max_rules,max_connections=e.max_connections,
 ip_limit=e.ip_limit,rule_speed_bps=e.rule_speed_bps,rule_ip_limit=e.rule_ip_limit,rule_connection_limit=e.rule_connection_limit,resource_expires_at=e.expires_at
FROM user_entitlements e WHERE u.id=e.id;
CREATE TABLE user_node_groups (
 user_id bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 group_id bigint NOT NULL REFERENCES node_groups(id) ON DELETE CASCADE,
 PRIMARY KEY(user_id,group_id)
);
INSERT INTO user_node_groups SELECT u.id,pg.group_id FROM users u JOIN plan_node_groups pg ON pg.plan_id=u.plan_id;
CREATE OR REPLACE VIEW user_entitlements AS
 SELECT u.id,u.username,u.is_admin,u.enabled AS account_enabled,u.plan_id,u.plan_started_at,u.created_at,
 u.enabled AND COALESCE(p.enabled,false) AS enabled,COALESCE(p.enabled,false) AS plan_enabled,
 COALESCE(p.name,'未分配套餐') AS plan_name,
 CASE WHEN u.subscription_managed THEN u.subscription_expires_at ELSE u.resource_expires_at END AS expires_at,
 u.speed_bps,u.quota_bytes,u.max_rules,u.max_connections,u.ip_limit,u.rule_speed_bps,u.rule_ip_limit,u.rule_connection_limit,
 u.quota_epoch,u.next_reset_at,u.subscription_managed,u.traffic_base_bytes,u.resources_revision
 FROM users u LEFT JOIN plans p ON p.id=u.plan_id;
CREATE OR REPLACE VIEW user_nodes AS
 SELECT DISTINCT u.id AS user_id,n.id AS node_id FROM user_entitlements u
 JOIN user_node_groups ug ON ug.user_id=u.id
 JOIN node_groups g ON g.id=ug.group_id AND g.enabled
 JOIN node_group_members m ON m.group_id=g.id
 JOIN nodes n ON n.id=m.node_id AND n.enabled
 WHERE u.enabled AND (u.expires_at IS NULL OR u.expires_at>now());

CREATE FUNCTION snapshot_user_plan_resources() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE p plans%ROWTYPE;
BEGIN
 IF TG_OP='INSERT' OR NEW.plan_id IS DISTINCT FROM OLD.plan_id THEN
  IF NEW.plan_id IS NOT NULL THEN SELECT * INTO STRICT p FROM plans WHERE id=NEW.plan_id; END IF;
  NEW.speed_bps=COALESCE(p.speed_bps,0); NEW.quota_bytes=COALESCE(p.quota_bytes,0);
  NEW.max_rules=COALESCE(p.max_rules,0); NEW.max_connections=COALESCE(p.max_connections,0); NEW.ip_limit=COALESCE(p.ip_limit,0);
  NEW.rule_speed_bps=COALESCE(p.rule_speed_bps,0); NEW.rule_ip_limit=COALESCE(p.rule_ip_limit,0); NEW.rule_connection_limit=COALESCE(p.rule_connection_limit,0);
  NEW.resource_expires_at=CASE WHEN NEW.subscription_managed THEN NEW.subscription_expires_at WHEN p.duration_days>0 THEN NEW.plan_started_at+make_interval(days=>p.duration_days) ELSE NULL END;
  IF TG_OP='UPDATE' THEN NEW.resources_revision=OLD.resources_revision+1; END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER snapshot_user_plan_resources BEFORE INSERT OR UPDATE OF plan_id ON users FOR EACH ROW EXECUTE FUNCTION snapshot_user_plan_resources();
CREATE FUNCTION snapshot_user_plan_groups() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='INSERT' OR NEW.plan_id IS DISTINCT FROM OLD.plan_id THEN
  DELETE FROM user_node_groups WHERE user_id=NEW.id;
  INSERT INTO user_node_groups SELECT NEW.id,group_id FROM plan_node_groups WHERE plan_id=NEW.plan_id;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER snapshot_user_plan_groups AFTER INSERT OR UPDATE OF plan_id ON users FOR EACH ROW EXECUTE FUNCTION snapshot_user_plan_groups();
CREATE TABLE user_resource_changes (
 id bigserial PRIMARY KEY,user_id bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 actor_id bigint REFERENCES users(id) ON DELETE SET NULL,before_state jsonb NOT NULL,after_state jsonb NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now()
);
UPDATE revision SET value=value+1;
INSERT INTO schema_version VALUES(15);
