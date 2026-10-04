CREATE TABLE node_groups (
 id bigserial PRIMARY KEY, name text NOT NULL UNIQUE, description text NOT NULL DEFAULT '',
 enabled boolean NOT NULL DEFAULT true, sort_order integer NOT NULL DEFAULT 0,
 strategy text NOT NULL DEFAULT 'manual' CHECK(strategy='manual'), legacy_node_id bigint UNIQUE
);
CREATE TABLE node_group_members (
 group_id bigint NOT NULL REFERENCES node_groups(id) ON DELETE CASCADE,
 node_id bigint NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
 weight integer NOT NULL DEFAULT 1 CHECK(weight>0), priority integer NOT NULL DEFAULT 0,
 PRIMARY KEY(group_id,node_id)
);
CREATE TABLE plans (
 id bigserial PRIMARY KEY, name text NOT NULL UNIQUE, description text NOT NULL DEFAULT '',
 enabled boolean NOT NULL DEFAULT true,
 speed_bps bigint NOT NULL CHECK(speed_bps BETWEEN 125000 AND 12500000000),
 quota_bytes bigint NOT NULL CHECK(quota_bytes>=0),
 max_rules integer NOT NULL CHECK(max_rules BETWEEN 1 AND 10000),
 max_connections bigint NOT NULL CHECK(max_connections BETWEEN 1 AND 1000000),
 ip_limit integer NOT NULL DEFAULT 0 CHECK(ip_limit BETWEEN 0 AND 1000000),
 rule_speed_bps bigint NOT NULL DEFAULT 0 CHECK(rule_speed_bps BETWEEN 0 AND 12500000000),
 rule_ip_limit integer NOT NULL DEFAULT 0 CHECK(rule_ip_limit BETWEEN 0 AND 1000000),
 rule_connection_limit integer NOT NULL DEFAULT 0 CHECK(rule_connection_limit BETWEEN 0 AND 1000000),
 duration_days integer NOT NULL DEFAULT 0 CHECK(duration_days BETWEEN 0 AND 36500),
 migration_key jsonb UNIQUE, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE plan_node_groups (
 plan_id bigint NOT NULL REFERENCES plans(id) ON DELETE CASCADE,
 group_id bigint NOT NULL REFERENCES node_groups(id), PRIMARY KEY(plan_id,group_id)
);
ALTER TABLE users ADD COLUMN plan_id bigint REFERENCES plans(id);
ALTER TABLE users ADD COLUMN plan_started_at timestamptz NOT NULL DEFAULT now();
INSERT INTO node_groups(name,legacy_node_id) SELECT '迁移节点 · '||name,id FROM nodes;
INSERT INTO node_group_members(group_id,node_id) SELECT id,legacy_node_id FROM node_groups;
CREATE TEMP TABLE old_entitlements ON COMMIT DROP AS
SELECT u.*, CASE WHEN expires_at IS NULL THEN 0 ELSE LEAST(36500,GREATEST(1,ceil(extract(epoch FROM(expires_at-created_at))/86400)::integer)) END AS duration_days,
 COALESCE((SELECT array_agg(n.node_id ORDER BY n.node_id) FROM user_nodes n WHERE n.user_id=u.id),'{}'::bigint[]) AS node_ids
FROM users u;
ALTER TABLE old_entitlements ADD COLUMN signature jsonb;
ALTER TABLE old_entitlements ADD COLUMN rule_speed_bps bigint, ADD COLUMN rule_ip_limit integer, ADD COLUMN rule_connection_limit integer;
UPDATE old_entitlements o SET rule_speed_bps=COALESCE((SELECT min(NULLIF(speed_mbps,0))*125000 FROM rules WHERE user_id=o.id),0),rule_ip_limit=COALESCE((SELECT min(NULLIF(ip_limit,0)) FROM rules WHERE user_id=o.id),0),rule_connection_limit=COALESCE((SELECT min(NULLIF(connection_limit,0)) FROM rules WHERE user_id=o.id),0);
UPDATE old_entitlements SET signature=jsonb_build_array(speed_bps,quota_bytes,max_rules,max_connections,duration_days,to_jsonb(node_ids),rule_speed_bps,rule_ip_limit,rule_connection_limit);
INSERT INTO plans(name,speed_bps,quota_bytes,max_rules,max_connections,duration_days,rule_speed_bps,rule_ip_limit,rule_connection_limit,migration_key)
 SELECT '迁移套餐 '||row_number() OVER(ORDER BY signature),speed_bps,quota_bytes,max_rules,max_connections,duration_days,rule_speed_bps,rule_ip_limit,rule_connection_limit,signature
 FROM (SELECT DISTINCT signature,speed_bps,quota_bytes,max_rules,max_connections,duration_days,rule_speed_bps,rule_ip_limit,rule_connection_limit FROM old_entitlements) t;
UPDATE users u SET plan_id=p.id,plan_started_at=CASE WHEN old.expires_at IS NULL THEN old.created_at ELSE old.expires_at-make_interval(days=>old.duration_days) END
 FROM old_entitlements old JOIN plans p ON p.migration_key=old.signature WHERE u.id=old.id;
INSERT INTO plan_node_groups(plan_id,group_id)
 SELECT DISTINCT p.id,g.id FROM old_entitlements o JOIN plans p ON p.migration_key=o.signature JOIN node_groups g ON g.legacy_node_id=ANY(o.node_ids);
ALTER TABLE plans DROP COLUMN migration_key;
ALTER TABLE node_groups DROP COLUMN legacy_node_id;
DROP TABLE user_nodes;
ALTER TABLE users DROP COLUMN speed_bps, DROP COLUMN quota_bytes, DROP COLUMN max_rules, DROP COLUMN max_connections, DROP COLUMN expires_at;
ALTER TABLE nodes ADD COLUMN enabled boolean NOT NULL DEFAULT true;
ALTER TABLE nodes ADD COLUMN notes text NOT NULL DEFAULT '';
ALTER TABLE nodes ADD COLUMN listen_host text NOT NULL DEFAULT '0.0.0.0';
ALTER TABLE nodes ADD COLUMN port_min integer NOT NULL DEFAULT 1024 CHECK(port_min BETWEEN 1024 AND 65535);
ALTER TABLE nodes ADD COLUMN port_max integer NOT NULL DEFAULT 65535 CHECK(port_max BETWEEN port_min AND 65535);
ALTER TABLE nodes ADD COLUMN max_connections bigint NOT NULL DEFAULT 10000 CHECK(max_connections BETWEEN 1 AND 1000000);
ALTER TABLE nodes ADD COLUMN dial_timeout_seconds integer NOT NULL DEFAULT 8 CHECK(dial_timeout_seconds BETWEEN 1 AND 120);
ALTER TABLE nodes ADD COLUMN idle_timeout_seconds integer NOT NULL DEFAULT 300 CHECK(idle_timeout_seconds BETWEEN 10 AND 86400);
ALTER TABLE nodes ADD COLUMN probe_interval_seconds integer NOT NULL DEFAULT 5 CHECK(probe_interval_seconds BETWEEN 2 AND 60);
ALTER TABLE nodes ADD COLUMN disk_path text NOT NULL DEFAULT '/';
ALTER TABLE nodes ADD COLUMN network_interfaces jsonb NOT NULL DEFAULT '[]';
ALTER TABLE nodes ADD COLUMN probe jsonb;
ALTER TABLE nodes ADD COLUMN probe_received_at timestamptz;
ALTER TABLE nodes ADD COLUMN config_revision bigint NOT NULL DEFAULT 0;
UPDATE rules SET speed_mbps=0,ip_limit=0,connection_limit=0;
CREATE VIEW user_entitlements AS
 SELECT u.id,u.username,u.is_admin,u.enabled AS account_enabled,u.plan_id,u.plan_started_at,u.created_at,
 u.enabled AND COALESCE(p.enabled,false) AS enabled, COALESCE(p.enabled,false) AS plan_enabled,
 COALESCE(p.name,'未分配套餐') AS plan_name,
 CASE WHEN p.duration_days>0 THEN u.plan_started_at+make_interval(days=>p.duration_days) ELSE NULL END AS expires_at,
 COALESCE(p.speed_bps,0)::bigint AS speed_bps, COALESCE(p.quota_bytes,0)::bigint AS quota_bytes,
 COALESCE(p.max_rules,0) AS max_rules, COALESCE(p.max_connections,0)::bigint AS max_connections,
 COALESCE(p.ip_limit,0) AS ip_limit, COALESCE(p.rule_speed_bps,0)::bigint AS rule_speed_bps,
 COALESCE(p.rule_ip_limit,0) AS rule_ip_limit, COALESCE(p.rule_connection_limit,0) AS rule_connection_limit
 FROM users u LEFT JOIN plans p ON p.id=u.plan_id;
CREATE VIEW user_nodes AS
 SELECT DISTINCT u.id AS user_id,n.id AS node_id FROM users u
 JOIN plans p ON p.id=u.plan_id AND p.enabled
 JOIN plan_node_groups pg ON pg.plan_id=p.id
 JOIN node_groups g ON g.id=pg.group_id AND g.enabled
 JOIN node_group_members m ON m.group_id=g.id
 JOIN nodes n ON n.id=m.node_id AND n.enabled
 WHERE u.enabled AND (p.duration_days=0 OR u.plan_started_at+make_interval(days=>p.duration_days)>now());
UPDATE revision SET value=value+1;
INSERT INTO schema_version VALUES(3);
