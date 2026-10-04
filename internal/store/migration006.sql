ALTER TABLE plans ADD COLUMN prices jsonb NOT NULL DEFAULT '{}';
ALTER TABLE users ADD COLUMN subscription_managed boolean NOT NULL DEFAULT false;
ALTER TABLE users ADD COLUMN subscription_expires_at timestamptz;
ALTER TABLE users ADD COLUMN next_reset_at timestamptz;
ALTER TABLE users ADD COLUMN reset_anchor_at timestamptz;
ALTER TABLE users ADD COLUMN reset_index integer NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN quota_epoch bigint NOT NULL DEFAULT 0 CHECK(quota_epoch>=0);
ALTER TABLE grants ADD COLUMN quota_epoch bigint NOT NULL DEFAULT 0 CHECK(quota_epoch>=0);
ALTER TABLE grants DROP CONSTRAINT grants_pkey;
ALTER TABLE grants ADD PRIMARY KEY(node_id,user_id,quota_epoch);
CREATE VIEW current_grants AS SELECT g.* FROM grants g JOIN users u ON u.id=g.user_id AND u.quota_epoch=g.quota_epoch;

CREATE TABLE wallet_accounts (
 user_id bigint PRIMARY KEY REFERENCES users(id),
 balance_cents bigint NOT NULL DEFAULT 0 CHECK(balance_cents BETWEEN 0 AND 100000000000),
 updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE shop_orders (
 id bigserial PRIMARY KEY, order_no text NOT NULL UNIQUE,
 user_id bigint NOT NULL REFERENCES users(id),
 kind text NOT NULL CHECK(kind IN ('purchase','renewal','recharge')),
 plan_id bigint REFERENCES plans(id) ON DELETE SET NULL,
 plan_name text NOT NULL DEFAULT '', cycle text NOT NULL DEFAULT '',
 amount_cents bigint NOT NULL CHECK(amount_cents BETWEEN 0 AND 100000000000),
 status text NOT NULL CHECK(status IN ('paid','pending','cancelled')),
 request_key text NOT NULL, actor_id bigint REFERENCES users(id),
 snapshot jsonb NOT NULL DEFAULT '{}', created_at timestamptz NOT NULL DEFAULT now(),
 paid_at timestamptz, UNIQUE(user_id,request_key)
);
CREATE INDEX shop_orders_user_time ON shop_orders(user_id,id DESC);
CREATE TABLE wallet_entries (
 id bigserial PRIMARY KEY, user_id bigint NOT NULL REFERENCES users(id),
 order_id bigint UNIQUE REFERENCES shop_orders(id),
 amount_cents bigint NOT NULL CHECK(amount_cents BETWEEN -100000000000 AND 100000000000),
 balance_after_cents bigint NOT NULL CHECK(balance_after_cents BETWEEN 0 AND 100000000000),
 kind text NOT NULL CHECK(kind IN ('purchase','recharge')),
 actor_id bigint REFERENCES users(id), note text NOT NULL DEFAULT '',
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX wallet_entries_user_time ON wallet_entries(user_id,id DESC);

CREATE OR REPLACE VIEW user_entitlements AS
 SELECT u.id,u.username,u.is_admin,u.enabled AS account_enabled,u.plan_id,u.plan_started_at,u.created_at,
 u.enabled AND COALESCE(p.enabled,false) AS enabled, COALESCE(p.enabled,false) AS plan_enabled,
 COALESCE(p.name,'未分配套餐') AS plan_name,
 CASE WHEN u.subscription_managed THEN u.subscription_expires_at WHEN p.duration_days>0 THEN u.plan_started_at+make_interval(days=>p.duration_days) ELSE NULL END AS expires_at,
 COALESCE(p.speed_bps,0)::bigint AS speed_bps, COALESCE(p.quota_bytes,0)::bigint AS quota_bytes,
 COALESCE(p.max_rules,0) AS max_rules, COALESCE(p.max_connections,0)::bigint AS max_connections,
 COALESCE(p.ip_limit,0) AS ip_limit, COALESCE(p.rule_speed_bps,0)::bigint AS rule_speed_bps,
 COALESCE(p.rule_ip_limit,0) AS rule_ip_limit, COALESCE(p.rule_connection_limit,0) AS rule_connection_limit,
 u.quota_epoch,u.next_reset_at,u.subscription_managed
 FROM users u LEFT JOIN plans p ON p.id=u.plan_id;
CREATE OR REPLACE VIEW user_nodes AS
 SELECT DISTINCT u.id AS user_id,n.id AS node_id FROM user_entitlements u
 JOIN plans p ON p.id=u.plan_id AND p.enabled
 JOIN plan_node_groups pg ON pg.plan_id=p.id
 JOIN node_groups g ON g.id=pg.group_id AND g.enabled
 JOIN node_group_members m ON m.group_id=g.id
 JOIN nodes n ON n.id=m.node_id AND n.enabled
 WHERE u.account_enabled AND (u.expires_at IS NULL OR u.expires_at>now());
UPDATE revision SET value=value+1;
INSERT INTO schema_version VALUES(6);
