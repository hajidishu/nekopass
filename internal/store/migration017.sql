CREATE TABLE payment_methods (
 id bigserial PRIMARY KEY, name text NOT NULL,
 interface text NOT NULL, config jsonb NOT NULL,
 enabled boolean NOT NULL DEFAULT true, sort_order integer NOT NULL DEFAULT 0,
 created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE shop_orders ADD COLUMN payment_method_id bigint REFERENCES payment_methods(id) ON DELETE SET NULL;
ALTER TABLE shop_orders ADD COLUMN payment_method_name text NOT NULL DEFAULT '';
-- Credentials are private immutable snapshots, never part of user order JSON.
-- method_id deliberately survives method deletion for delayed notifications.
CREATE TABLE payment_attempts (
 order_id bigint PRIMARY KEY REFERENCES shop_orders(id) ON DELETE CASCADE,
 method_id bigint NOT NULL, interface text NOT NULL, config jsonb NOT NULL,
 account_scope text NOT NULL, create_context jsonb NOT NULL, checkout jsonb NOT NULL DEFAULT '{}',
 gateway_trade_no text,
 UNIQUE(account_scope,gateway_trade_no)
);
CREATE INDEX payment_attempts_method ON payment_attempts(method_id);
INSERT INTO schema_version VALUES(17);
