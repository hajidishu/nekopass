ALTER TABLE users ADD COLUMN email_verified_at timestamptz;
ALTER TABLE users ADD COLUMN invite_code text NOT NULL DEFAULT substr(md5(random()::text || clock_timestamp()::text),1,16);
ALTER TABLE users ADD CONSTRAINT users_invite_code_unique UNIQUE(invite_code);
ALTER TABLE users ADD COLUMN inviter_id bigint REFERENCES users(id) ON DELETE SET NULL;
ALTER TABLE users ADD CONSTRAINT users_inviter_not_self CHECK(inviter_id IS NULL OR inviter_id<>id);
ALTER TABLE users ADD COLUMN referral_enabled boolean;
ALTER TABLE users ADD COLUMN referral_mode text NOT NULL DEFAULT 'inherit' CHECK(referral_mode IN ('inherit','first','recurring'));
ALTER TABLE users ADD COLUMN referral_rate_bps integer CHECK(referral_rate_bps BETWEEN 0 AND 10000);
CREATE UNIQUE INDEX users_verified_email_unique ON users(lower(username)) WHERE email_verified_at IS NOT NULL;
CREATE INDEX users_inviter_id ON users(inviter_id);
CREATE TABLE registration_captchas (
 id text PRIMARY KEY, answer_hash text NOT NULL, remote_key text NOT NULL,
 expires_at timestamptz NOT NULL
);
CREATE INDEX registration_captchas_expiry ON registration_captchas(expires_at);
CREATE TABLE registration_codes (
 id text PRIMARY KEY, email text NOT NULL, code_hash text NOT NULL,
 attempts integer NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 5),
 sent boolean NOT NULL DEFAULT false, expires_at timestamptz NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX registration_codes_email ON registration_codes(email);
CREATE INDEX registration_codes_expiry ON registration_codes(expires_at);
ALTER TABLE shop_orders DROP CONSTRAINT shop_orders_kind_check;
ALTER TABLE shop_orders ADD CONSTRAINT shop_orders_kind_check CHECK(kind IN ('purchase','renewal','recharge','rebate'));
ALTER TABLE wallet_entries DROP CONSTRAINT wallet_entries_kind_check;
ALTER TABLE wallet_entries ADD CONSTRAINT wallet_entries_kind_check CHECK(kind IN ('purchase','recharge','rebate'));
CREATE TABLE referral_rewards (
 source_order_id bigint PRIMARY KEY REFERENCES shop_orders(id),
 inviter_id bigint NOT NULL REFERENCES users(id), invitee_id bigint NOT NULL REFERENCES users(id),
 reward_order_id bigint NOT NULL UNIQUE REFERENCES shop_orders(id),
 amount_cents bigint NOT NULL CHECK(amount_cents>0), rate_bps integer NOT NULL CHECK(rate_bps BETWEEN 0 AND 10000),
 mode text NOT NULL CHECK(mode IN ('first','recurring')), created_at timestamptz NOT NULL DEFAULT now(),
 CHECK(inviter_id<>invitee_id)
);
CREATE INDEX referral_rewards_inviter ON referral_rewards(inviter_id);
INSERT INTO schema_version VALUES(18);
