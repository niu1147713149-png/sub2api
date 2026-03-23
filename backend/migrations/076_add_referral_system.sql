ALTER TABLE users ADD COLUMN IF NOT EXISTS referrer_id BIGINT REFERENCES users(id);
ALTER TABLE users ADD COLUMN IF NOT EXISTS referral_code VARCHAR(20);
CREATE INDEX IF NOT EXISTS idx_users_referrer_id ON users (referrer_id) WHERE referrer_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_referral_code ON users (referral_code) WHERE referral_code IS NOT NULL AND deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS referral_commissions (
    id BIGSERIAL PRIMARY KEY,
    referrer_id BIGINT NOT NULL REFERENCES users(id),
    referred_user_id BIGINT NOT NULL REFERENCES users(id),
    order_id BIGINT NOT NULL,
    order_amount DECIMAL(20,8) NOT NULL,
    commission_rate DECIMAL(10,8) NOT NULL,
    commission_amount DECIMAL(20,8) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_referral_commissions_referrer ON referral_commissions (referrer_id);

-- backfill existing users
UPDATE users SET referral_code = 'R' || LPAD(TO_HEX(id), 6, '0') WHERE referral_code IS NULL;
