-- 分组按次收费字段
ALTER TABLE groups ADD COLUMN IF NOT EXISTS per_request_price DECIMAL(20,8) NULL;
ALTER TABLE groups ADD COLUMN IF NOT EXISTS model_per_request_prices JSONB NULL;
