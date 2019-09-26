ALTER TABLE sponsorships ALTER COLUMN paypal_order_id DROP NOT NULL;
ALTER TABLE sponsorships ADD COLUMN payment_type TEXT DEFAULT 'paypal';