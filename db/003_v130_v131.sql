CREATE TABLE IF NOT EXISTS sponsor_amounts
(
    petfinder_id       BIGINT PRIMARY KEY NOT NULL,
    sponsor_amount     NUMERIC NOT NULL,
    sponsor_increments TEXT NOT NULL,
    last_updated       TIMESTAMP WITH TIME ZONE DEFAULT (now() at time zone 'utc')
);
