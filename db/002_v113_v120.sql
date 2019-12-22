CREATE TABLE IF NOT EXISTS intents
(
    id              UUID PRIMARY KEY NOT NULL,
    sponsored_at    TIMESTAMP WITH TIME ZONE DEFAULT (now() at time zone 'utc'),
    sponsor_amount  NUMERIC          NOT NULL,
    cat_self_link   TEXT             NOT NULL,
    cat_img         TEXT,
    cat_name        TEXT,
    petfinder_id    BIGINT           NOT NULL
);
