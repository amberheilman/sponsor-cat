CREATE TABLE IF NOT EXISTS sponsorships (
    id UUID PRIMARY KEY NOT NULL,
    sponsored_at TIMESTAMP WITH TIME ZONE DEFAULT (now() at time zone 'utc'),
    sponsor_amount NUMERIC NOT NULL,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    paypal_order_id TEXT UNIQUE NOT NULL,
    cat_self_link TEXT NOT NULL,
    cat_img TEXT,
    cat_name TEXT
);

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT (now() at time zone 'utc'),
    modified_at TIMESTAMP WITH TIME ZONE DEFAULT (now() at time zone 'utc')
);
