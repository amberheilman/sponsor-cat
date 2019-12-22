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

CREATE TYPE public.adoption_status AS ENUM (
    'adoptable',
    'adopted',
    'found'
);

CREATE TABLE IF NOT EXISTS public.sponsorship_emails (
    id uuid NOT NULL,
    sponsorship_id uuid,
    contact_email text NOT NULL,
    adoption_status public.adoption_status NOT NULL,
    created_at timestamp with time zone DEFAULT timezone('utc'::text, now()),
    modified_at timestamp with time zone DEFAULT timezone('utc'::text, now()),
    last_polled_at timestamp with time zone DEFAULT timezone('utc'::text, now())
);

ALTER TABLE ONLY public.sponsorship_emails
    ADD CONSTRAINT sponsorship_emails_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.sponsorship_emails
    ADD CONSTRAINT sponsorship_emails_sponsorship_id_fkey FOREIGN KEY (sponsorship_id) REFERENCES public.sponsorships(id) ON DELETE RESTRICT;