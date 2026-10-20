-- Cegat vulnerable target — schema.
-- NOTE: `email` intentionally has NO UNIQUE constraint. Uniqueness is "enforced"
-- only at the code level (a SELECT-then-INSERT in /register), which is racy:
-- concurrent requests with the same email can all pass the check before any
-- INSERT lands, so duplicates slip in. This is the bug the parallel-send test
-- is meant to exploit.
CREATE TABLE IF NOT EXISTS users (
  id         SERIAL PRIMARY KEY,
  email      TEXT NOT NULL,
  password   TEXT NOT NULL,
  role       TEXT NOT NULL DEFAULT 'user',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
