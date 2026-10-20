# Cegat vulnerable target (local lab)

An **intentionally vulnerable** Express + Postgres API for exercising Cegat
against real bugs. **Authorized, localhost-only testing.** Do not deploy.

## Vulnerabilities

1. **Register race (no DB unique constraint)** — `POST /register` checks
   `SELECT ... WHERE email = $1` then `INSERT`, with an artificial delay in
   between and **no unique index on `email`**. Fire the same email many times in
   parallel and duplicates slip through (the code-level exists-check loses the
   race). This is the one to prove Cegat's parallel send can beat, like Burp.
2. **SQL injection** — `POST /login` builds its query by string concatenation.
   e.g. `{"email":"admin@nikko.id' -- ","password":"x"}` logs in.
3. **IDOR** — `GET /users/:id` returns any user (incl. password) with no auth.

## Run

Postgres via Docker (or use your own and set `DATABASE_URL`):

```bash
docker run -d --name cegat-pg -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=cegat_target -p 5432:5432 postgres:16

cd test-target
npm install
npm run init-db          # creates schema + seeds admin@nikko.id / admin123
npm start                # http://127.0.0.1:4000
```

Env: `DATABASE_URL`, `PORT` (4000), `HOST` (127.0.0.1), `RACE_DELAY_MS` (60).

## Exploit the register race with Cegat

1. Point the target's traffic through Cegat (or just send from Repeater/Intruder
   directly to `http://127.0.0.1:4000`).
2. In **Repeater**: create a tab with
   ```
   POST /register HTTP/1.1
   Host: 127.0.0.1:4000
   Content-Type: application/json

   {"email":"race@nikko.id","password":"x"}
   ```
   Duplicate it into a **group** of ~20 tabs, then **Send multi — all at once**.
   (Or use **Intruder** with a null payload set of N rows and high threads.)
3. `POST /reset` first for a clean run; afterwards `GET /users` shows
   `duplicates` > 0 when the race was won.

A single sequential run returns one `201` and the rest `409`; a parallel burst
returns multiple `201`s for the same email.
