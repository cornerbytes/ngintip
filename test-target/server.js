// Cegat vulnerable target — an intentionally-insecure local API for authorized
// security testing of Cegat (parallel/race, SQLi, IDOR). Localhost only; do NOT
// deploy. Every "vulnerability" here is deliberate.
import express from 'express';
import pg from 'pg';

const PORT = Number(process.env.PORT || 4000);
const HOST = process.env.HOST || '127.0.0.1';
// Widen the check->insert window so the register race is easy to hit/observe.
const RACE_DELAY_MS = Number(process.env.RACE_DELAY_MS ?? 60);
const connectionString = process.env.DATABASE_URL || 'postgres://postgres:postgres@127.0.0.1:5432/cegat_target';

const pool = new pg.Pool({ connectionString });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.get('/', (_req, res) => {
  res.json({
    name: 'cegat-vuln-target',
    warning: 'Intentionally vulnerable. Authorized local testing only.',
    endpoints: {
      'POST /register': '{ email, password } — code-level exists-check, NO db unique (racy)',
      'POST /login': '{ email, password } — SQL injection (string-concatenated)',
      'GET /users': 'list all users (count + rows)',
      'GET /users/:id': 'IDOR — returns any user by id, no auth',
      'POST /reset': 'wipe users (re-seeds admin)',
    },
  });
});

// VULN #1: register uniqueness is enforced only in code (SELECT then INSERT),
// with no DB unique constraint. Concurrent same-email requests race past the
// check and create duplicates — the parallel-send bug to exploit.
app.post('/register', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'email and password required' });
  try {
    const existing = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (existing.rowCount > 0) {
      return res.status(409).json({ error: 'email already registered' });
    }
    await sleep(RACE_DELAY_MS); // <-- the race window
    const ins = await pool.query('INSERT INTO users (email, password) VALUES ($1, $2) RETURNING id', [email, password]);
    res.status(201).json({ id: ins.rows[0].id, email });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// VULN #2: classic SQL injection (query built by string concatenation).
app.post('/login', async (req, res) => {
  const { email, password } = req.body || {};
  try {
    const sql = `SELECT id, email, role FROM users WHERE email = '${email}' AND password = '${password}'`;
    const r = await pool.query(sql);
    if (r.rowCount > 0) return res.json({ ok: true, user: r.rows[0] });
    res.status(401).json({ ok: false });
  } catch (e) {
    res.status(500).json({ error: e.message, sqlHint: 'query was string-concatenated' });
  }
});

app.get('/users', async (_req, res) => {
  const r = await pool.query('SELECT id, email, role, created_at FROM users ORDER BY id');
  // Duplicates of the same email are the tell-tale of a successful register race.
  const counts = {};
  for (const u of r.rows) counts[u.email] = (counts[u.email] || 0) + 1;
  const duplicates = Object.entries(counts).filter(([, n]) => n > 1).map(([email, n]) => ({ email, n }));
  res.json({ total: r.rowCount, duplicates, users: r.rows });
});

// VULN #3: IDOR — any user by id, no authentication.
app.get('/users/:id', async (req, res) => {
  const r = await pool.query('SELECT id, email, password, role FROM users WHERE id = $1', [req.params.id]);
  if (r.rowCount === 0) return res.status(404).json({ error: 'not found' });
  res.json(r.rows[0]);
});

app.post('/reset', async (_req, res) => {
  await pool.query('DELETE FROM users');
  await pool.query("INSERT INTO users (email, password, role) VALUES ($1, $2, $3)", ['admin@nikko.id', 'admin123', 'admin']);
  res.json({ ok: true });
});

app.listen(PORT, HOST, () => {
  console.log(`cegat vuln target on http://${HOST}:${PORT}  (RACE_DELAY_MS=${RACE_DELAY_MS})`);
});
