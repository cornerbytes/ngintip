// Create the schema and a seed user. Run once: `npm run init-db`.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import pg from 'pg';

const dir = dirname(fileURLToPath(import.meta.url));
const connectionString = process.env.DATABASE_URL || 'postgres://postgres:postgres@127.0.0.1:5432/cegat_target';

const pool = new pg.Pool({ connectionString });
const schema = readFileSync(join(dir, 'schema.sql'), 'utf8');

const seed = async () => {
  await pool.query(schema);
  await pool.query('DELETE FROM users');
  await pool.query("INSERT INTO users (email, password, role) VALUES ($1, $2, $3)", ['admin@nikko.id', 'admin123', 'admin']);
  const { rows } = await pool.query('SELECT count(*)::int AS n FROM users');
  console.log(`schema ready; users=${rows[0].n} (seeded admin@nikko.id / admin123)`);
  await pool.end();
};

seed().catch((e) => {
  console.error('init-db failed:', e.message);
  process.exit(1);
});
