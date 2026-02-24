import express from "express";
import { Pool } from "pg";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

const app = express();
app.use(express.json({ limit: "5mb" }));

// --- CORS (website can call API)
app.use((req, res, next) => {
  const allowed = new Set(["https://adoptmehub.com", "https://www.adoptmehub.com"]);
  const origin = req.headers.origin;

  if (origin && allowed.has(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
  }

  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, x-inventory-key, x-admin-key");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS");

  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

// --- request logger (IMPORTANT: before routes)
app.use((req, res, next) => {
  console.log("REQ", req.method, req.url);
  next();
});

// ✅ Health routes (ONE)
app.get("/", (req, res) => res.status(200).send("API running ✅"));
app.get("/health", (req, res) => res.status(200).json({ ok: true }));

// ✅ Postgres pool
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : undefined,
});

const JWT_SECRET = process.env.JWT_SECRET || "dev_secret_change_me";
const ADMIN_KEY = process.env.ADMIN_KEY || "";
const INVENTORY_API_KEY = process.env.INVENTORY_API_KEY || "";

function requireAdmin(req, res, next) {
  if (!ADMIN_KEY) return res.status(500).json({ ok: false, error: "ADMIN_KEY not set" });
  if (req.header("x-admin-key") !== ADMIN_KEY) return res.status(401).json({ ok: false, error: "bad admin key" });
  next();
}

function requireInventoryKey(req, res, next) {
  if (!INVENTORY_API_KEY) return res.status(500).json({ ok: false, error: "INVENTORY_API_KEY not set" });
  if (req.header("x-inventory-key") !== INVENTORY_API_KEY) return res.status(401).json({ ok: false, error: "bad inventory key" });
  next();
}

function requireAuth(req, res, next) {
  const auth = req.header("Authorization") || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  if (!token) return res.status(401).json({ ok: false, error: "missing token" });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ ok: false, error: "invalid token" });
  }
}

// --- inventory delta helpers
function countFromSnapshot(snapshot) {
  const counts = {};
  const pets = Array.isArray(snapshot?.pets) ? snapshot.pets : [];
  for (const p of pets) {
    const k = String(p?.name || p?.id || "unknown_pet");
    counts[k] = (counts[k] || 0) + 1;
  }
  const food = Array.isArray(snapshot?.food) ? snapshot.food : [];
  for (const f of food) {
    const k = String(f?.name || f?.id || "unknown_food");
    const qty = Number(f?.quantity || 1);
    counts[k] = (counts[k] || 0) + qty;
  }
  return counts;
}
function deltaCounts(prevCounts, newCounts) {
  const delta = {};
  const keys = new Set([...Object.keys(prevCounts), ...Object.keys(newCounts)]);
  for (const k of keys) {
    const d = (newCounts[k] || 0) - (prevCounts[k] || 0);
    if (d > 0) delta[k] = d;
  }
  return delta;
}
function satisfies(delta, expected) {
  for (const [k, need] of Object.entries(expected || {})) {
    if ((delta[k] || 0) < Number(need)) return false;
  }
  return true;
}

async function initDb() {
  await pool.query(`
    create table if not exists users (
      id bigserial primary key,
      email text not null unique,
      password_hash text not null,
      balance_int bigint not null default 0,
      created_at timestamptz not null default now()
    );

    create table if not exists settings (
      key text primary key,
      value text not null
    );

    create table if not exists products (
      id bigserial primary key,
      code text not null unique,
      title text not null,
      kind text not null default 'account',
      age_pots int not null default 0,
      bucks int not null default 0,
      price_int bigint not null default 0,
      stock_int int not null default 1,
      note text not null default '',
      sold boolean not null default false,
      sold_at timestamptz,
      purchases_count int not null default 0,
      created_at timestamptz not null default now()
    );

    create table if not exists orders (
      id bigserial primary key,
      user_id bigint references users(id),
      status text not null default 'pending',
      cart jsonb not null default '[]'::jsonb,
      total_int bigint not null default 0,
      created_at timestamptz not null default now()
    );

    create table if not exists order_items (
      id bigserial primary key,
      order_id bigint references orders(id),
      product_code text not null,
      qty int not null default 1
    );

    create table if not exists payment_slots (
      slot int primary key,
      title text not null default '',
      item_key text not null default '',
      points_per_unit int not null default 0,
      image_url text,
      enabled boolean not null default false
    );

    create table if not exists expected_payments (
      id bigserial primary key,
      user_id bigint references users(id),
      type text not null,
      expected jsonb not null,
      points_to_credit bigint not null,
      receiver_account text not null,
      status text not null default 'pending',
      created_at timestamptz not null default now()
    );

    create table if not exists inventory_snapshots (
      id bigserial primary key,
      receiver_account text not null,
      received_at timestamptz not null default now(),
      data jsonb not null
    );
  `);

  await pool.query(`
    insert into settings (key,value)
    values ('rate_agepots_per_token','80')
    on conflict (key) do nothing;
  `);

  for (let i = 1; i <= 15; i++) {
    await pool.query(
      `insert into payment_slots (slot) values ($1) on conflict (slot) do nothing`,
      [i]
    );
  }
}

// --- pricing helper (based on rate)
async function computePriceFromRate(agePots) {
  const r = await pool.query(`select value from settings where key='rate_agepots_per_token'`);
  const rate = Math.max(1, Number(r.rows[0]?.value || 80));
  return Math.ceil(Number(agePots || 0) / rate);
}

// ----------------- AUTH -----------------
app.post("/api/auth/register", async (req, res) => {
  const email = String(req.body?.email || "").trim().toLowerCase();
  const password = String(req.body?.password || "");
  if (!email.includes("@") || password.length < 6) {
    return res.status(400).json({ ok: false, error: "bad email or password too short" });
  }
  const hash = await bcrypt.hash(password, 10);
  try {
    const ins = await pool.query(
      `insert into users (email,password_hash) values ($1,$2) returning id,email,balance_int`,
      [email, hash]
    );
    const token = jwt.sign({ id: ins.rows[0].id, email }, JWT_SECRET, { expiresIn: "30d" });
    res.json({ ok: true, token, user: ins.rows[0] });
  } catch {
    res.status(400).json({ ok: false, error: "email already used" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  const email = String(req.body?.email || "").trim().toLowerCase();
  const password = String(req.body?.password || "");
  const u = await pool.query(`select id,email,password_hash,balance_int from users where email=$1`, [email]);
  if (!u.rows[0]) return res.status(401).json({ ok: false, error: "bad login" });
  const ok = await bcrypt.compare(password, u.rows[0].password_hash);
  if (!ok) return res.status(401).json({ ok: false, error: "bad login" });
  const token = jwt.sign({ id: u.rows[0].id, email }, JWT_SECRET, { expiresIn: "30d" });
  res.json({ ok: true, token, user: { id: u.rows[0].id, email: u.rows[0].email, balance_int: u.rows[0].balance_int } });
});

app.get("/api/me", requireAuth, async (req, res) => {
  const u = await pool.query(`select id,email,balance_int from users where id=$1`, [req.user.id]);
  res.json({ ok: true, me: u.rows[0] });
});

// ----------------- SETTINGS -----------------
app.get("/api/settings", async (req, res) => {
  const r = await pool.query(`select value from settings where key='rate_agepots_per_token'`);
  res.json({ ok: true, rate_agepots_per_token: Number(r.rows[0]?.value || 80) });
});

app.post("/api/admin/settings", requireAdmin, async (req, res) => {
  const rate = Math.max(1, Number(req.body?.rate_agepots_per_token || 80));
  await pool.query(
    `insert into settings(key,value) values('rate_agepots_per_token',$1)
     on conflict(key) do update set value=excluded.value`,
    [String(rate)]
  );
  res.json({ ok: true, rate });
});

// ----------------- PRODUCTS -----------------
app.get("/api/products", async (req, res) => {
  const rows = await pool.query(`
    select id,code,title,kind,age_pots,bucks,price_int,stock_int,note,sold,purchases_count
    from products
    order by created_at desc
  `);
  res.json({ ok: true, products: rows.rows });
});

app.post("/api/admin/products/add", requireAdmin, async (req, res) => {
  const code = String(req.body?.code || "").trim();
  const title = String(req.body?.title || "").trim();
  const age_pots = Number(req.body?.age_pots || 0);
  const bucks = Number(req.body?.bucks || 0);
  const note = String(req.body?.note || "").trim();
  if (!code || !title) return res.status(400).json({ ok: false, error: "code + title required" });
  const price_int = await computePriceFromRate(age_pots);
  await pool.query(
    `insert into products (code,title,kind,age_pots,bucks,price_int,stock_int,note)
     values ($1,$2,'account',$3,$4,$5,1,$6)`,
    [code, title, age_pots, bucks, price_int, note]
  );
  res.json({ ok: true });
});

app.post("/api/admin/products/mark-sold", requireAdmin, async (req, res) => {
  const code = String(req.body?.code || "").trim();
  const p = await pool.query(`select note from products where code=$1`, [code]);
  if (!p.rows[0]) return res.status(404).json({ ok: false, error: "not found" });

  const note = p.rows[0].note.includes("--sold")
    ? p.rows[0].note
    : (p.rows[0].note ? `${p.rows[0].note} --sold` : "--sold");

  await pool.query(
    `update products set sold=true, stock_int=0, sold_at=now(), note=$2 where code=$1`,
    [code, note]
  );
  res.json({ ok: true });
});

// ----------------- ORDERS -----------------
app.post("/api/orders/create", requireAuth, async (req, res) => {
  const cart = Array.isArray(req.body?.cart) ? req.body.cart : [];
  if (!cart.length) return res.status(400).json({ ok: false, error: "empty cart" });

  const codes = cart.map(i => String(i.code || ""));
  const prods = await pool.query(
    `select code,price_int,stock_int,sold from products where code = any($1::text[])`,
    [codes]
  );
  const map = new Map(prods.rows.map(p => [p.code, p]));

  let total = 0;
  for (const item of cart) {
    const code = String(item.code || "");
    const qty = Math.max(1, Number(item.qty || 1));
    const p = map.get(code);
    if (!p) return res.status(400).json({ ok: false, error: `unknown ${code}` });
    if (p.sold || p.stock_int < qty) return res.status(400).json({ ok: false, error: `out of stock: ${code}` });
    total += Number(p.price_int) * qty;
  }

  const created = await pool.query(
    `insert into orders (user_id, cart, total_int) values ($1,$2,$3) returning id,status,total_int`,
    [req.user.id, JSON.stringify(cart), total]
  );

  for (const item of cart) {
    await pool.query(
      `insert into order_items(order_id,product_code,qty) values ($1,$2,$3)`,
      [created.rows[0].id, String(item.code), Math.max(1, Number(item.qty || 1))]
    );
  }

  res.json({ ok: true, order: created.rows[0] });
});

// ----------------- PAYMENT SLOTS -----------------
app.get("/api/payment-slots", async (req, res) => {
  const rows = await pool.query(
    `select slot,title,item_key,points_per_unit,image_url,enabled from payment_slots order by slot asc`
  );
  res.json({ ok: true, slots: rows.rows });
});

app.post("/api/admin/payment-slots/set", requireAdmin, async (req, res) => {
  const slot = Math.min(15, Math.max(1, Number(req.body?.slot)));
  const title = String(req.body?.title || "");
  const item_key = String(req.body?.item_key || "");
  const points_per_unit = Math.max(0, Number(req.body?.points_per_unit || 0));
  const image_url = req.body?.image_url ? String(req.body.image_url) : null;
  const enabled = Boolean(req.body?.enabled);

  await pool.query(
    `update payment_slots
     set title=$2,item_key=$3,points_per_unit=$4,image_url=$5,enabled=$6
     where slot=$1`,
    [slot, title, item_key, points_per_unit, image_url, enabled]
  );
  res.json({ ok: true });
});

app.post("/api/payments/expect-slot", requireAuth, async (req, res) => {
  const receiver_account = String(req.body?.receiver_account || "").trim();
  const slot = Math.min(15, Math.max(1, Number(req.body?.slot)));
  const qty = Math.max(1, Number(req.body?.qty || 1));
  if (!receiver_account) return res.status(400).json({ ok: false, error: "receiver_account required" });

  const s = await pool.query(`select enabled,item_key,points_per_unit from payment_slots where slot=$1`, [slot]);
  if (!s.rows[0] || !s.rows[0].enabled) return res.status(400).json({ ok: false, error: "slot disabled" });

  const item_key = s.rows[0].item_key;
  const points = Number(s.rows[0].points_per_unit) * qty;

  const expected = { [item_key]: qty };

  const ins = await pool.query(
    `insert into expected_payments (user_id,type,expected,points_to_credit,receiver_account)
     values ($1,'slot',$2,$3,$4) returning id,status`,
    [req.user.id, JSON.stringify(expected), points, receiver_account]
  );

  res.json({ ok: true, expected_payment: ins.rows[0], expected, points });
});

// ----------------- INVENTORY INGEST -----------------
app.post("/inventory", requireInventoryKey, async (req, res) => {
  const receiver_account = String(req.body?.user || "unknown");
  const snapshot = req.body;

  const last = await pool.query(
    `select data from inventory_snapshots where receiver_account=$1 order by id desc limit 1`,
    [receiver_account]
  );

  const prev = last.rows[0]?.data || null;
  const delta = deltaCounts(prev ? countFromSnapshot(prev) : {}, countFromSnapshot(snapshot));

  await pool.query(`insert into inventory_snapshots (receiver_account,data) values ($1,$2)`, [
    receiver_account, JSON.stringify(snapshot)
  ]);

  const pending = await pool.query(
    `select id,user_id,expected,points_to_credit
     from expected_payments
     where receiver_account=$1 and status='pending'
     order by id asc`,
    [receiver_account]
  );

  const matched = [];
  for (const p of pending.rows) {
    if (satisfies(delta, p.expected)) {
      await pool.query(`update expected_payments set status='matched' where id=$1`, [p.id]);
      await pool.query(`update users set balance_int = balance_int + $1 where id=$2`, [Number(p.points_to_credit), p.user_id]);
      matched.push({ expected_payment_id: p.id, credited: Number(p.points_to_credit) });
    }
  }

  res.json({ ok: true, delta, matched });
});

// ----------------- LEADERBOARD + MY ACCOUNTS -----------------
app.get("/api/leaderboard", async (req, res) => {
  const rows = await pool.query(`
    select product_code, sum(qty)::int as buys
    from order_items
    group by product_code
    order by buys desc
    limit 20
  `);
  res.json({ ok: true, leaderboard: rows.rows });
});

app.get("/api/my-accounts", requireAuth, async (req, res) => {
  const rows = await pool.query(
    `select id,status,cart,total_int,created_at from orders where user_id=$1 order by id desc`,
    [req.user.id]
  );
  res.json({ ok: true, orders: rows.rows });
});

// ✅ Railway-safe start
const PORT = Number(process.env.PORT || 3000);
const server = app.listen(PORT, "0.0.0.0", () => console.log("✅ listening on", PORT));

process.on("SIGTERM", () => {
  console.log("⚠️ SIGTERM received — shutting down");
  server.close(() => process.exit(0));
});

// Start DB init AFTER listen (and do not crash server)
initDb()
  .then(() => console.log("✅ DB ready"))
  .catch((e) => console.error("❌ DB init error (server still running):", e?.message || e));
