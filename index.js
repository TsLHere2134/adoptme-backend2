import express from "express";
import { Pool } from "pg";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";

const app = express();

// ✅ Health FIRST (Railway loves this)
app.get("/health", (req, res) => res.status(200).json({ ok: true }));
app.get("/", (req, res) => res.status(200).send("API running ✅"));

app.use(express.json({ limit: "5mb" }));

app.get("/api/health", (req, res) => {
  res.json({ ok: true, status: "up", ts: Date.now() });
});

// --- CORS
app.use((req, res, next) => {
  const origin = req.headers.origin;
  // Reflect origin back — allows adoptmehub.com, localhost, and any other origin
  // Tighten this list in production if needed
  if (origin) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
  }
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, x-inventory-key, x-admin-key");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

// --- Logger
app.use((req, res, next) => {
  console.log("REQ", req.method, req.url);
  next();
});

// ✅ Postgres
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : undefined,
});

const JWT_SECRET = process.env.JWT_SECRET || "dev_secret_change_me";
const ADMIN_KEY = process.env.ADMIN_KEY || "";
const INVENTORY_API_KEY = process.env.INVENTORY_API_KEY || "";

// --------- AUTH HELPERS ----------

// Old header-key admin (kept for inventory/settings endpoints that still use it)
function requireAdminKey(req, res, next) {
  if (!ADMIN_KEY) return res.status(500).json({ ok: false, error: "ADMIN_KEY not set" });
  if (req.header("x-admin-key") !== ADMIN_KEY) return res.status(401).json({ ok: false, error: "bad admin key" });
  next();
}

function requireInventoryKey(req, res, next) {
  if (!INVENTORY_API_KEY) return res.status(500).json({ ok: false, error: "INVENTORY_API_KEY not set" });
  if (req.header("x-inventory-key") !== INVENTORY_API_KEY)
    return res.status(401).json({ ok: false, error: "bad inventory key" });
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

// JWT-based admin: checks is_admin claim in token (set at login from DB)
function requireAdmin(req, res, next) {
  if (!req.user?.is_admin) return res.status(403).json({ ok: false, error: "admin only" });
  next();
}

// --------- INVENTORY DELTA HELPERS ----------
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

// --------- DB INIT ----------
async function initDb() {
  await pool.query(`
    create table if not exists users_local (
      id bigserial primary key,
      username text not null unique,
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
      image_url text not null default '',
      sold boolean not null default false,
      sold_at timestamptz,
      purchases_count int not null default 0,
      created_at timestamptz not null default now()
    );

    create table if not exists orders (
      id bigserial primary key,
      user_id bigint references users_local(id),
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
      user_id bigint references users_local(id),
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

    create table if not exists account_credentials (
      id bigserial primary key,
      product_code text not null unique,
      roblox_user text not null,
      roblox_pass text not null,
      note text not null default '',
      assigned_order_id bigint,
      assigned_at timestamptz,
      created_at timestamptz not null default now()
    );
  `);

  // ✅ MIGRATIONS — add columns to existing tables safely
  await pool.query(`
    alter table products add column if not exists kind text not null default 'account';
    alter table products add column if not exists sold boolean not null default false;
    alter table products add column if not exists sold_at timestamptz;
    alter table products add column if not exists purchases_count int not null default 0;
    alter table products add column if not exists image_url text not null default '';

    alter table users_local add column if not exists is_admin boolean not null default false;
    alter table users_local add column if not exists is_blacklisted boolean not null default false;
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

// --- pricing helper
async function computePriceFromRate(agePots) {
  const r = await pool.query(`select value from settings where key='rate_agepots_per_token'`);
  const rate = Math.max(1, Number(r.rows[0]?.value || 80));
  return Math.ceil(Number(agePots || 0) / rate);
}

// ================= AUTH: USERNAME + PASSWORD =================

// Register
app.post("/api/auth/register", async (req, res) => {
  const username = String(req.body?.username || "").trim().toLowerCase();
  const password = String(req.body?.password || "");

  if (username.length < 3) return res.status(400).json({ ok: false, error: "username too short" });
  if (password.length < 6) return res.status(400).json({ ok: false, error: "password too short (min 6)" });

  const hash = await bcrypt.hash(password, 10);

  try {
    const ins = await pool.query(
      `insert into users_local (username,password_hash) values ($1,$2)
       returning id,username,balance_int,is_admin,created_at`,
      [username, hash]
    );
    const user = ins.rows[0];
    const token = jwt.sign(
      { id: user.id, username: user.username, is_admin: user.is_admin },
      JWT_SECRET,
      { expiresIn: "30d" }
    );
    res.json({ ok: true, token, user });
  } catch {
    res.status(400).json({ ok: false, error: "username already used" });
  }
});

// Login
app.post("/api/auth/login", async (req, res) => {
  const username = String(req.body?.username || "").trim().toLowerCase();
  const password = String(req.body?.password || "");

  const u = await pool.query(
    `select id,username,password_hash,balance_int,is_admin,is_blacklisted,created_at
     from users_local where username=$1`,
    [username]
  );
  if (!u.rows[0]) return res.status(401).json({ ok: false, error: "bad login" });

  // Block blacklisted users at login
  if (u.rows[0].is_blacklisted) return res.status(403).json({ ok: false, error: "blacklisted" });

  const ok = await bcrypt.compare(password, u.rows[0].password_hash);
  if (!ok) return res.status(401).json({ ok: false, error: "bad login" });

  const token = jwt.sign(
    { id: u.rows[0].id, username: u.rows[0].username, is_admin: u.rows[0].is_admin },
    JWT_SECRET,
    { expiresIn: "30d" }
  );
  res.json({
    ok: true,
    token,
    user: {
      id: u.rows[0].id,
      username: u.rows[0].username,
      balance_int: u.rows[0].balance_int,
      is_admin: u.rows[0].is_admin,
      created_at: u.rows[0].created_at,
    },
  });
});

// Me — also checks blacklist on every authenticated request
app.get("/api/me", requireAuth, async (req, res) => {
  const u = await pool.query(
    `select id,username,balance_int,is_admin,is_blacklisted,created_at
     from users_local where id=$1`,
    [req.user.id]
  );
  if (!u.rows[0]) return res.status(404).json({ ok: false, error: "user not found" });
  if (u.rows[0].is_blacklisted) return res.status(403).json({ ok: false, error: "blacklisted" });
  res.json({
    ok: true,
    me: {
      id: u.rows[0].id,
      username: u.rows[0].username,
      balance_int: u.rows[0].balance_int,
      is_admin: u.rows[0].is_admin,
      created_at: u.rows[0].created_at,
    },
  });
});

// ================= SETTINGS =================
app.get("/api/settings", async (req, res) => {
  const r = await pool.query(`select value from settings where key='rate_agepots_per_token'`);
  res.json({ ok: true, rate_agepots_per_token: Number(r.rows[0]?.value || 80) });
});

// Old header-key version kept for compatibility
app.post("/api/admin/settings", requireAdminKey, async (req, res) => {
  const rate = Math.max(1, Number(req.body?.rate_agepots_per_token || 80));
  await pool.query(
    `insert into settings(key,value) values('rate_agepots_per_token',$1)
     on conflict(key) do update set value=excluded.value`,
    [String(rate)]
  );
  res.json({ ok: true, rate });
});

// ================= PRODUCTS =================
app.get("/api/products", async (req, res) => {
  const rows = await pool.query(`
    select id,code,title,kind,age_pots,bucks,price_int,stock_int,note,image_url,sold,purchases_count
    from products
    order by created_at desc
  `);
  res.json({ ok: true, products: rows.rows });
});

// Old header-key add (kept for compatibility)
app.post("/api/admin/products/add", requireAdminKey, async (req, res) => {
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

// Old header-key mark-sold (kept for compatibility)
app.post("/api/admin/products/mark-sold", requireAdminKey, async (req, res) => {
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

// ================= NEW: JWT ADMIN ENDPOINTS =================

// --- Balance: add or remove
app.post("/api/admin/users/balance", requireAuth, requireAdmin, async (req, res) => {
  const username = String(req.body?.username || "").trim();
  const delta = Number(req.body?.delta || 0);
  if (!username || !Number.isFinite(delta))
    return res.status(400).json({ ok: false, error: "username + numeric delta required" });

  const q = await pool.query(
    `update users_local
     set balance_int = GREATEST(0, balance_int + $1)
     where username=$2
     returning id,username,balance_int,is_blacklisted,is_admin`,
    [Math.trunc(delta), username]
  );
  if (!q.rows[0]) return res.status(404).json({ ok: false, error: "user not found" });
  res.json({ ok: true, user: q.rows[0] });
});

// --- Blacklist / unblacklist
app.post("/api/admin/users/blacklist", requireAuth, requireAdmin, async (req, res) => {
  const username = String(req.body?.username || "").trim();
  const value = !!req.body?.value;
  if (!username) return res.status(400).json({ ok: false, error: "username required" });

  const q = await pool.query(
    `update users_local set is_blacklisted=$1 where username=$2
     returning id,username,is_blacklisted`,
    [value, username]
  );
  if (!q.rows[0]) return res.status(404).json({ ok: false, error: "user not found" });
  res.json({ ok: true, user: q.rows[0] });
});

// --- Upsert product (add + edit in one)
app.post("/api/admin/products/upsert", requireAuth, requireAdmin, async (req, res) => {
  const p = req.body || {};
  const code = String(p.code || "").trim();
  const title = String(p.title || "").trim();
  if (!code || !title) return res.status(400).json({ ok: false, error: "code + title required" });

  const price_int = Math.max(0, Math.trunc(Number(p.price_int || 0)));
  const stock_int = Math.max(0, Math.trunc(Number(p.stock_int ?? 1)));
  const age_pots  = Math.max(0, Math.trunc(Number(p.age_pots  || 0)));
  const bucks     = Math.max(0, Math.trunc(Number(p.bucks     || 0)));
  const note      = String(p.note      || "");
  const image_url = String(p.image_url || "");
  const kind      = String(p.kind      || "account");
  const sold      = !!p.sold || stock_int <= 0;

  const q = await pool.query(`
    insert into products (code,title,kind,age_pots,bucks,price_int,stock_int,note,image_url,sold)
    values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
    on conflict (code) do update set
      title=excluded.title,
      kind=excluded.kind,
      age_pots=excluded.age_pots,
      bucks=excluded.bucks,
      price_int=excluded.price_int,
      stock_int=excluded.stock_int,
      note=excluded.note,
      image_url=excluded.image_url,
      sold=excluded.sold
    returning *;
  `, [code, title, kind, age_pots, bucks, price_int, stock_int, note, image_url, sold]);

  res.json({ ok: true, product: q.rows[0] });
});

// --- Delete product
app.post("/api/admin/products/delete", requireAuth, requireAdmin, async (req, res) => {
  const code = String(req.body?.code || "").trim();
  if (!code) return res.status(400).json({ ok: false, error: "code required" });
  await pool.query(`delete from products where code=$1`, [code]);
  res.json({ ok: true });
});

// ================= ADMIN: CREDENTIALS =================

// Add a single credential slot for a product
app.post("/api/admin/credentials/add", requireAuth, requireAdmin, async (req, res) => {
  const product_code = String(req.body?.product_code || "").trim();
  const roblox_user  = String(req.body?.roblox_user  || "").trim();
  const roblox_pass  = String(req.body?.roblox_pass  || "").trim();
  const note         = String(req.body?.note         || "").trim();
  if (!product_code || !roblox_user || !roblox_pass)
    return res.status(400).json({ ok: false, error: "product_code, roblox_user, roblox_pass required" });
  const r = await pool.query(
    `insert into account_credentials (product_code, roblox_user, roblox_pass, note)
     values ($1,$2,$3,$4)
     returning id, product_code, roblox_user, assigned_order_id, created_at`,
    [product_code, roblox_user, roblox_pass, note]
  );
  res.json({ ok: true, credential: r.rows[0] });
});

// Mass import credentials — array of { product_code, roblox_user, roblox_pass, note }
// Also accepts CSV text: one line per account in format "CODE,user,pass" or "CODE,user,pass,note"
app.post("/api/admin/credentials/import", requireAuth, requireAdmin, async (req, res) => {
  let rows = [];

  if (typeof req.body?.csv === "string") {
    // Parse CSV text
    const lines = req.body.csv.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
    for (const line of lines) {
      const parts = line.split(",").map(p => p.trim());
      if (parts.length < 3) continue;
      rows.push({
        product_code: parts[0],
        roblox_user:  parts[1],
        roblox_pass:  parts[2],
        note:         parts[3] || "",
      });
    }
  } else if (Array.isArray(req.body?.rows)) {
    rows = req.body.rows;
  }

  if (!rows.length) return res.status(400).json({ ok: false, error: "no valid rows" });

  let inserted = 0, skipped = 0;
  for (const row of rows) {
    const code = String(row.product_code || "").trim();
    const u    = String(row.roblox_user  || "").trim();
    const p    = String(row.roblox_pass  || "").trim();
    const n    = String(row.note         || "").trim();
    if (!code || !u || !p) { skipped++; continue; }
    try {
      await pool.query(
        `insert into account_credentials (product_code, roblox_user, roblox_pass, note)
         values ($1,$2,$3,$4)`,
        [code, u, p, n]
      );
      inserted++;
    } catch { skipped++; }
  }

  res.json({ ok: true, inserted, skipped, total: rows.length });
});

// List credentials for a product (admin only — shows passwords)
app.get("/api/admin/credentials/:code", requireAuth, requireAdmin, async (req, res) => {
  const code = String(req.params.code || "").trim();
  const r = await pool.query(
    `select id, product_code, roblox_user, roblox_pass, note, assigned_order_id, assigned_at, created_at
     from account_credentials where product_code=$1 order by id asc`,
    [code]
  );
  res.json({ ok: true, credentials: r.rows });
});

// Delete a single credential by id
app.post("/api/admin/credentials/delete", requireAuth, requireAdmin, async (req, res) => {
  const id = Number(req.body?.id);
  if (!id) return res.status(400).json({ ok: false, error: "id required" });
  await pool.query(`delete from account_credentials where id=$1`, [id]);
  res.json({ ok: true });
});

// ================= ORDERS =================
app.post("/api/orders/create", requireAuth, async (req, res) => {
  const cart = Array.isArray(req.body?.cart) ? req.body.cart : [];
  if (!cart.length) return res.status(400).json({ ok: false, error: "empty cart" });

  const codes = cart.map((i) => String(i.code || ""));
  const prods = await pool.query(
    `select code,price_int,stock_int,sold from products where code = any($1::text[])`,
    [codes]
  );
  const map = new Map(prods.rows.map((p) => [p.code, p]));

  // Validate stock and compute total
  let total = 0;
  for (const item of cart) {
    const code = String(item.code || "");
    const qty = Math.max(1, Number(item.qty || 1));
    const p = map.get(code);
    if (!p) return res.status(400).json({ ok: false, error: `unknown product: ${code}` });
    if (p.sold || p.stock_int < qty) return res.status(400).json({ ok: false, error: `out of stock: ${code}` });
    total += Number(p.price_int) * qty;
  }

  // Check balance
  const userRow = await pool.query(
    `select id, balance_int from users_local where id=$1`,
    [req.user.id]
  );
  const user = userRow.rows[0];
  if (!user) return res.status(404).json({ ok: false, error: "user not found" });
  if (Number(user.balance_int) < total) {
    return res.status(400).json({
      ok: false,
      error: `Insufficient balance. Need ${total} tokens, you have ${user.balance_int}.`,
    });
  }

  // Deduct balance
  await pool.query(
    `update users_local set balance_int = balance_int - $1 where id=$2`,
    [total, req.user.id]
  );

  // Build enriched cart with credentials
  const enrichedCart = [];
  for (const item of cart) {
    const code = String(item.code || "");
    const qty = Math.max(1, Number(item.qty || 1));

    // Mark product sold / decrement stock
    await pool.query(
      `update products set stock_int = GREATEST(0, stock_int - $1),
        sold = (stock_int - $1 <= 0),
        sold_at = case when (stock_int - $1 <= 0) then now() else sold_at end,
        purchases_count = purchases_count + $1
       where code=$2`,
      [qty, code]
    );

    // Fetch and assign credentials
    const cred = await pool.query(
      `select id, roblox_user, roblox_pass, note
       from account_credentials
       where product_code=$1 and assigned_order_id is null
       limit 1`,
      [code]
    );
    let credentials = null;
    if (cred.rows[0]) {
      credentials = {
        user: cred.rows[0].roblox_user,
        pass: cred.rows[0].roblox_pass,
        note: cred.rows[0].note,
      };
      // Mark as assigned
      await pool.query(
        `update account_credentials set assigned_order_id=$1, assigned_at=now() where id=$2`,
        [0, cred.rows[0].id] // will be updated below once order is created
      );
      // store id to update after order insert
      item._credId = cred.rows[0].id;
    }
    enrichedCart.push({ code, qty, credentials });
  }

  // Create order with enriched cart (including credentials)
  const created = await pool.query(
    `insert into orders (user_id, cart, total_int, status)
     values ($1,$2,$3,'completed')
     returning id,status,total_int,created_at`,
    [req.user.id, JSON.stringify(enrichedCart), total]
  );
  const orderId = created.rows[0].id;

  // Update credential assignments with real order id
  for (const item of cart) {
    if (item._credId) {
      await pool.query(
        `update account_credentials set assigned_order_id=$1 where id=$2`,
        [orderId, item._credId]
      );
    }
    await pool.query(`insert into order_items(order_id,product_code,qty) values ($1,$2,$3)`, [
      orderId,
      String(item.code),
      Math.max(1, Number(item.qty || 1)),
    ]);
  }

  res.json({ ok: true, order: created.rows[0] });
});

// ================= PAYMENT SLOTS =================
app.get("/api/payment-slots", async (req, res) => {
  const rows = await pool.query(
    `select slot,title,item_key,points_per_unit,image_url,enabled from payment_slots order by slot asc`
  );
  res.json({ ok: true, slots: rows.rows });
});

app.post("/api/admin/payment-slots/set", requireAdminKey, async (req, res) => {
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
     values ($1,'slot',$2,$3,$4) returning id,status,created_at`,
    [req.user.id, JSON.stringify(expected), points, receiver_account]
  );

  res.json({ ok: true, expected_payment: ins.rows[0], expected, points });
});

app.post("/api/payments/expect-multi", requireAuth, async (req, res) => {
  const receiver_account = String(req.body?.receiver_account || "").trim();
  const items = req.body?.items || {};

  if (!receiver_account) return res.status(400).json({ ok: false, error: "receiver_account required" });
  if (!items || typeof items !== "object") return res.status(400).json({ ok: false, error: "items object required" });

  const rows = await pool.query(`select slot, enabled, item_key, points_per_unit from payment_slots`);
  const byKey = new Map(rows.rows.map(r => [String(r.item_key || ""), r]));

  let expected = {};
  let totalPoints = 0;

  for (const [k, v] of Object.entries(items)) {
    const key = String(k || "").trim();
    const qty = Math.floor(Number(v || 0));
    if (!key || qty <= 0) continue;
    const slot = byKey.get(key);
    if (!slot || !slot.enabled)
      return res.status(400).json({ ok: false, error: `slot disabled or unknown item_key: ${key}` });
    expected[key] = qty;
    totalPoints += Number(slot.points_per_unit || 0) * qty;
  }

  if (Object.keys(expected).length === 0)
    return res.status(400).json({ ok: false, error: "no valid items selected" });

  const ins = await pool.query(
    `insert into expected_payments (user_id,type,expected,points_to_credit,receiver_account)
     values ($1,'multi',$2,$3,$4) returning id,status,created_at`,
    [req.user.id, JSON.stringify(expected), totalPoints, receiver_account]
  );

  res.json({ ok: true, expected_payment: ins.rows[0], expected, points: totalPoints });
});

// ================= INVENTORY INGEST =================
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
    receiver_account,
    JSON.stringify(snapshot),
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
      await pool.query(`update users_local set balance_int = balance_int + $1 where id=$2`, [
        Number(p.points_to_credit),
        p.user_id,
      ]);
      matched.push({ expected_payment_id: p.id, credited: Number(p.points_to_credit) });
    }
  }

  res.json({ ok: true, delta, matched });
});

// ================= LEADERBOARD + MY ACCOUNTS =================
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
console.log("PORT ENV =", process.env.PORT);
const PORT = Number(process.env.PORT || 8080);
const server = app.listen(PORT, "0.0.0.0", () => console.log("✅ listening on", PORT));

process.on("SIGTERM", () => {
  console.log("⚠️ SIGTERM received — shutting down");
  server.close(() => process.exit(0));
});

// DB init after listen
initDb()
  .then(() => console.log("✅ DB ready"))
  .catch((e) => console.error("❌ DB init error (server still running):", e?.message || e));
