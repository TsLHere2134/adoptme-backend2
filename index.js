// index.js
// ESM version — package.json should include: { "type": "module" }

import express from "express";
import { Pool } from "pg";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import crypto from "crypto";
import helmet from "helmet";
import rateLimit from "express-rate-limit";

const app = express();

// ===== REQUIRED ENV =====
if (!process.env.JWT_SECRET) throw new Error("JWT_SECRET is required");
if (!process.env.ADMIN_KEY) throw new Error("ADMIN_KEY is required");
if (!process.env.INVENTORY_API_KEY) throw new Error("INVENTORY_API_KEY is required");
if (!process.env.CREDENTIALS_ENCRYPTION_KEY) {
  throw new Error("CREDENTIALS_ENCRYPTION_KEY is required");
}

const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_KEY = process.env.ADMIN_KEY;
const INVENTORY_API_KEY = process.env.INVENTORY_API_KEY;
const TWOFA_INGEST_KEY = process.env.TWOFA_INGEST_KEY || "";

const DISCORD_PUBLIC_WEBHOOK = process.env.DISCORD_PUBLIC_WEBHOOK || "";
const DISCORD_ADMIN_WEBHOOK  = process.env.DISCORD_ADMIN_WEBHOOK  || "";

const FRONTEND_ORIGINS = (process.env.FRONTEND_ORIGINS || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

const ENC_KEY = crypto
  .createHash("sha256")
  .update(process.env.CREDENTIALS_ENCRYPTION_KEY)
  .digest();

// ===== BASIC APP =====
app.set("trust proxy", 1);

app.get("/health", (req, res) => res.status(200).json({ ok: true }));
app.get("/", (req, res) => res.status(200).send("API running ✅"));

app.use(helmet());
app.use(express.json({ limit: "1mb" }));

app.use((err, req, res, next) => {
  if (err instanceof SyntaxError && "body" in err) {
    console.error("BAD JSON body:", err.message);
    return res.status(400).json({ ok: false, error: "invalid JSON in request body" });
  }
  next(err);
});

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && FRONTEND_ORIGINS.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
  }
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, x-inventory-key, x-admin-key, x-twofa-key");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

app.use((req, res, next) => {
  console.log("REQ", req.method, req.url);
  next();
});

// ===== RATE LIMITERS =====
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, standardHeaders: true, legacyHeaders: false });
const orderLimiter = rateLimit({ windowMs: 10 * 60 * 1000, max: 20, standardHeaders: true, legacyHeaders: false });
const inventoryLimiter = rateLimit({ windowMs: 1 * 60 * 1000, max: 120, standardHeaders: true, legacyHeaders: false });
const adminLimiter = rateLimit({ windowMs: 10 * 60 * 1000, max: 100, standardHeaders: true, legacyHeaders: false });
const twofaLimiter = rateLimit({ windowMs: 1 * 60 * 1000, max: 180, standardHeaders: true, legacyHeaders: false });

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : undefined,
});

// ===== DISCORD HELPERS =====
async function sendToWebhook(url, payload) {
  if (!url) return;
  try {
    await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
  } catch (e) {
    console.error("Discord webhook error:", e?.message || e);
  }
}

async function notifyPublic(username, itemCount) {
  await sendToWebhook(DISCORD_PUBLIC_WEBHOOK, {
    content: `🛒 **${username}** successfully bought ${itemCount} account${itemCount !== 1 ? "s" : ""} off the website!`,
  });
}

async function notifyAdmin({ username, orderId, totalTokens, itemCount, cartItems }) {
  const itemLines = cartItems
    .map((i) => `• \`${i.code}\` × ${i.qty}${i.credentials ? " ✅" : " ⏳"}`)
    .join("\n");

  await sendToWebhook(DISCORD_ADMIN_WEBHOOK, {
    embeds: [{
      title: "🧾 New Order — Admin Log",
      color: 0x8b7cf6,
      fields: [
        { name: "👤 User",          value: `\`${username}\``,         inline: true  },
        { name: "🧾 Order ID",      value: `#${orderId}`,             inline: true  },
        { name: "🪙 Tokens Spent",  value: `${totalTokens} tokens`,   inline: true  },
        { name: "📦 Accounts",      value: `${itemCount}`,            inline: true  },
        { name: "🗂 Items",         value: itemLines || "—",          inline: false },
      ],
      footer: { text: "AdoptMeHub — Admin Only" },
      timestamp: new Date().toISOString(),
    }],
  });
}

// --------- CRYPTO HELPERS ----------
function encryptText(text) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv("aes-256-cbc", ENC_KEY, iv);
  let encrypted = cipher.update(String(text), "utf8", "hex");
  encrypted += cipher.final("hex");
  return `${iv.toString("hex")}:${encrypted}`;
}

function decryptText(value) {
  try {
    const raw = String(value || "");
    const [ivHex, encrypted] = raw.split(":");
    if (!ivHex || !encrypted) return raw;
    const iv = Buffer.from(ivHex, "hex");
    const decipher = crypto.createDecipheriv("aes-256-cbc", ENC_KEY, iv);
    let decrypted = decipher.update(encrypted, "hex", "utf8");
    decrypted += decipher.final("utf8");
    return decrypted;
  } catch {
    return String(value || "");
  }
}

// --------- AUTH HELPERS ----------
function requireAdminKey(req, res, next) {
  if (req.header("x-admin-key") !== ADMIN_KEY)
    return res.status(401).json({ ok: false, error: "bad admin key" });
  next();
}

function requireInventoryKey(req, res, next) {
  if (req.header("x-inventory-key") !== INVENTORY_API_KEY)
    return res.status(401).json({ ok: false, error: "bad inventory key" });
  next();
}

function requireTwofaKey(req, res, next) {
  if (!TWOFA_INGEST_KEY) {
    return res.status(500).json({ ok: false, error: "TWOFA_INGEST_KEY not configured" });
  }
  if (req.header("x-twofa-key") !== TWOFA_INGEST_KEY) {
    return res.status(401).json({ ok: false, error: "bad twofa key" });
  }
  next();
}

function requireAuth(req, res, next) {
  const auth = req.header("Authorization") || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  if (!token) return res.status(401).json({ ok: false, error: "missing token" });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    payload.id = Number(payload.id);
    if (!payload.id || Number.isNaN(payload.id))
      return res.status(401).json({ ok: false, error: "invalid token payload" });
    req.user = payload;
    next();
  } catch {
    return res.status(401).json({ ok: false, error: "invalid token" });
  }
}

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
  const keys = new Set([...Object.keys(prevCounts || {}), ...Object.keys(newCounts || {})]);
  for (const k of keys) {
    const d = (newCounts?.[k] || 0) - (prevCounts?.[k] || 0);
    if (d > 0) delta[k] = d;
  }
  return delta;
}

function satisfies(delta, expected) {
  for (const [k, need] of Object.entries(expected || {})) {
    if ((delta?.[k] || 0) < Number(need)) return false;
  }
  return true;
}

// --------- HELPERS ----------
function makeCode(username) {
  const base = String(username || "ACC")
    .toUpperCase()
    .replace(/[^A-Z0-9]/g, "")
    .slice(0, 4)
    .padEnd(3, "X");
  const rand = String(Math.floor(1000 + Math.random() * 9000));
  return "U" + base + rand;
}

async function computePriceFromRate(agePots) {
  const r = await pool.query(`select value from settings where key='rate_agepots_per_token'`);
  const rate = Math.max(1, Number(r.rows[0]?.value || 70));
  return Math.ceil(Number(agePots || 0) / rate);
}

function normalizeAccountUsername(value) {
  return String(value || "").trim();
}

// --------- DB INIT ----------
async function initDb() {
  await pool.query(`
    create table if not exists users_local (
      id bigserial primary key,
      username text not null unique,
      password_hash text not null,
      balance_int bigint not null default 0,
      is_admin boolean not null default false,
      is_blacklisted boolean not null default false,
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
      created_at timestamptz not null default now(),
      expires_at timestamptz,
      matched_at timestamptz,
      matched_snapshot_id bigint
    );

    create table if not exists inventory_snapshots (
      id bigserial primary key,
      receiver_account text not null,
      received_at timestamptz not null default now(),
      data jsonb not null,
      delta jsonb not null default '{}'::jsonb
    );

    create table if not exists account_credentials (
      id bigserial primary key,
      product_code text not null,
      roblox_user text not null,
      roblox_pass text not null,
      note text not null default '',
      age_pots int not null default 0,
      bucks int not null default 0,
      assigned_order_id bigint,
      assigned_at timestamptz,
      created_at timestamptz not null default now()
    );

    create table if not exists token_ledger (
      id bigserial primary key,
      user_id bigint references users_local(id),
      delta bigint not null,
      reason text not null,
      meta jsonb not null default '{}'::jsonb,
      created_at timestamptz not null default now()
    );

    create table if not exists account_twofa_codes (
      id bigserial primary key,
      account_username text not null,
      code text not null,
      source text not null default 'unknown',
      message_id text,
      channel_id text,
      used boolean not null default false,
      created_at timestamptz not null default now(),
      expires_at timestamptz not null
    );
  `);

  await pool.query(`
    alter table products add column if not exists kind text not null default 'account';
    alter table products add column if not exists sold boolean not null default false;
    alter table products add column if not exists sold_at timestamptz;
    alter table products add column if not exists purchases_count int not null default 0;
    alter table products add column if not exists image_url text not null default '';

    alter table users_local add column if not exists is_admin boolean not null default false;
    alter table users_local add column if not exists is_blacklisted boolean not null default false;

    alter table account_credentials add column if not exists age_pots int not null default 0;
    alter table account_credentials add column if not exists bucks int not null default 0;

    alter table inventory_snapshots add column if not exists delta jsonb not null default '{}'::jsonb;
    alter table inventory_snapshots add column if not exists receiver_account text not null default 'unknown';
    alter table inventory_snapshots add column if not exists received_at timestamptz not null default now();

    alter table expected_payments add column if not exists expires_at timestamptz;
    alter table expected_payments add column if not exists matched_at timestamptz;
    alter table expected_payments add column if not exists matched_snapshot_id bigint;

    alter table account_twofa_codes add column if not exists source text not null default 'unknown';
    alter table account_twofa_codes add column if not exists message_id text;
    alter table account_twofa_codes add column if not exists channel_id text;
    alter table account_twofa_codes add column if not exists used boolean not null default false;
    alter table account_twofa_codes add column if not exists created_at timestamptz not null default now();
    alter table account_twofa_codes add column if not exists expires_at timestamptz;
  `);

  await pool.query(`
    update expected_payments
    set expires_at = created_at + interval '45 minutes'
    where expires_at is null
  `);

  await pool.query(`
    update account_twofa_codes
    set expires_at = created_at + interval '5 minutes'
    where expires_at is null
  `);

  await pool.query(`
    do $$ begin
      if exists (
        select 1 from pg_constraint
        where conname = 'account_credentials_product_code_key'
      ) then
        alter table account_credentials drop constraint account_credentials_product_code_key;
      end if;
    end $$;
  `);

  await pool.query(`
    insert into settings (key,value)
    values ('rate_agepots_per_token','70')
    on conflict (key) do nothing;
  `);

  for (let i = 1; i <= 15; i++) {
    await pool.query(
      `insert into payment_slots (slot) values ($1) on conflict (slot) do nothing`,
      [i]
    );
  }

  const creds = await pool.query(`select id, roblox_pass from account_credentials`);
  for (const row of creds.rows) {
    const val = String(row.roblox_pass || "");
    if (val && !val.includes(":")) {
      await pool.query(
        `update account_credentials set roblox_pass=$1 where id=$2`,
        [encryptText(val), row.id]
      );
    }
  }

  await pool.query(`
    create index if not exists idx_account_twofa_codes_account_username
    on account_twofa_codes (account_username);

    create index if not exists idx_account_twofa_codes_expires_at
    on account_twofa_codes (expires_at);
  `);
}

// ================= AUTH =================
app.post("/api/auth/register", authLimiter, async (req, res) => {
  const username = String(req.body?.username || "").trim().toLowerCase();
  const password = String(req.body?.password || "");
  if (username.length < 3) return res.status(400).json({ ok: false, error: "username too short" });
  if (password.length < 6) return res.status(400).json({ ok: false, error: "password too short (min 6)" });
  const hash = await bcrypt.hash(password, 10);
  try {
    const ins = await pool.query(
      `insert into users_local (username,password_hash) values ($1,$2) returning id,username,balance_int,is_admin,created_at`,
      [username, hash]
    );
    const user = ins.rows[0];
    const token = jwt.sign({ id: user.id, username: user.username, is_admin: user.is_admin }, JWT_SECRET, { expiresIn: "30d" });
    res.json({ ok: true, token, user });
  } catch {
    res.status(400).json({ ok: false, error: "username already used" });
  }
});

app.post("/api/auth/login", authLimiter, async (req, res) => {
  const username = String(req.body?.username || "").trim().toLowerCase();
  const password = String(req.body?.password || "");
  const u = await pool.query(
    `select id,username,password_hash,balance_int,is_admin,is_blacklisted,created_at from users_local where username=$1`,
    [username]
  );
  if (!u.rows[0]) return res.status(401).json({ ok: false, error: "bad login" });
  if (u.rows[0].is_blacklisted) return res.status(403).json({ ok: false, error: "blacklisted" });
  const ok = await bcrypt.compare(password, u.rows[0].password_hash);
  if (!ok) return res.status(401).json({ ok: false, error: "bad login" });
  const token = jwt.sign(
    { id: u.rows[0].id, username: u.rows[0].username, is_admin: u.rows[0].is_admin },
    JWT_SECRET,
    { expiresIn: "30d" }
  );
  res.json({
    ok: true, token,
    user: { id: u.rows[0].id, username: u.rows[0].username, balance_int: u.rows[0].balance_int, is_admin: u.rows[0].is_admin, created_at: u.rows[0].created_at },
  });
});

app.get("/api/me", requireAuth, async (req, res) => {
  const u = await pool.query(
    `select id,username,balance_int,is_admin,is_blacklisted,created_at from users_local where id=$1`,
    [req.user.id]
  );
  if (!u.rows[0]) return res.status(404).json({ ok: false, error: "user not found" });
  if (u.rows[0].is_blacklisted) return res.status(403).json({ ok: false, error: "blacklisted" });
  res.json({ ok: true, me: { id: u.rows[0].id, username: u.rows[0].username, balance_int: u.rows[0].balance_int, is_admin: u.rows[0].is_admin, created_at: u.rows[0].created_at } });
});

// ================= SETTINGS =================
app.get("/api/settings", async (req, res) => {
  const r = await pool.query(`select value from settings where key='rate_agepots_per_token'`);
  res.json({ ok: true, rate_agepots_per_token: Number(r.rows[0]?.value || 70) });
});

app.post("/api/admin/settings", adminLimiter, requireAdminKey, async (req, res) => {
  const rate = Math.max(1, Number(req.body?.rate_agepots_per_token || 70));
  await pool.query(
    `insert into settings(key,value) values('rate_agepots_per_token',$1) on conflict(key) do update set value=excluded.value`,
    [String(rate)]
  );
  res.json({ ok: true, rate });
});

// ================= PRODUCTS =================
app.get("/api/products", async (req, res) => {
  const rows = await pool.query(`
    select
      p.id, p.code, p.title, p.kind, p.age_pots, p.bucks,
      p.price_int, p.stock_int, p.note, p.image_url, p.sold, p.purchases_count,
      count(c.id) filter (where c.assigned_order_id is null) as cred_count
    from products p
    left join account_credentials c on c.product_code = p.code
    group by p.id, p.code, p.title, p.kind, p.age_pots, p.bucks,
      p.price_int, p.stock_int, p.note, p.image_url, p.sold, p.purchases_count, p.created_at
    order by p.created_at desc
  `);
  res.json({ ok: true, products: rows.rows });
});

// ===== OWNER VAULT (ALL ACCOUNTS IN ONE REQUEST) =====
app.get("/api/admin/all-accounts", requireAuth, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT roblox_user
      FROM account_credentials
      WHERE roblox_user IS NOT NULL
      ORDER BY id ASC
    `);

    const users = result.rows.map(r => ({
      user: String(r.roblox_user || "").trim()
    })).filter(x => x.user.length > 0);

    res.json(users);

  } catch (err) {
    console.error("Vault fetch error:", err);
    res.status(500).json({ error: "Failed to fetch accounts" });
  }
});
// ================= JWT ADMIN: USERS =================
app.post("/api/admin/users/balance", adminLimiter, requireAuth, requireAdmin, async (req, res) => {
  const username = String(req.body?.username || "").trim();
  const delta = Number(req.body?.delta || 0);
  if (!username || !Number.isFinite(delta))
    return res.status(400).json({ ok: false, error: "username + numeric delta required" });
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const q = await client.query(
      `update users_local set balance_int = GREATEST(0, balance_int + $1) where username=$2 returning id,username,balance_int,is_blacklisted,is_admin`,
      [Math.trunc(delta), username]
    );
    if (!q.rows[0]) { await client.query("ROLLBACK"); return res.status(404).json({ ok: false, error: "user not found" }); }
    await client.query(
      `insert into token_ledger (user_id, delta, reason, meta) values ($1,$2,'admin_balance_adjust',$3::jsonb)`,
      [q.rows[0].id, Math.trunc(delta), JSON.stringify({ admin_id: req.user.id, username })]
    );
    await client.query("COMMIT");
    res.json({ ok: true, user: q.rows[0] });
  } catch (e) {
    await client.query("ROLLBACK");
    console.error("admin/users/balance error:", e?.message || e);
    res.status(500).json({ ok: false, error: "balance update failed" });
  } finally { client.release(); }
});

app.post("/api/admin/users/blacklist", adminLimiter, requireAuth, requireAdmin, async (req, res) => {
  const username = String(req.body?.username || "").trim();
  const value = !!req.body?.value;
  if (!username) return res.status(400).json({ ok: false, error: "username required" });
  const q = await pool.query(
    `update users_local set is_blacklisted=$1 where username=$2 returning id,username,is_blacklisted`,
    [value, username]
  );
  if (!q.rows[0]) return res.status(404).json({ ok: false, error: "user not found" });
  res.json({ ok: true, user: q.rows[0] });
});

// ================= JWT ADMIN: PRODUCTS =================
app.post("/api/admin/products/upsert", adminLimiter, requireAuth, requireAdmin, async (req, res) => {
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
  const sold      = stock_int <= 0;
  const q = await pool.query(
    `insert into products (code,title,kind,age_pots,bucks,price_int,stock_int,note,image_url,sold)
     values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
     on conflict (code) do update set
       title=excluded.title, kind=excluded.kind, age_pots=excluded.age_pots, bucks=excluded.bucks,
       price_int=excluded.price_int, stock_int=excluded.stock_int, note=excluded.note,
       image_url=excluded.image_url, sold=excluded.sold
     returning *;`,
    [code, title, kind, age_pots, bucks, price_int, stock_int, note, image_url, sold]
  );
  res.json({ ok: true, product: q.rows[0] });
});

app.post("/api/admin/products/delete", adminLimiter, requireAuth, requireAdmin, async (req, res) => {
  const code = String(req.body?.code || "").trim();
  if (!code) return res.status(400).json({ ok: false, error: "code required" });
  await pool.query(`delete from products where code=$1`, [code]);
  res.json({ ok: true });
});

// ================= BULK DELETE ALL PRODUCTS =================
app.post("/api/admin/products/delete-all", adminLimiter, requireAuth, requireAdmin, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query(`delete from account_credentials where assigned_order_id is null`);
    const r = await client.query(`delete from products returning code`);
    await client.query("COMMIT");
    console.log(`Admin ${req.user.username} bulk-deleted ${r.rowCount} products`);
    res.json({ ok: true, deleted: r.rowCount });
  } catch (e) {
    await client.query("ROLLBACK");
    console.error("products/delete-all error:", e?.message || e);
    res.status(500).json({ ok: false, error: "bulk delete failed" });
  } finally { client.release(); }
});

// ================= ADMIN: CREDENTIALS =================
app.post("/api/admin/credentials/add", adminLimiter, requireAuth, requireAdmin, async (req, res) => {
  const product_code = String(req.body?.product_code || "").trim();
  const roblox_user  = String(req.body?.roblox_user  || "").trim();
  const roblox_pass  = String(req.body?.roblox_pass  || "").trim();
  const note         = String(req.body?.note         || "").trim();
  const age_pots     = Math.max(0, Number(req.body?.age_pots || 0));
  const bucks        = Math.max(0, Number(req.body?.bucks    || 0));
  if (!product_code || !roblox_user || !roblox_pass)
    return res.status(400).json({ ok: false, error: "product_code, roblox_user, roblox_pass required" });
  const encryptedPass = encryptText(roblox_pass);
  const r = await pool.query(
    `insert into account_credentials (product_code,roblox_user,roblox_pass,note,age_pots,bucks)
     values ($1,$2,$3,$4,$5,$6) returning id,product_code,roblox_user,assigned_order_id,created_at`,
    [product_code, roblox_user, encryptedPass, note, age_pots, bucks]
  );
  await pool.query(`update products set stock_int = stock_int + 1, sold = false where code=$1`, [product_code]);
  res.json({ ok: true, credential: r.rows[0] });
});

app.get("/api/admin/credentials/:code", adminLimiter, requireAuth, requireAdmin, async (req, res) => {
  const code = req.params.code;
  const r = await pool.query(
    `select id, product_code, roblox_user, roblox_pass, note, age_pots, bucks, assigned_order_id, created_at
     from account_credentials where product_code=$1 order by id asc`,
    [code]
  );
  res.json({ ok: true, credentials: r.rows.map((row) => ({ ...row, roblox_pass: decryptText(row.roblox_pass) })) });
});

app.post("/api/admin/credentials/delete", adminLimiter, requireAuth, requireAdmin, async (req, res) => {
  const id = Number(req.body?.id);
  if (!id) return res.status(400).json({ ok: false, error: "id required" });
  await pool.query(`delete from account_credentials where id=$1`, [id]);
  res.json({ ok: true });
});

// ================= ADMIN: MASS IMPORT =================
app.post("/api/admin/credentials/import", adminLimiter, requireAuth, requireAdmin, async (req, res) => {
  const csv = String(req.body?.csv || "").trim();
  if (!csv) return res.status(400).json({ ok: false, error: "csv required" });
  const lines = csv.split("\n").map((l) => l.trim()).filter(Boolean);
  let inserted = 0, skipped = 0;
  const products = [];
  for (const line of lines) {
    const parts = line.split(",");
    if (parts.length < 4) { skipped++; continue; }
    const [roblox_user_raw, roblox_pass_raw, age_pots_raw, bucks_raw, ...noteParts] = parts;
    const roblox_user = roblox_user_raw?.trim();
    const roblox_pass = roblox_pass_raw?.trim();
    const note        = noteParts.join(",").trim();
    const age_pots    = Math.max(0, Number(age_pots_raw?.trim() || 0));
    const bucks       = Math.max(0, Number(bucks_raw?.trim()    || 0));
    if (!roblox_user || !roblox_pass) { skipped++; continue; }
    const censored  = roblox_user[0] + "*".repeat(Math.max(1, roblox_user.length - 1));
    const price_int = await computePriceFromRate(age_pots);
    const code      = makeCode(roblox_user);
    try {
      await pool.query(
        `insert into products (code, title, kind, age_pots, bucks, price_int, stock_int, note, sold)
         values ($1, $2, 'account', $3, $4, $5, 1, '', false)
         on conflict (code) do update set
           age_pots=excluded.age_pots, bucks=excluded.bucks, price_int=excluded.price_int,
           stock_int=products.stock_int + 1, sold=false`,
        [code, censored, age_pots, bucks, price_int]
      );
      await pool.query(
        `insert into account_credentials (product_code, roblox_user, roblox_pass, note, age_pots, bucks) values ($1, $2, $3, $4, $5, $6)`,
        [code, roblox_user, encryptText(roblox_pass), note, age_pots, bucks]
      );
      products.push(code);
      inserted++;
    } catch (e) {
      console.error("import row error:", e?.message);
      skipped++;
    }
  }
  res.json({ ok: true, inserted, skipped, total: lines.length, products });
});

// ================= ORDERS =================
app.post("/api/orders/create", orderLimiter, requireAuth, async (req, res) => {
  const cart = Array.isArray(req.body?.cart) ? req.body.cart : [];
  if (!cart.length) return res.status(400).json({ ok: false, error: "empty cart" });

  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    const codes = [...new Set(cart.map((i) => String(i.code || "")))];
    const prods = await client.query(
      `select code, price_int, stock_int, sold from products where code = any($1::text[]) for update`,
      [codes]
    );
    const map = new Map(prods.rows.map((p) => [p.code, p]));

    let total = 0;
    for (const item of cart) {
      const code = String(item.code || "");
      const qty  = Math.max(1, Number(item.qty || 1));
      const p    = map.get(code);
      if (!p) { await client.query("ROLLBACK"); return res.status(400).json({ ok: false, error: `unknown product: ${code}` }); }
      if (p.sold || Number(p.stock_int) < qty) { await client.query("ROLLBACK"); return res.status(400).json({ ok: false, error: `out of stock: ${code}` }); }
      total += Number(p.price_int) * qty;
    }

    const userRow = await client.query(`select id, balance_int from users_local where id=$1 for update`, [req.user.id]);
    const user = userRow.rows[0];
    if (!user) { await client.query("ROLLBACK"); return res.status(404).json({ ok: false, error: "user not found" }); }
    if (Number(user.balance_int) < total) {
      await client.query("ROLLBACK");
      return res.status(400).json({ ok: false, error: `Not enough tokens. Need ${total}, you have ${user.balance_int}.` });
    }

    await client.query(`update users_local set balance_int = balance_int - $1 where id=$2`, [total, req.user.id]);
    await client.query(`insert into token_ledger (user_id, delta, reason, meta) values ($1,$2,'purchase',$3::jsonb)`, [req.user.id, -total, JSON.stringify({ cart })]);

    const enrichedCart = [];
    for (const item of cart) {
      const code = String(item.code || "");
      const qty  = Math.max(1, Number(item.qty || 1));
      await client.query(`update products set stock_int = GREATEST(0, stock_int - $1), purchases_count = purchases_count + $1 where code = $2`, [qty, code]);
      await client.query(`update products set sold = (stock_int <= 0), sold_at = case when stock_int <= 0 then now() else sold_at end where code = $1`, [code]);
      const cred = await client.query(
        `select id, roblox_user, roblox_pass, note, age_pots, bucks from account_credentials
         where product_code = $1 and assigned_order_id is null order by id asc limit 1 for update skip locked`,
        [code]
      );
      let credentials = null, credId = null;
      if (cred.rows[0]) {
        credId = cred.rows[0].id;
        credentials = {
          user: cred.rows[0].roblox_user,
          pass: decryptText(cred.rows[0].roblox_pass),
          note: cred.rows[0].note,
          age_pots: cred.rows[0].age_pots,
          bucks: cred.rows[0].bucks,
        };
        await client.query(`update account_credentials set assigned_order_id=-1 where id=$1`, [credId]);
      }
      enrichedCart.push({ code, qty, credentials, _credId: credId });
    }

    const created = await client.query(
      `insert into orders (user_id, cart, total_int, status) values ($1::bigint,$2,$3,'completed') returning id, status, total_int, created_at`,
      [req.user.id, JSON.stringify(enrichedCart.map((i) => ({ code: i.code, qty: i.qty, credentials: i.credentials }))), total]
    );
    const orderId = created.rows[0].id;

    for (const item of enrichedCart) {
      if (item._credId) await client.query(`update account_credentials set assigned_order_id=$1, assigned_at=now() where id=$2`, [orderId, item._credId]);
      await client.query(`insert into order_items(order_id,product_code,qty) values($1,$2,$3)`, [orderId, item.code, item.qty]);
    }

    await client.query("COMMIT");

    const totalItems = enrichedCart.reduce((s, i) => s + i.qty, 0);
    notifyPublic(req.user.username, totalItems).catch(console.error);
    notifyAdmin({ username: req.user.username, orderId, totalTokens: total, itemCount: totalItems, cartItems: enrichedCart }).catch(console.error);

    res.json({
      ok: true,
      order: {
        ...created.rows[0],
        cart: enrichedCart.map((i) => ({ code: i.code, qty: i.qty, credentials: i.credentials })),
      },
    });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("orders/create error:", err?.message || err);
    res.status(500).json({ ok: false, error: "order failed" });
  } finally {
    client.release();
  }
});

// ================= PAYMENT SLOTS =================
app.get("/api/payment-slots", async (req, res) => {
  const rows = await pool.query(`select slot,title,item_key,points_per_unit,image_url,enabled from payment_slots order by slot asc`);
  res.json({ ok: true, slots: rows.rows });
});

app.post("/api/admin/payment-slots/set", adminLimiter, requireAdminKey, async (req, res) => {
  const slot            = Math.min(15, Math.max(1, Number(req.body?.slot)));
  const title           = String(req.body?.title || "");
  const item_key        = String(req.body?.item_key || "");
  const points_per_unit = Math.max(0, Number(req.body?.points_per_unit || 0));
  const image_url       = req.body?.image_url ? String(req.body.image_url) : null;
  const enabled         = Boolean(req.body?.enabled);
  await pool.query(`update payment_slots set title=$2,item_key=$3,points_per_unit=$4,image_url=$5,enabled=$6 where slot=$1`, [slot, title, item_key, points_per_unit, image_url, enabled]);
  res.json({ ok: true });
});

async function createExpectedPayment(userId, type, expectedObj, points, receiver) {
  const ins = await pool.query(
    `insert into expected_payments (user_id,type,expected,points_to_credit,receiver_account,status,expires_at)
     values ($1,$2,$3,$4,$5,'pending', now() + interval '45 minutes') returning id,status,created_at,expires_at`,
    [userId, type, JSON.stringify(expectedObj), points, receiver]
  );
  return ins.rows[0];
}

app.post("/api/payments/expect-slot", requireAuth, async (req, res) => {
  const receiver_account = String(req.body?.receiver_account || "").trim();
  const slot = Math.min(15, Math.max(1, Number(req.body?.slot)));
  const qty  = Math.max(1, Number(req.body?.qty || 1));
  if (!receiver_account) return res.status(400).json({ ok: false, error: "receiver_account required" });
  const s = await pool.query(`select enabled,item_key,points_per_unit from payment_slots where slot=$1`, [slot]);
  if (!s.rows[0] || !s.rows[0].enabled) return res.status(400).json({ ok: false, error: "slot disabled" });
  const item_key = String(s.rows[0].item_key || "").trim();
  if (!item_key) return res.status(400).json({ ok: false, error: "slot has empty item_key" });
  const points   = Number(s.rows[0].points_per_unit) * qty;
  const expected = { [item_key]: qty };
  const expected_payment = await createExpectedPayment(req.user.id, "slot", expected, points, receiver_account);
  res.json({ ok: true, expected_payment, expected, points });
});

app.post("/api/payments/expect-multi", requireAuth, async (req, res) => {
  const receiver_account = String(req.body?.receiver_account || "").trim();
  const items = req.body?.items || {};
  if (!receiver_account) return res.status(400).json({ ok: false, error: "receiver_account required" });
  if (!items || typeof items !== "object" || Array.isArray(items)) return res.status(400).json({ ok: false, error: "items object required" });
  const rows = await pool.query(`select enabled,item_key,points_per_unit from payment_slots`);
  const byKey = new Map(rows.rows.map((r) => [String(r.item_key || ""), r]));
  let expected = {}, totalPoints = 0;
  for (const [k, v] of Object.entries(items)) {
    const key = String(k || "").trim();
    const qty = Math.floor(Number(v || 0));
    if (!key || qty <= 0) continue;
    const slotRow = byKey.get(key);
    if (!slotRow || !slotRow.enabled) return res.status(400).json({ ok: false, error: `slot disabled or unknown item_key: ${key}` });
    expected[key] = qty;
    totalPoints += Number(slotRow.points_per_unit || 0) * qty;
  }
  if (!Object.keys(expected).length) return res.status(400).json({ ok: false, error: "no valid items selected" });
  const expected_payment = await createExpectedPayment(req.user.id, "multi", expected, totalPoints, receiver_account);
  res.json({ ok: true, expected_payment, expected, points: totalPoints });
});

// ================= INVENTORY INGEST =================
async function handleInventoryIngest(req, res) {
  const receiver_account = String(req.body?.receiver_account || req.body?.user || "unknown");
  const snapshot = req.body;
  const last = await pool.query(`select data from inventory_snapshots where receiver_account=$1 order by id desc limit 1`, [receiver_account]);
  const prev  = last.rows[0]?.data || null;
  const delta = deltaCounts(prev ? countFromSnapshot(prev) : {}, countFromSnapshot(snapshot));
  const snapIns = await pool.query(
    `insert into inventory_snapshots (receiver_account,data,delta) values ($1,$2,$3) returning id, received_at`,
    [receiver_account, JSON.stringify(snapshot), JSON.stringify(delta)]
  );
  const snapshotId = snapIns.rows[0].id;
  const client = await pool.connect();
  const matched = [];
  try {
    await client.query("BEGIN");
    await client.query(`update expected_payments set status='expired' where status='pending' and expires_at <= now()`);
    const pending = await client.query(
      `select id,user_id,expected,points_to_credit,expires_at from expected_payments
       where receiver_account=$1 and status='pending' and expires_at > now() order by id asc for update skip locked`,
      [receiver_account]
    );
    let picked = null;
    for (const p of pending.rows) { if (satisfies(delta, p.expected)) { picked = p; break; } }
    if (picked) {
      await client.query(`update expected_payments set status='matched', matched_at=now(), matched_snapshot_id=$2 where id=$1`, [picked.id, snapshotId]);
      await client.query(`update users_local set balance_int = balance_int + $1 where id=$2`, [Number(picked.points_to_credit), picked.user_id]);
      await client.query(
        `insert into token_ledger (user_id, delta, reason, meta) values ($1,$2,'inventory_payment_match',$3::jsonb)`,
        [picked.user_id, Number(picked.points_to_credit), JSON.stringify({ expected_payment_id: picked.id, snapshot_id: snapshotId, receiver_account })]
      );
      matched.push({ expected_payment_id: picked.id, credited: Number(picked.points_to_credit) });
    }
    await client.query("COMMIT");
  } catch (e) {
    await client.query("ROLLBACK");
    console.error("inventory ingest match error:", e?.message || e);
    return res.status(500).json({ ok: false, error: "inventory ingest failed" });
  } finally { client.release(); }
  res.json({ ok: true, receiver_account, snapshot_id: snapshotId, delta, matched });
}

app.post("/inventory",     inventoryLimiter, requireInventoryKey, handleInventoryIngest);
app.post("/inventory.php", inventoryLimiter, requireInventoryKey, handleInventoryIngest);

// ================= 2FA =================
app.post("/api/twofa/ingest", twofaLimiter, requireTwofaKey, async (req, res) => {
  const username = normalizeAccountUsername(req.body?.username);
  const code = String(req.body?.code || "").trim();
  const source = String(req.body?.source || "discord_bot").trim().slice(0, 100) || "discord_bot";
  const message_id = req.body?.message_id ? String(req.body.message_id).trim().slice(0, 100) : null;
  const channel_id = req.body?.channel_id ? String(req.body.channel_id).trim().slice(0, 100) : null;
  const expiresInSeconds = Math.max(30, Math.min(900, Number(req.body?.expires_in_seconds || 300)));

  if (!username || !code) {
    return res.status(400).json({ ok: false, error: "missing username/code" });
  }

  const expiresAt = new Date(Date.now() + expiresInSeconds * 1000);

  const inserted = await pool.query(
    `insert into account_twofa_codes (account_username, code, source, message_id, channel_id, expires_at)
     values ($1, $2, $3, $4, $5, $6)
     returning id, account_username, code, created_at, expires_at`,
    [username, code, source, message_id, channel_id, expiresAt]
  );

  res.json({ ok: true, entry: inserted.rows[0] });
});

async function getOwnedAccountUsernames(userId) {
  const orders = await pool.query(
    `select cart from orders where user_id=$1 and status='completed' order by id desc`,
    [userId]
  );

  const usernames = new Set();

  for (const order of orders.rows) {
    const cart = Array.isArray(order.cart) ? order.cart : [];
    for (const item of cart) {
      const ownedUser = normalizeAccountUsername(item?.credentials?.user);
      if (ownedUser) usernames.add(ownedUser);
    }
  }

  return [...usernames];
}

async function sendMyTwofaCodes(req, res) {
  const usernames = await getOwnedAccountUsernames(req.user.id);

  if (!usernames.length) {
    return res.json({ ok: true, codes: [] });
  }

  const r = await pool.query(
    `select distinct on (account_username)
        account_username,
        code,
        created_at,
        expires_at,
        source
     from account_twofa_codes
     where account_username = any($1::text[])
       and expires_at > now()
       and used = false
     order by account_username, id desc`,
    [usernames]
  );

  res.json({ ok: true, codes: r.rows });
}

app.get("/api/my-2fa-codes", requireAuth, sendMyTwofaCodes);
app.get("/api/my-accounts/2fa", requireAuth, sendMyTwofaCodes);
app.get("/api/twofa/my", requireAuth, sendMyTwofaCodes);

// ================= LEADERBOARD + MY ACCOUNTS =================
app.get("/api/leaderboard", async (req, res) => {
  const rows = await pool.query(`
    select u.username, sum(o.total_int)::bigint as total_spent, count(o.id)::int as order_count
    from orders o join users_local u on u.id = o.user_id
    where o.status = 'completed' group by u.username order by total_spent desc limit 20
  `);
  res.json({ ok: true, leaderboard: rows.rows });
});

app.get("/api/member-count", async (req, res) => {
  const r = await pool.query(`select count(*)::int as count from users_local`);
  res.json({ ok: true, count: r.rows[0]?.count ?? 0 });
});

app.get("/api/my-accounts", requireAuth, async (req, res) => {
  const rows = await pool.query(`select id, status, cart, total_int, created_at from orders where user_id=$1 order by id desc`, [req.user.id]);
  res.json({ ok: true, orders: rows.rows });
});

app.delete("/api/my-accounts/:orderId", requireAuth, async (req, res) => {
  const orderId = Number(req.params.orderId);
  if (!orderId || Number.isNaN(orderId)) return res.status(400).json({ ok: false, error: "invalid order id" });
  const check = await pool.query(`select id from orders where id=$1 and user_id=$2`, [orderId, req.user.id]);
  if (!check.rows[0]) return res.status(404).json({ ok: false, error: "order not found" });
  await pool.query(`delete from order_items where order_id=$1`, [orderId]);
  await pool.query(`delete from orders where id=$1 and user_id=$2`, [orderId, req.user.id]);
  res.json({ ok: true, deleted: orderId });
});

app.delete("/api/my-accounts", requireAuth, async (req, res) => {
  const ids = await pool.query(`select id from orders where user_id=$1`, [req.user.id]);
  const orderIds = ids.rows.map((r) => r.id);
  if (orderIds.length) {
    await pool.query(`delete from order_items where order_id = any($1::bigint[])`, [orderIds]);
    await pool.query(`delete from orders where user_id=$1`, [req.user.id]);
  }
  res.json({ ok: true, deleted: orderIds.length });
});

// ================= ADMIN: CUSTOMER ORDERS =================
app.get("/api/admin/orders/user/:username", adminLimiter, requireAuth, requireAdmin, async (req, res) => {
  const username = req.params.username;
  const u = await pool.query(`select id, username, balance_int from users_local where username=$1`, [username]);
  if (!u.rows[0]) return res.status(404).json({ ok: false, error: "user not found" });
  const orders = await pool.query(`select id, status, cart, total_int, created_at from orders where user_id=$1 order by id desc`, [u.rows[0].id]);
  res.json({ ok: true, user: u.rows[0], orders: orders.rows });
});

app.get("/api/admin/orders", adminLimiter, requireAuth, requireAdmin, async (req, res) => {
  const rows = await pool.query(`
    select o.id, o.status, o.cart, o.total_int, o.created_at, u.username
    from orders o left join users_local u on u.id = o.user_id
    order by o.id desc limit 100
  `);
  res.json({ ok: true, orders: rows.rows });
});

// ================= AUTO-EXPIRE JOBS =================
setInterval(async () => {
  try {
    const r = await pool.query(`update expected_payments set status='expired' where status='pending' and expires_at <= now() returning id`);
    if (r.rowCount) console.log("Expired expected_payments:", r.rows.map((x) => x.id));
  } catch (e) {
    console.error("expire job error:", e?.message || e);
  }
}, 60_000);

setInterval(async () => {
  try {
    await pool.query(`delete from account_twofa_codes where expires_at <= now()`);
  } catch (e) {
    console.error("2FA cleanup error:", e?.message || e);
  }
}, 60_000);

// ================= START =================
console.log("PORT ENV =", process.env.PORT);
const PORT = Number(process.env.PORT || 8080);
const server = app.listen(PORT, "0.0.0.0", () => console.log("✅ listening on", PORT));

process.on("SIGTERM", () => { console.log("⚠️ SIGTERM received — shutting down"); server.close(() => process.exit(0)); });
process.on("unhandledRejection", (err) => console.error("UNHANDLED REJECTION:", err));
process.on("uncaughtException",  (err) => console.error("UNCAUGHT EXCEPTION:", err));

initDb()
  .then(() => console.log("✅ DB ready"))
  .catch((e) => console.error("❌ DB init error (server still running):", e?.message || e));
