// index.js
// ESM version — package.json should include: { "type": "module" }

import express from "express";
import { Pool } from "pg";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import crypto from "crypto";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import cookieParser from "cookie-parser";

const app = express();

// ===== REQUIRED ENV =====
if (!process.env.JWT_SECRET) throw new Error("JWT_SECRET is required");
if (!process.env.ADMIN_KEY) throw new Error("ADMIN_KEY is required");
if (!process.env.INVENTORY_API_KEY) throw new Error("INVENTORY_API_KEY is required");
if (!process.env.CREDENTIALS_ENCRYPTION_KEY) throw new Error("CREDENTIALS_ENCRYPTION_KEY is required");

const JWT_SECRET        = process.env.JWT_SECRET;
const ADMIN_KEY         = process.env.ADMIN_KEY;
const INVENTORY_API_KEY = process.env.INVENTORY_API_KEY;
const TWOFA_INGEST_KEY  = process.env.TWOFA_INGEST_KEY || "";
const NOWPAYMENTS_API_KEY   = process.env.NOWPAYMENTS_API_KEY || "";
const NOWPAYMENTS_IPN_SECRET = process.env.NOWPAYMENTS_IPN_SECRET || "";
const NOWPAYMENTS_API = "https://api.nowpayments.io/v1";
const TURNSTILE_SECRET = process.env.TURNSTILE_SECRET || "";
const RESEND_API_KEY   = process.env.RESEND_API_KEY   || "";

const DISCORD_PUBLIC_WEBHOOK = process.env.DISCORD_PUBLIC_WEBHOOK || "";
const DISCORD_ADMIN_WEBHOOK  = process.env.DISCORD_ADMIN_WEBHOOK  || "";

const FRONTEND_ORIGINS = (process.env.FRONTEND_ORIGINS || "")
  .split(",").map((s) => s.trim()).filter(Boolean);

const ENC_KEY = crypto.createHash("sha256").update(process.env.CREDENTIALS_ENCRYPTION_KEY).digest();

// ===== DATABASE =====
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes("railway") || process.env.DATABASE_SSL === "true"
    ? { rejectUnauthorized: false }
    : false,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});

// ===== ENCRYPTION =====
function encryptText(text) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv("aes-256-cbc", ENC_KEY, iv);
  const encrypted = Buffer.concat([cipher.update(String(text), "utf8"), cipher.final()]);
  return iv.toString("hex") + ":" + encrypted.toString("hex");
}

function decryptText(stored) {
  try {
    const [ivHex, encHex] = String(stored).split(":");
    const iv = Buffer.from(ivHex, "hex");
    const enc = Buffer.from(encHex, "hex");
    const decipher = crypto.createDecipheriv("aes-256-cbc", ENC_KEY, iv);
    return Buffer.concat([decipher.update(enc), decipher.final()]).toString("utf8");
  } catch {
    return stored;
  }
}

// ===== HELPERS =====
function makeCode(roblox_user) {
  return "ACC_" + String(roblox_user).toLowerCase().replace(/[^a-z0-9]/g, "").slice(0, 24) + "_" + Date.now().toString(36);
}

async function computePriceFromRate(age_pots) {
  try {
    const r = await pool.query(`select value from settings where key='rate_agepots_per_token'`);
    const rate = Number(r.rows[0]?.value || 70);
    return Math.max(1, Math.ceil(Number(age_pots) / rate));
  } catch {
    return Math.max(1, Math.ceil(Number(age_pots) / 70));
  }
}

function normalizeAccountUsername(raw) {
  if (!raw) return null;
  const s = String(raw).trim().toLowerCase();
  return s.length > 0 ? s : null;
}

function countFromSnapshot(snapshot) {
  const counts = {};
  if (!snapshot || typeof snapshot !== "object") return counts;

  // Your sender uses a "food" array with {name, quantity} objects
  const sources = [
    ...(Array.isArray(snapshot.food)  ? snapshot.food  : []),
    ...(Array.isArray(snapshot.items) ? snapshot.items : []),
  ];

  for (const item of sources) {
    const key = String(item.name || item.key || item.item_key || "").trim();
    const count = Number(item.quantity ?? item.count ?? item.qty ?? 0);
    if (key && count > 0) counts[key] = (counts[key] || 0) + count;
  }
  return counts;
}

function deltaCounts(prev, curr) {
  const delta = {};
  for (const [k, v] of Object.entries(curr)) {
    const d = v - (prev[k] || 0);
    if (d > 0) delta[k] = d;
  }
  return delta;
}

function satisfies(delta, expectedRaw) {
  try {
    const expected = typeof expectedRaw === "string" ? JSON.parse(expectedRaw) : expectedRaw;
    for (const [key, qty] of Object.entries(expected)) {
      if ((delta[key] || 0) < Number(qty)) return false;
    }
    return true;
  } catch {
    return false;
  }
}

async function notifyPublic(username, itemCount) {
  if (!DISCORD_PUBLIC_WEBHOOK) return;
  try {
    await fetch(DISCORD_PUBLIC_WEBHOOK, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ content: `🛒 **${username}** just purchased ${itemCount} account${itemCount !== 1 ? "s" : ""}!` }),
    });
  } catch (e) { console.error("notifyPublic error:", e?.message); }
}

async function notifyAdmin({ username, orderId, totalTokens, itemCount, cartItems }) {
  if (!DISCORD_ADMIN_WEBHOOK) return;
  try {
    const lines = (cartItems || []).map((i) =>
      `• \`${i.code}\` × ${i.qty}${i.credentials ? ` → **${i.credentials.user}**` : " (no cred)"}`
    );
    await fetch(DISCORD_ADMIN_WEBHOOK, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        embeds: [{
          title: `Order #${orderId} — ${username}`,
          color: 0x8b7cf6,
          fields: [
            { name: "Tokens", value: String(totalTokens), inline: true },
            { name: "Items",  value: String(itemCount),   inline: true },
            { name: "Cart",   value: lines.join("\n") || "—" },
          ],
          timestamp: new Date().toISOString(),
        }],
      }),
    });
  } catch (e) { console.error("notifyAdmin error:", e?.message); }
}

// ===== TURNSTILE VERIFICATION =====
async function verifyTurnstile(token, ip) {
  if (!TURNSTILE_SECRET) return true; // skip if not configured
  if (!token) return false;
  try {
    const resp = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ secret: TURNSTILE_SECRET, response: token, remoteip: ip }),
    });
    const data = await resp.json();
    return data.success === true;
  } catch { return false; }
}

// ===== EMAIL HELPER (Resend) =====
async function sendEmail({ to, subject, html }) {
  if (!RESEND_API_KEY) { console.warn("RESEND_API_KEY not set — skipping email"); return false; }
  try {
    const resp = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { "Authorization": `Bearer ${RESEND_API_KEY}`, "Content-Type": "application/json" },
      body: JSON.stringify({ from: "AdoptMeHub <noreply@adoptmehub.com>", to, subject, html }),
    });
    const data = await resp.json();
    if (!resp.ok) { console.error("Resend error:", data); return false; }
    return true;
  } catch (e) { console.error("sendEmail error:", e?.message); return false; }
}
const JWT_COOKIE = "amh_token";

const requireAuth = (req, res, next) => {
  // Read from httpOnly cookie first, fall back to Authorization header
  let token = req.cookies?.[JWT_COOKIE] || "";
  if (!token) {
    const header = req.headers.authorization || "";
    token = header.startsWith("Bearer ") ? header.slice(7) : "";
  }
  if (!token) return res.status(401).json({ ok: false, error: "auth required" });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ ok: false, error: "invalid or expired token" });
  }
};

const requireAdmin = (req, res, next) => {
  if (!req.user?.is_admin) return res.status(403).json({ ok: false, error: "admin only" });
  next();
};

const requireAdminKey = (req, res, next) => {
  const key = req.headers["x-admin-key"] || req.body?.admin_key || "";
  if (key !== ADMIN_KEY) return res.status(403).json({ ok: false, error: "invalid admin key" });
  next();
};

const requireInventoryKey = (req, res, next) => {
  const key = req.headers["x-inventory-key"] || req.query?.key || "";
  if (key !== INVENTORY_API_KEY) return res.status(403).json({ ok: false, error: "invalid inventory key" });
  next();
};

const requireTwofaKey = (req, res, next) => {
  const key = req.headers["x-twofa-key"] || "";
  if (!TWOFA_INGEST_KEY || key !== TWOFA_INGEST_KEY) return res.status(403).json({ ok: false, error: "invalid 2fa key" });
  next();
};

// ===== DB INIT =====
async function initDb() {
  await pool.query(`
    create table if not exists users_local (
      id bigserial primary key,
      username text unique not null,
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
    insert into settings(key,value) values('rate_agepots_per_token','70') on conflict(key) do nothing;
    create table if not exists products (
      id bigserial primary key,
      code text unique not null,
      title text not null default '',
      kind text not null default 'account',
      age_pots bigint not null default 0,
      bucks bigint not null default 0,
      price_int bigint not null default 0,
      stock_int int not null default 0,
      note text not null default '',
      image_url text not null default '',
      sold boolean not null default false,
      purchases_count int not null default 0,
      sold_at timestamptz,
      created_at timestamptz not null default now()
    );
    create table if not exists account_credentials (
      id bigserial primary key,
      product_code text not null,
      roblox_user text not null,
      roblox_pass text not null,
      note text not null default '',
      age_pots bigint not null default 0,
      bucks bigint not null default 0,
      assigned_order_id bigint,
      assigned_at timestamptz,
      created_at timestamptz not null default now()
    );
    create table if not exists orders (
      id bigserial primary key,
      user_id bigint not null,
      cart jsonb not null default '[]',
      total_int bigint not null default 0,
      status text not null default 'pending',
      created_at timestamptz not null default now()
    );
    create table if not exists order_items (
      id bigserial primary key,
      order_id bigint not null,
      product_code text not null,
      qty int not null default 1
    );
    create table if not exists token_ledger (
      id bigserial primary key,
      user_id bigint not null,
      delta bigint not null,
      reason text not null,
      meta jsonb not null default '{}',
      created_at timestamptz not null default now()
    );
    create table if not exists payment_slots (
      slot int primary key,
      title text not null default '',
      item_key text not null default '',
      points_per_unit numeric not null default 0,
      image_url text,
      enabled boolean not null default false
    );
    insert into payment_slots(slot) select generate_series(1,15) on conflict(slot) do nothing;
    create table if not exists expected_payments (
      id bigserial primary key,
      user_id bigint not null,
      type text not null default 'slot',
      expected jsonb not null default '{}',
      points_to_credit numeric not null default 0,
      receiver_account text not null,
      status text not null default 'pending',
      expires_at timestamptz not null,
      matched_at timestamptz,
      matched_snapshot_id bigint,
      created_at timestamptz not null default now()
    );
    create table if not exists inventory_snapshots (
      id bigserial primary key,
      receiver_account text not null,
      data jsonb not null default '{}',
      delta jsonb not null default '{}',
      received_at timestamptz not null default now()
    );
    create table if not exists account_twofa_codes (
      id bigserial primary key,
      account_username text not null,
      code text not null,
      source text not null default 'discord_bot',
      message_id text,
      channel_id text,
      expires_at timestamptz not null,
      used boolean not null default false,
      created_at timestamptz not null default now()
    );
    alter table users_local add column if not exists usd_balance numeric(12,4) not null default 0;
    alter table users_local add column if not exists email text;
    create unique index if not exists users_local_email_unique on users_local (lower(email)) where email is not null;
    create table if not exists password_resets (
      id bigserial primary key,
      user_id bigint not null,
      token text unique not null,
      expires_at timestamptz not null,
      used boolean not null default false,
      created_at timestamptz not null default now()
    );
    create table if not exists crypto_payments (
      id bigserial primary key,
      user_id bigint not null,
      nowpayments_id text unique not null,
      payment_status text not null default 'waiting',
      pay_currency text not null,
      pay_amount numeric(20,8),
      price_amount numeric(12,4) not null,
      pay_address text,
      actually_paid numeric(20,8) default 0,
      usd_credited numeric(12,4) default 0,
      created_at timestamptz not null default now(),
      updated_at timestamptz not null default now()
    );
    create table if not exists aging_orders (
      id bigserial primary key,
      discord_user_id text not null,
      discord_username text not null default '',
      age_pots int not null,
      price_tokens int not null,
      ticket_id text,
      status text not null default 'pending_payment',
      paid_by_user_id bigint,
      paid_at timestamptz,
      created_at timestamptz not null default now()
    );
    create table if not exists account_requests (
      id bigserial primary key,
      ager_discord_id text not null,
      ager_username text not null default '',
      ticket_id text,
      status text not null default 'pending',
      created_at timestamptz not null default now()
    );
    create table if not exists ager_assignments (
      id bigserial primary key,
      product_code text not null,
      cred_id bigint not null,
      ager_discord_id text not null,
      ticket_id text,
      roblox_user text not null,
      roblox_pass text not null,
      bucks bigint not null default 0,
      age_pots bigint not null default 0,
      status text not null default 'active',
      order_id bigint,
      completed_at timestamptz,
      created_at timestamptz not null default now()
    );
    alter table ager_assignments add column if not exists order_id bigint;
  `);
}

// ===== BASIC APP SETUP =====
app.set("trust proxy", 1);
app.get("/health", (req, res) => res.status(200).json({ ok: true }));
app.get("/", (req, res) => res.status(200).send("API running ✅"));
app.use(helmet());
app.use(cookieParser());
app.use(express.json({ limit: "1mb" }));

// ===== CSRF PROTECTION =====
const CSRF_COOKIE = "amh_csrf";
const CSRF_HEADER = "x-csrf-token";

function generateCsrfToken() {
  return crypto.randomBytes(32).toString("hex");
}

function setCsrfCookie(res) {
  const token = generateCsrfToken();
  res.cookie(CSRF_COOKIE, token, {
    httpOnly: false, // must be readable by JS so it can be sent in header
    sameSite: "strict",
    secure: process.env.NODE_ENV !== "development",
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });
  return token;
}

// Middleware to verify CSRF token on state-changing requests
const requireCsrf = (req, res, next) => {
  // Skip CSRF for GET, HEAD, OPTIONS and for inventory/bot endpoints that use API keys
  if (["GET","HEAD","OPTIONS"].includes(req.method)) return next();
  const skipPaths = ["/inventory", "/inventory.php", "/api/twofa/ingest", "/api/payments/crypto/webhook"];
  if (skipPaths.some(p => req.path.startsWith(p))) return next();
  const cookieToken = req.cookies?.[CSRF_COOKIE];
  const headerToken = req.headers?.[CSRF_HEADER];
  if (!cookieToken || !headerToken || cookieToken !== headerToken) {
    return res.status(403).json({ ok: false, error: "invalid csrf token" });
  }
  next();
};

app.use(requireCsrf);

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
    res.setHeader("Access-Control-Allow-Credentials", "true");
  }
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, x-inventory-key, x-admin-key, x-twofa-key, x-csrf-token");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

app.use((req, res, next) => { console.log("REQ", req.method, req.url); next(); });

// ===== RATE LIMITERS =====
const authLimiter      = rateLimit({ windowMs: 15 * 60 * 1000, max: 10,  standardHeaders: true, legacyHeaders: false });
const orderLimiter     = rateLimit({ windowMs: 10 * 60 * 1000, max: 20,  standardHeaders: true, legacyHeaders: false });
const inventoryLimiter = rateLimit({ windowMs:  1 * 60 * 1000, max: 120, standardHeaders: true, legacyHeaders: false });
const adminLimiter     = rateLimit({ windowMs: 10 * 60 * 1000, max: 100, standardHeaders: true, legacyHeaders: false });
const twofaLimiter     = rateLimit({ windowMs:  1 * 60 * 1000, max: 180, standardHeaders: true, legacyHeaders: false });

// ================= AUTH =================
app.post("/api/auth/register", authLimiter, async (req, res) => {
  const username = String(req.body?.username || "").trim().toLowerCase();
  const password = String(req.body?.password || "");
  const email    = String(req.body?.email || "").trim().toLowerCase() || null;
  const cfToken  = String(req.body?.cf_turnstile_response || "");

  if (username.length < 3) return res.status(400).json({ ok: false, error: "username too short" });
  if (password.length < 6) return res.status(400).json({ ok: false, error: "password too short (min 6)" });
  if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ ok: false, error: "invalid email" });

  // Verify Turnstile captcha
  const turnstileOk = await verifyTurnstile(cfToken, req.ip);
  if (!turnstileOk) return res.status(400).json({ ok: false, error: "Captcha failed — please try again." });

  const hash = await bcrypt.hash(password, 10);
  try {
    const ins = await pool.query(
      `insert into users_local (username, password_hash, email) values ($1,$2,$3) returning id,username,balance_int,is_admin,created_at`,
      [username, hash, email]
    );
    const user = ins.rows[0];
    const token = jwt.sign({ id: user.id, username: user.username, is_admin: user.is_admin }, JWT_SECRET, { expiresIn: "30d" });
    res.cookie(JWT_COOKIE, token, {
      httpOnly: true,
      sameSite: "strict",
      secure: process.env.NODE_ENV !== "development",
      maxAge: 30 * 24 * 60 * 60 * 1000,
    });
    const csrfToken = setCsrfCookie(res);
    res.json({ ok: true, user, csrf: csrfToken });
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
    JWT_SECRET, { expiresIn: "30d" }
  );
  res.cookie(JWT_COOKIE, token, {
    httpOnly: true,
    sameSite: "strict",
    secure: process.env.NODE_ENV !== "development",
    maxAge: 30 * 24 * 60 * 60 * 1000,
  });
  const csrfToken = setCsrfCookie(res);
  res.json({
    ok: true,
    csrf: csrfToken,
    user: { id: u.rows[0].id, username: u.rows[0].username, balance_int: u.rows[0].balance_int, is_admin: u.rows[0].is_admin, created_at: u.rows[0].created_at },
  });
});

app.get("/api/me", requireAuth, async (req, res) => {
  const u = await pool.query(
    `select id,username,balance_int,is_admin,is_blacklisted,created_at,email from users_local where id=$1`, [req.user.id]
  );
  if (!u.rows[0]) return res.status(404).json({ ok: false, error: "user not found" });
  if (u.rows[0].is_blacklisted) return res.status(403).json({ ok: false, error: "blacklisted" });
  res.json({ ok: true, me: { id: u.rows[0].id, username: u.rows[0].username, balance_int: u.rows[0].balance_int, is_admin: u.rows[0].is_admin, created_at: u.rows[0].created_at, email: u.rows[0].email || "" } });
});

app.post("/api/auth/logout", (req, res) => {
  res.clearCookie(JWT_COOKIE, { sameSite: "strict", secure: process.env.NODE_ENV !== "development" });
  res.clearCookie(CSRF_COOKIE, { sameSite: "strict", secure: process.env.NODE_ENV !== "development" });
  res.json({ ok: true });
});

// Issue a fresh CSRF token (called on page load)
app.get("/api/auth/csrf", (req, res) => {
  const token = setCsrfCookie(res);
  res.json({ ok: true, csrf: token });
});

// Update email for logged-in user
app.post("/api/me/email", requireAuth, async (req, res) => {
  const email = String(req.body?.email || "").trim().toLowerCase() || null;
  if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
    return res.status(400).json({ ok: false, error: "invalid email" });
  try {
    await pool.query(`update users_local set email=$1 where id=$2`, [email, req.user.id]);
    res.json({ ok: true });
  } catch {
    res.status(400).json({ ok: false, error: "email already in use by another account" });
  }
});
app.post("/api/auth/forgot-password", authLimiter, async (req, res) => {
  const email = String(req.body?.email || "").trim().toLowerCase();
  if (!email) return res.status(400).json({ ok: false, error: "email required" });

  // Always return ok to prevent email enumeration
  const u = await pool.query(`select id, username from users_local where lower(email)=$1`, [email]);
  if (!u.rows[0]) return res.json({ ok: true });

  const token = crypto.randomBytes(32).toString("hex");
  const expires = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

  await pool.query(
    `insert into password_resets (user_id, token, expires_at) values ($1,$2,$3)`,
    [u.rows[0].id, token, expires]
  );

  const resetUrl = `https://adoptmehub.com?reset=${token}`;
  await sendEmail({
    to: email,
    subject: "Reset your AdoptMeHub password",
    html: `
      <div style="font-family:sans-serif;max-width:480px;margin:0 auto;padding:32px">
        <h2 style="margin:0 0 16px">Reset your password</h2>
        <p>Hi <b>${u.rows[0].username}</b>, click the button below to reset your password. This link expires in 1 hour.</p>
        <a href="${resetUrl}" style="display:inline-block;margin:16px 0;padding:12px 24px;background:#8b7cf6;color:#fff;border-radius:8px;text-decoration:none;font-weight:700">Reset Password</a>
        <p style="color:#888;font-size:13px">If you didn't request this, ignore this email. Your password won't change.</p>
      </div>
    `,
  });

  res.json({ ok: true });
});

app.post("/api/auth/reset-password", authLimiter, async (req, res) => {
  const { token, password } = req.body;
  if (!token || !password) return res.status(400).json({ ok: false, error: "token and password required" });
  if (password.length < 6) return res.status(400).json({ ok: false, error: "password too short (min 6)" });

  const r = await pool.query(
    `select * from password_resets where token=$1 and used=false and expires_at > now()`, [token]
  );
  if (!r.rows[0]) return res.status(400).json({ ok: false, error: "Invalid or expired reset link." });

  const hash = await bcrypt.hash(password, 10);
  await pool.query(`update users_local set password_hash=$1 where id=$2`, [hash, r.rows[0].user_id]);
  await pool.query(`update password_resets set used=true where id=$1`, [r.rows[0].id]);

  res.json({ ok: true });
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
    select p.id, p.code, p.title, p.kind, p.age_pots, p.bucks,
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

// ===== OWNER VAULT =====
app.get("/api/admin/all-accounts", requireAuth, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(`select roblox_user from account_credentials where roblox_user is not null order by id asc`);
    const users = result.rows.map(r => ({ user: String(r.roblox_user || "").trim() })).filter(x => x.user.length > 0);
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
  const r = await pool.query(
    `insert into account_credentials (product_code,roblox_user,roblox_pass,note,age_pots,bucks)
     values ($1,$2,$3,$4,$5,$6) returning id,product_code,roblox_user,assigned_order_id,created_at`,
    [product_code, roblox_user, encryptText(roblox_pass), note, age_pots, bucks]
  );
  await pool.query(`update products set stock_int = stock_int + 1, sold = false where code=$1`, [product_code]);
  res.json({ ok: true, credential: r.rows[0] });
});

app.get("/api/admin/credentials/:code", adminLimiter, requireAuth, requireAdmin, async (req, res) => {
  const code = req.params.code;
  const r = await pool.query(
    `select id, product_code, roblox_user, roblox_pass, note, age_pots, bucks, assigned_order_id, created_at
     from account_credentials where product_code=$1 order by id asc`, [code]
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

// ================= ADMIN: IMPORT PASSWORDS =================
app.post("/api/admin/credentials/import-passwords", adminLimiter, requireAuth, requireAdmin, async (req, res) => {
  const raw = String(req.body?.text || req.body?.csv || "").trim();
  if (!raw) return res.status(400).json({ ok: false, error: "text required" });
  const lines = raw.split("\n").map((l) => l.trim()).filter(Boolean);
  let updated_available = 0, updated_sold = 0, skipped = 0;
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    for (const line of lines) {
      const colonIdx = line.indexOf(":");
      if (colonIdx < 1) { skipped++; continue; }
      const roblox_user = line.slice(0, colonIdx).trim();
      const new_pass    = line.slice(colonIdx + 1).trim();
      if (!roblox_user || !new_pass) { skipped++; continue; }
      const credResult = await client.query(
        `select id, assigned_order_id from account_credentials where lower(roblox_user) = lower($1) order by id desc limit 1`,
        [roblox_user]
      );
      if (!credResult.rows[0]) { skipped++; continue; }
      const { id: credId, assigned_order_id } = credResult.rows[0];
      await client.query(`update account_credentials set roblox_pass = $1 where id = $2`, [encryptText(new_pass), credId]);
      if (assigned_order_id && assigned_order_id > 0) {
        const orderResult = await client.query(`select id, cart from orders where id = $1`, [assigned_order_id]);
        for (const orderRow of orderResult.rows) {
          const cart = Array.isArray(orderRow.cart) ? orderRow.cart : [];
          let patched = false;
          const newCart = cart.map((item) => {
            if (item?.credentials?.user && item.credentials.user.toLowerCase() === roblox_user.toLowerCase()) {
              patched = true;
              return { ...item, credentials: { ...item.credentials, pass: new_pass } };
            }
            return item;
          });
          if (patched) await client.query(`update orders set cart = $1 where id = $2`, [JSON.stringify(newCart), orderRow.id]);
        }
        updated_sold++;
      } else {
        updated_available++;
      }
    }
    await client.query("COMMIT");
  } catch (e) {
    await client.query("ROLLBACK");
    console.error("import-passwords error:", e?.message || e);
    return res.status(500).json({ ok: false, error: "import failed" });
  } finally { client.release(); }
  console.log(`Admin ${req.user.username} import-passwords: +${updated_available} avail, +${updated_sold} sold, ${skipped} skipped`);
  res.json({ ok: true, updated_available, updated_sold, skipped, total: lines.length });
});

// ================= ORDERS =================
app.post("/api/orders/create", orderLimiter, requireAuth, async (req, res) => {
  const cart = Array.isArray(req.body?.cart) ? req.body.cart : [];
  if (!cart.length) return res.status(400).json({ ok: false, error: "empty cart" });
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const codes = [...new Set(cart.map((i) => String(i.code || "")))];
    const prods = await client.query(`select code, price_int, stock_int, sold from products where code = any($1::text[]) for update`, [codes]);
    const map = new Map(prods.rows.map((p) => [p.code, p]));
    let total = 0;
    for (const item of cart) {
      const code = String(item.code || ""); const qty = Math.max(1, Number(item.qty || 1)); const p = map.get(code);
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
      const code = String(item.code || ""); const qty = Math.max(1, Number(item.qty || 1));
      await client.query(`update products set stock_int = GREATEST(0, stock_int - $1), purchases_count = purchases_count + $1 where code = $2`, [qty, code]);
      await client.query(`update products set sold = (stock_int <= 0), sold_at = case when stock_int <= 0 then now() else sold_at end where code = $1`, [code]);
      const cred = await client.query(
        `select id, roblox_user, roblox_pass, note, age_pots, bucks from account_credentials
         where product_code = $1 and assigned_order_id is null order by id asc limit 1 for update skip locked`, [code]
      );
      let credentials = null, credId = null;
      if (cred.rows[0]) {
        credId = cred.rows[0].id;
        credentials = { user: cred.rows[0].roblox_user, pass: decryptText(cred.rows[0].roblox_pass), note: cred.rows[0].note, age_pots: cred.rows[0].age_pots, bucks: cred.rows[0].bucks };
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
    res.json({ ok: true, order: { ...created.rows[0], cart: enrichedCart.map((i) => ({ code: i.code, qty: i.qty, credentials: i.credentials })) } });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("orders/create error:", err?.message || err);
    res.status(500).json({ ok: false, error: "order failed" });
  } finally { client.release(); }
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
    const key = String(k || "").trim(); const qty = Math.floor(Number(v || 0));
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
  console.log("INVENTORY BODY:", JSON.stringify(req.body));
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
  if (!username || !code) return res.status(400).json({ ok: false, error: "missing username/code" });
  const expiresAt = new Date(Date.now() + expiresInSeconds * 1000);
  const inserted = await pool.query(
    `insert into account_twofa_codes (account_username, code, source, message_id, channel_id, expires_at)
     values ($1, $2, $3, $4, $5, $6) returning id, account_username, code, created_at, expires_at`,
    [username, code, source, message_id, channel_id, expiresAt]
  );
  res.json({ ok: true, entry: inserted.rows[0] });
});

async function getOwnedAccountUsernames(userId) {
  const orders = await pool.query(`select cart from orders where user_id=$1 and status='completed' order by id desc`, [userId]);
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
  if (!usernames.length) return res.json({ ok: true, codes: [] });
  const r = await pool.query(
    `select distinct on (account_username) account_username, code, created_at, expires_at, source
     from account_twofa_codes
     where account_username = any($1::text[]) and expires_at > now() and used = false
     order by account_username, id desc`,
    [usernames]
  );
  res.json({ ok: true, codes: r.rows });
}

app.get("/api/my-2fa-codes",    requireAuth, sendMyTwofaCodes);
app.get("/api/my-accounts/2fa", requireAuth, sendMyTwofaCodes);
app.get("/api/twofa/my",        requireAuth, sendMyTwofaCodes);

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

// ================= CRYPTO PAYMENTS =================

// Get user's USD balance
app.get("/api/usd/balance", requireAuth, async (req, res) => {
  const r = await pool.query(`select usd_balance from users_local where id=$1`, [req.user.id]);
  res.json({ ok: true, usd_balance: Number(r.rows[0]?.usd_balance || 0) });
});

// Create a NOWPayments invoice
app.post("/api/payments/crypto/create", requireAuth, async (req, res) => {
  const currency = String(req.body?.currency || "").toLowerCase();
  const amount   = Number(req.body?.amount || 0);

  if (!["btc", "ltc"].includes(currency))
    return res.status(400).json({ ok: false, error: "currency must be btc or ltc" });
  if (amount < 5)
    return res.status(400).json({ ok: false, error: "minimum deposit is $5.00" });
  if (!NOWPAYMENTS_API_KEY)
    return res.status(500).json({ ok: false, error: "crypto payments not configured" });

  try {
    const resp = await fetch(`${NOWPAYMENTS_API}/payment`, {
      method: "POST",
      headers: {
        "x-api-key": NOWPAYMENTS_API_KEY,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        price_amount: amount,
        price_currency: "usd",
        pay_currency: currency,
        order_id: `user_${req.user.id}_${Date.now()}`,
        order_description: `AdoptMeHub USD balance top-up for ${req.user.username}`,
        ipn_callback_url: "https://api.adoptmehub.com/api/payments/crypto/webhook",
      }),
    });

    const data = await resp.json();
    if (!resp.ok || !data.payment_id)
      return res.status(500).json({ ok: false, error: data.message || "NOWPayments error" });

    // Store in DB
    await pool.query(
      `insert into crypto_payments (user_id, nowpayments_id, payment_status, pay_currency, price_amount, pay_amount, pay_address)
       values ($1,$2,$3,$4,$5,$6,$7)`,
      [req.user.id, String(data.payment_id), data.payment_status, currency,
       amount, data.pay_amount, data.pay_address]
    );

    res.json({
      ok: true,
      payment_id: data.payment_id,
      pay_address: data.pay_address,
      pay_amount: data.pay_amount,
      pay_currency: currency.toUpperCase(),
      price_amount: amount,
      status: data.payment_status,
    });
  } catch (e) {
    console.error("crypto/create error:", e?.message);
    res.status(500).json({ ok: false, error: "failed to create payment" });
  }
});

// Poll payment status
app.get("/api/payments/crypto/status/:paymentId", requireAuth, async (req, res) => {
  const r = await pool.query(
    `select * from crypto_payments where nowpayments_id=$1 and user_id=$2`,
    [req.params.paymentId, req.user.id]
  );
  if (!r.rows[0]) return res.status(404).json({ ok: false, error: "not found" });
  res.json({ ok: true, payment: r.rows[0] });
});

// NOWPayments IPN webhook
app.post("/api/payments/crypto/webhook", express.json(), async (req, res) => {
  // Verify IPN signature
  if (NOWPAYMENTS_IPN_SECRET) {
    const sig = req.headers["x-nowpayments-sig"] || "";
    const sorted = JSON.stringify(sortObject(req.body));
    const expected = crypto.createHmac("sha512", NOWPAYMENTS_IPN_SECRET).update(sorted).digest("hex");
    if (sig !== expected) {
      console.error("IPN signature mismatch");
      return res.status(400).json({ ok: false, error: "invalid signature" });
    }
  }

  const { payment_id, payment_status, actually_paid, price_amount } = req.body;
  if (!payment_id) return res.status(400).json({ ok: false, error: "missing payment_id" });

  const confirmed = ["finished", "confirmed", "complete", "partially_paid"].includes(payment_status);

  await pool.query(
    `update crypto_payments set payment_status=$1, actually_paid=$2, updated_at=now() where nowpayments_id=$3`,
    [payment_status, actually_paid || 0, String(payment_id)]
  );

  if (confirmed) {
    // Only credit once — check usd_credited is 0
    const r = await pool.query(
      `select * from crypto_payments where nowpayments_id=$1 and usd_credited=0`,
      [String(payment_id)]
    );
    if (r.rows[0]) {
      const usdToCredit = Number(price_amount || r.rows[0].price_amount);
      await pool.query(`update users_local set usd_balance = usd_balance + $1 where id=$2`, [usdToCredit, r.rows[0].user_id]);
      await pool.query(`update crypto_payments set usd_credited=$1 where nowpayments_id=$2`, [usdToCredit, String(payment_id)]);
      console.log(`Credited $${usdToCredit} USD to user ${r.rows[0].user_id} via crypto payment ${payment_id}`);
    }
  }

  res.json({ ok: true });
});

// USD order create (same credential assignment, deducts USD balance)
app.post("/api/orders/create-usd", orderLimiter, requireAuth, async (req, res) => {
  const cart = Array.isArray(req.body?.cart) ? req.body.cart : [];
  if (!cart.length) return res.status(400).json({ ok: false, error: "empty cart" });

  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    const codes = [...new Set(cart.map((i) => String(i.code || "")))];
    const prods = await client.query(
      `select code, age_pots, stock_int, sold from products where code = any($1::text[]) for update`, [codes]
    );
    const map = new Map(prods.rows.map((p) => [p.code, p]));

    // Calculate USD total: age_pots * $0.005
    let totalUsd = 0;
    for (const item of cart) {
      const code = String(item.code || "");
      const qty  = Math.max(1, Number(item.qty || 1));
      const p    = map.get(code);
      if (!p) { await client.query("ROLLBACK"); return res.status(400).json({ ok: false, error: `unknown product: ${code}` }); }
      if (p.sold || Number(p.stock_int) < qty) { await client.query("ROLLBACK"); return res.status(400).json({ ok: false, error: `out of stock: ${code}` }); }
      totalUsd += Number(p.age_pots) * 0.005 * qty;
    }
    totalUsd = Math.round(totalUsd * 10000) / 10000;

    const userRow = await client.query(`select id, usd_balance from users_local where id=$1 for update`, [req.user.id]);
    const user = userRow.rows[0];
    if (!user) { await client.query("ROLLBACK"); return res.status(404).json({ ok: false, error: "user not found" }); }
    if (Number(user.usd_balance) < totalUsd) {
      await client.query("ROLLBACK");
      return res.status(400).json({ ok: false, error: `Not enough USD balance. Need $${totalUsd.toFixed(4)}, you have $${Number(user.usd_balance).toFixed(4)}.` });
    }

    await client.query(`update users_local set usd_balance = usd_balance - $1 where id=$2`, [totalUsd, req.user.id]);

    const enrichedCart = [];
    for (const item of cart) {
      const code = String(item.code || "");
      const qty  = Math.max(1, Number(item.qty || 1));
      await client.query(`update products set stock_int = GREATEST(0, stock_int - $1), purchases_count = purchases_count + $1 where code = $2`, [qty, code]);
      await client.query(`update products set sold = (stock_int <= 0), sold_at = case when stock_int <= 0 then now() else sold_at end where code = $1`, [code]);
      const cred = await client.query(
        `select id, roblox_user, roblox_pass, note, age_pots, bucks from account_credentials
         where product_code = $1 and assigned_order_id is null order by id asc limit 1 for update skip locked`, [code]
      );
      let credentials = null, credId = null;
      if (cred.rows[0]) {
        credId = cred.rows[0].id;
        credentials = { user: cred.rows[0].roblox_user, pass: decryptText(cred.rows[0].roblox_pass), note: cred.rows[0].note, age_pots: cred.rows[0].age_pots, bucks: cred.rows[0].bucks };
        await client.query(`update account_credentials set assigned_order_id=-1 where id=$1`, [credId]);
      }
      enrichedCart.push({ code, qty, credentials, _credId: credId });
    }

    const created = await client.query(
      `insert into orders (user_id, cart, total_int, status) values ($1::bigint,$2,$3,'completed') returning id, status, total_int, created_at`,
      [req.user.id, JSON.stringify(enrichedCart.map((i) => ({ code: i.code, qty: i.qty, credentials: i.credentials }))), Math.round(totalUsd * 100)]
    );
    const orderId = created.rows[0].id;

    for (const item of enrichedCart) {
      if (item._credId) await client.query(`update account_credentials set assigned_order_id=$1, assigned_at=now() where id=$2`, [orderId, item._credId]);
      await client.query(`insert into order_items(order_id,product_code,qty) values($1,$2,$3)`, [orderId, item.code, item.qty]);
    }

    await client.query("COMMIT");

    const totalItems = enrichedCart.reduce((s, i) => s + i.qty, 0);
    notifyPublic(req.user.username, totalItems).catch(console.error);
    notifyAdmin({ username: req.user.username, orderId, totalTokens: `$${totalUsd.toFixed(2)} USD`, itemCount: totalItems, cartItems: enrichedCart }).catch(console.error);

    res.json({ ok: true, order: { ...created.rows[0], usd_total: totalUsd, cart: enrichedCart.map((i) => ({ code: i.code, qty: i.qty, credentials: i.credentials })) } });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("orders/create-usd error:", err?.message || err);
    res.status(500).json({ ok: false, error: "order failed" });
  } finally { client.release(); }
});

// Helper to sort object keys for IPN signature
function sortObject(obj) {
  if (typeof obj !== "object" || obj === null) return obj;
  if (Array.isArray(obj)) return obj.map(sortObject);
  return Object.keys(obj).sort().reduce((acc, k) => { acc[k] = sortObject(obj[k]); return acc; }, {});
}

// ================= AGING SERVICE =================

// Bot creates an aging order and gets back a pending payment ID
app.post("/api/aging/create", async (req, res) => {
  const bot_secret = req.headers["x-bot-secret"] || "";
  if (bot_secret !== (process.env.BOT_SECRET || "")) return res.status(403).json({ ok: false, error: "forbidden" });

  const { discord_user_id, discord_username, age_pots, ticket_id } = req.body;
  if (!discord_user_id || !age_pots || age_pots < 1)
    return res.status(400).json({ ok: false, error: "discord_user_id and age_pots required" });

  const price_tokens = Math.ceil(Number(age_pots) / 70);

  // Find user by discord_user_id if linked, else store pending
  const r = await pool.query(
    `insert into aging_orders (discord_user_id, discord_username, age_pots, price_tokens, ticket_id, status)
     values ($1,$2,$3,$4,$5,'pending_payment') returning id`,
    [String(discord_user_id), discord_username || "", Number(age_pots), price_tokens, ticket_id || null]
  );

  res.json({ ok: true, aging_order_id: r.rows[0].id, price_tokens, age_pots: Number(age_pots) });
});

// Customer links their site account to their aging order
app.post("/api/aging/link", requireAuth, async (req, res) => {
  const { aging_order_id } = req.body;
  if (!aging_order_id) return res.status(400).json({ ok: false, error: "aging_order_id required" });

  const order = await pool.query(`select * from aging_orders where id=$1`, [aging_order_id]);
  if (!order.rows[0]) return res.status(404).json({ ok: false, error: "aging order not found" });
  if (order.rows[0].status !== "pending_payment")
    return res.status(400).json({ ok: false, error: "order already paid or completed" });

  const userRow = await pool.query(`select balance_int from users_local where id=$1`, [req.user.id]);
  res.json({ ok: true, order: order.rows[0], user_balance: userRow.rows[0]?.balance_int ?? 0 });
});

// Customer pays for aging order from their token balance
app.post("/api/aging/pay", requireAuth, async (req, res) => {
  const { aging_order_id } = req.body;
  if (!aging_order_id) return res.status(400).json({ ok: false, error: "aging_order_id required" });

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const order = await client.query(`select * from aging_orders where id=$1 for update`, [aging_order_id]);
    if (!order.rows[0]) { await client.query("ROLLBACK"); return res.status(404).json({ ok: false, error: "not found" }); }
    if (order.rows[0].status !== "pending_payment") {
      await client.query("ROLLBACK");
      return res.status(400).json({ ok: false, error: "already paid" });
    }

    const price = Number(order.rows[0].price_tokens);
    const userRow = await client.query(`select id, balance_int from users_local where id=$1 for update`, [req.user.id]);
    if (!userRow.rows[0] || Number(userRow.rows[0].balance_int) < price) {
      await client.query("ROLLBACK");
      return res.status(400).json({ ok: false, error: `Not enough tokens. Need ${price}, you have ${userRow.rows[0]?.balance_int || 0}.` });
    }

    await client.query(`update users_local set balance_int = balance_int - $1 where id=$2`, [price, req.user.id]);
    await client.query(`update aging_orders set status='paid', paid_by_user_id=$1, paid_at=now() where id=$2`, [req.user.id, aging_order_id]);
    await client.query(`insert into token_ledger (user_id, delta, reason, meta) values ($1,$2,'aging_service',$3::jsonb)`,
      [req.user.id, -price, JSON.stringify({ aging_order_id, age_pots: order.rows[0].age_pots })]);
    await client.query("COMMIT");

    res.json({ ok: true, paid: true, tokens_spent: price, age_pots: order.rows[0].age_pots });
  } catch (e) {
    await client.query("ROLLBACK");
    console.error("aging/pay error:", e?.message);
    res.status(500).json({ ok: false, error: "payment failed" });
  } finally { client.release(); }
});

// Bot polls this to check if customer paid
app.get("/api/aging/status/:id", async (req, res) => {
  const bot_secret = req.headers["x-bot-secret"] || "";
  if (bot_secret !== (process.env.BOT_SECRET || "")) return res.status(403).json({ ok: false, error: "forbidden" });
  const r = await pool.query(`select * from aging_orders where id=$1`, [req.params.id]);
  if (!r.rows[0]) return res.status(404).json({ ok: false, error: "not found" });
  res.json({ ok: true, order: r.rows[0] });
});

// Bot: ager requests an account — just logs it, owner handles on website
app.post("/api/aging/request-account", async (req, res) => {
  const bot_secret = req.headers["x-bot-secret"] || "";
  if (bot_secret !== (process.env.BOT_SECRET || "")) return res.status(403).json({ ok: false, error: "forbidden" });
  const { ager_discord_id, ager_username, ticket_id } = req.body;
  await pool.query(
    `insert into account_requests (ager_discord_id, ager_username, ticket_id, status) values ($1,$2,$3,'pending')`,
    [String(ager_discord_id), ager_username || "", ticket_id || null]
  );
  res.json({ ok: true });
});

// Admin: assign account to ager for a ticket
app.post("/api/admin/aging/assign-account", adminLimiter, requireAuth, requireAdmin, async (req, res) => {
  const { product_code, ager_discord_id, ticket_id, ager_site_username } = req.body;
  if (!product_code || !ager_discord_id) return res.status(400).json({ ok: false, error: "product_code and ager_discord_id required" });

  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    // Pull the credential
    const cred = await client.query(
      `select id, roblox_user, roblox_pass, note, age_pots, bucks from account_credentials
       where product_code=$1 and assigned_order_id is null order by id asc limit 1 for update skip locked`, [product_code]
    );
    if (!cred.rows[0]) { await client.query("ROLLBACK"); return res.status(400).json({ ok: false, error: "no available credential for that product" }); }

    // Find ager's site user ID if username provided
    let agerUserId = null;
    if (ager_site_username) {
      const u = await client.query(`select id from users_local where lower(username)=lower($1)`, [ager_site_username]);
      if (u.rows[0]) agerUserId = u.rows[0].id;
    }

    // Mark product as unavailable
    await client.query(`update products set stock_int=0, sold=true where code=$1`, [product_code]);

    let orderId = null;
    if (agerUserId) {
      // Create a real order tagged as ager assignment so it shows in My Accounts
      const cartJson = JSON.stringify([{
        code: product_code,
        qty: 1,
        credentials: {
          user: cred.rows[0].roblox_user,
          pass: decryptText(cred.rows[0].roblox_pass),
          note: cred.rows[0].note,
          age_pots: cred.rows[0].age_pots,
          bucks: cred.rows[0].bucks,
        },
        is_ager_assignment: true,
      }]);
      const created = await client.query(
        `insert into orders (user_id, cart, total_int, status) values ($1,$2,0,'completed') returning id`,
        [agerUserId, cartJson]
      );
      orderId = created.rows[0].id;
      await client.query(`update account_credentials set assigned_order_id=$1, assigned_at=now() where id=$2`, [orderId, cred.rows[0].id]);
    } else {
      // No site account — use sentinel
      await client.query(`update account_credentials set assigned_order_id=-999, assigned_at=now() where id=$1`, [cred.rows[0].id]);
    }

    // Store in ager_assignments
    await client.query(
      `insert into ager_assignments (product_code, cred_id, ager_discord_id, ticket_id, roblox_user, roblox_pass, bucks, age_pots, status, order_id)
       values ($1,$2,$3,$4,$5,$6,$7,$8,'active',$9)`,
      [product_code, cred.rows[0].id, String(ager_discord_id), ticket_id || null,
       cred.rows[0].roblox_user, encryptText(decryptText(cred.rows[0].roblox_pass)),
       cred.rows[0].bucks, cred.rows[0].age_pots, orderId]
    );

    await client.query("COMMIT");
    res.json({ ok: true, roblox_user: cred.rows[0].roblox_user, bucks: cred.rows[0].bucks, order_id: orderId });
  } catch (e) {
    await client.query("ROLLBACK");
    console.error("assign-account error:", e?.message);
    res.status(500).json({ ok: false, error: "assign failed" });
  } finally { client.release(); }
});

// Ager marks account as emptied (aged) from My Accounts tab
app.post("/api/aging/mark-emptied", requireAuth, async (req, res) => {
  const { order_id, product_code } = req.body;
  if (!order_id) return res.status(400).json({ ok: false, error: "order_id required" });

  // Verify this order belongs to the requesting user and is an ager assignment
  const orderCheck = await pool.query(
    `select id, cart from orders where id=$1 and user_id=$2`, [order_id, req.user.id]
  );
  if (!orderCheck.rows[0]) return res.status(404).json({ ok: false, error: "order not found" });

  const cart = Array.isArray(orderCheck.rows[0].cart) ? orderCheck.rows[0].cart : [];
  const isAgerAssignment = cart.some(i => i.is_ager_assignment === true);
  if (!isAgerAssignment) return res.status(403).json({ ok: false, error: "not an ager assignment" });

  // Find the assignment
  const assignment = await pool.query(
    `select * from ager_assignments where order_id=$1 and status='active' limit 1`, [order_id]
  );
  if (!assignment.rows[0]) return res.status(404).json({ ok: false, error: "assignment not found or already completed" });

  await pool.query(`update ager_assignments set status='completed', completed_at=now() where id=$1`, [assignment.rows[0].id]);

  // Return info for owner notification (bot/discord notif handled client-side or via separate webhook)
  res.json({
    ok: true,
    roblox_user: assignment.rows[0].roblox_user,
    bucks: assignment.rows[0].bucks,
    product_code: assignment.rows[0].product_code,
    ticket_id: assignment.rows[0].ticket_id,
  });
});

// Bot: ager completes aging — returns account info for owner review
app.post("/api/aging/complete", async (req, res) => {
  const bot_secret = req.headers["x-bot-secret"] || "";
  if (bot_secret !== (process.env.BOT_SECRET || "")) return res.status(403).json({ ok: false, error: "forbidden" });

  const { roblox_username, ager_discord_id } = req.body;
  if (!roblox_username) return res.status(400).json({ ok: false, error: "roblox_username required" });

  const r = await pool.query(
    `select * from ager_assignments where lower(roblox_user)=lower($1) and status='active' order by id desc limit 1`,
    [roblox_username]
  );
  if (!r.rows[0]) return res.status(404).json({ ok: false, error: "no active assignment found for that username" });

  const assignment = r.rows[0];
  await pool.query(`update ager_assignments set status='completed', completed_at=now() where id=$1`, [assignment.id]);

  res.json({
    ok: true,
    roblox_user: assignment.roblox_user,
    bucks: assignment.bucks,
    age_pots_before: assignment.age_pots,
    product_code: assignment.product_code,
    ticket_id: assignment.ticket_id,
  });
});

// Admin: get pending account requests
app.get("/api/admin/aging/requests", adminLimiter, requireAuth, requireAdmin, async (req, res) => {
  const r = await pool.query(`select * from account_requests where status='pending' order by id desc`);
  res.json({ ok: true, requests: r.rows });
});

// Admin: get completed aging assignments (for relisting)
app.get("/api/admin/aging/completed", adminLimiter, requireAuth, requireAdmin, async (req, res) => {
  const r = await pool.query(`select * from ager_assignments where status='completed' order by completed_at desc limit 50`);
  res.json({ ok: true, assignments: r.rows });
});

// ================= AUTO-EXPIRE JOBS =================
setInterval(async () => {
  try {
    const r = await pool.query(`update expected_payments set status='expired' where status='pending' and expires_at <= now() returning id`);
    if (r.rowCount) console.log("Expired expected_payments:", r.rows.map((x) => x.id));
  } catch (e) { console.error("expire job error:", e?.message || e); }
}, 60_000);

setInterval(async () => {
  try {
    await pool.query(`delete from account_twofa_codes where expires_at <= now()`);
  } catch (e) { console.error("2FA cleanup error:", e?.message || e); }
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
