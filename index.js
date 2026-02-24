import express from "express";
import crypto from "crypto";
import pg from "pg";

const app = express();
app.use(express.json({ limit: "5mb" }));

const { Pool } = pg;
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes("railway") ? { rejectUnauthorized: false } : undefined,
});

const INVENTORY_API_KEY = process.env.INVENTORY_API_KEY;
if (!INVENTORY_API_KEY) console.warn("⚠️ Set INVENTORY_API_KEY in Railway Variables.");

async function initDb() {
  await pool.query(`
    create table if not exists users (
      id bigserial primary key,
      username text not null,
      token text not null unique,
      balance_int bigint not null default 0,
      created_at timestamptz not null default now()
    );

    create table if not exists products (
      id bigserial primary key,
      code text not null unique,
      title text not null,
      price_int bigint not null,
      stock_int bigint not null default 0,
      image_url text,
      meta jsonb not null default '{}'::jsonb
    );

    create table if not exists orders (
      id bigserial primary key,
      user_id bigint references users(id),
      status text not null default 'pending', -- pending, paid, fulfilled, canceled
      cart jsonb not null default '[]'::jsonb,
      total_int bigint not null default 0,
      created_at timestamptz not null default now()
    );

    create table if not exists expected_payments (
      id bigserial primary key,
      user_id bigint references users(id),
      order_id bigint references orders(id),
      pay_type text not null,            -- ride_potion, pets, etc
      expected jsonb not null,           -- {"ride_potion":2}
      receiver_account text not null,    -- which farm account inventory we're watching
      status text not null default 'pending', -- pending, matched, expired
      created_at timestamptz not null default now()
    );

    create table if not exists inventory_snapshots (
      id bigserial primary key,
      receiver_account text not null,
      received_at timestamptz not null default now(),
      data jsonb not null
    );
  `);

  // Seed example products if empty
  const { rows } = await pool.query(`select count(*)::int as c from products;`);
  if (rows[0].c === 0) {
    await pool.query(
      `insert into products (code,title,price_int,stock_int,image_url,meta)
       values
       ('ACC_A','Account A (Anonymous)', 200, 3, null, '{"type":"account"}'),
       ('ACC_B','Account B (Anonymous)', 350, 2, null, '{"type":"account"}'),
       ('CREDITS_100','100 Credits', 100, 9999, null, '{"type":"credits"}')
      `
    );
  }
}

function requireUser(req, res, next) {
  const token = req.header("x-user-token");
  if (!token) return res.status(401).json({ ok: false, error: "Missing x-user-token" });
  req.userToken = token;
  next();
}

function requireInventoryKey(req, res, next) {
  const key = req.header("x-inventory-key");
  if (!INVENTORY_API_KEY) return res.status(500).json({ ok: false, error: "Server missing INVENTORY_API_KEY" });
  if (key !== INVENTORY_API_KEY) return res.status(401).json({ ok: false, error: "Bad inventory key" });
  next();
}

// Utility: count items in snapshot for delta check
function countFromSnapshot(snapshot) {
  // Snapshot is whatever you send. We'll support:
  // { user, pets:[{name}], food:[{name,quantity}], timestamp }
  // We'll compute counts by name for pets and food.
  const counts = {};
  const pets = Array.isArray(snapshot?.pets) ? snapshot.pets : [];
  for (const p of pets) {
    const name = p?.name || "unknown_pet";
    counts[name] = (counts[name] || 0) + 1;
  }
  const food = Array.isArray(snapshot?.food) ? snapshot.food : [];
  for (const f of food) {
    const name = f?.name || "unknown_food";
    const qty = Number(f?.quantity || 1);
    counts[name] = (counts[name] || 0) + qty;
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
  // expected: {"ride_potion":2} etc
  for (const [k, need] of Object.entries(expected || {})) {
    if ((delta[k] || 0) < Number(need)) return false;
  }
  return true;
}

// ------------------- PUBLIC PAGES -------------------
app.get("/", async (req, res) => {
  res.send(`
  <h1>AdoptMeHub API is running</h1>
  <p>Try <a href="/shop">/shop</a></p>
  `);
});

app.get("/shop", async (req, res) => {
  const { rows } = await pool.query(`select id,code,title,price_int,stock_int,image_url from products order by id asc;`);
  const cards = rows.map(p => `
    <div style="border:1px solid #333;padding:12px;border-radius:10px;margin:10px;max-width:420px">
      <div style="font-weight:700">${p.title}</div>
      <div style="opacity:.8">Code: ${p.code}</div>
      <div>Price: <b>${p.price_int}</b> credits</div>
      <div>Stock: <b>${p.stock_int}</b></div>
    </div>
  `).join("");

  res.send(`
  <html><body style="background:#111;color:#fff;font-family:Arial;padding:24px">
    <h1>Shop (v1)</h1>
    <p>This is a basic preview. The real UI comes next.</p>
    ${cards}
    <hr style="opacity:.2"/>
    <p><b>API:</b> GET /api/products</p>
  </body></html>
  `);
});

// ------------------- AUTH (simple token) -------------------
app.post("/api/register", async (req, res) => {
  const username = String(req.body?.username || "").trim();
  if (!username) return res.status(400).json({ ok: false, error: "username required" });

  const token = crypto.randomBytes(24).toString("hex");
  const { rows } = await pool.query(
    `insert into users (username, token) values ($1,$2) returning id, username, token, balance_int;`,
    [username, token]
  );
  res.json({ ok: true, user: rows[0] });
});

app.get("/api/me", requireUser, async (req, res) => {
  const { rows } = await pool.query(`select id,username,balance_int from users where token=$1`, [req.userToken]);
  if (!rows[0]) return res.status(401).json({ ok: false, error: "bad token" });
  res.json({ ok: true, me: rows[0] });
});

// ------------------- SHOP API -------------------
app.get("/api/products", async (req, res) => {
  const { rows } = await pool.query(`select id,code,title,price_int,stock_int,image_url,meta from products order by id asc;`);
  res.json({ ok: true, products: rows });
});

app.post("/api/orders/create", requireUser, async (req, res) => {
  const cart = Array.isArray(req.body?.cart) ? req.body.cart : [];
  if (cart.length === 0) return res.status(400).json({ ok: false, error: "cart is empty" });

  // cart items: [{code:"ACC_A", qty:1}]
  const codes = cart.map(i => String(i.code || ""));
  const { rows: prods } = await pool.query(
    `select code, price_int, stock_int from products where code = any($1::text[])`,
    [codes]
  );

  const map = new Map(prods.map(p => [p.code, p]));
  let total = 0;
  for (const item of cart) {
    const code = String(item.code || "");
    const qty = Math.max(1, Number(item.qty || 1));
    const p = map.get(code);
    if (!p) return res.status(400).json({ ok: false, error: `unknown product ${code}` });
    if (p.stock_int < qty) return res.status(400).json({ ok: false, error: `out of stock: ${code}` });
    total += p.price_int * qty;
  }

  const u = await pool.query(`select id from users where token=$1`, [req.userToken]);
  if (!u.rows[0]) return res.status(401).json({ ok: false, error: "bad token" });

  const created = await pool.query(
    `insert into orders (user_id, cart, total_int) values ($1,$2,$3) returning id,status,total_int;`,
    [u.rows[0].id, JSON.stringify(cart), total]
  );

  res.json({ ok: true, order: created.rows[0] });
});

// Create an expected payment for an order (what you described)
app.post("/api/payments/expect", requireUser, async (req, res) => {
  const orderId = Number(req.body?.order_id);
  const payType = String(req.body?.pay_type || "").trim(); // ride_potion, pets, etc
  const expected = req.body?.expected; // {"ride_potion":2}
  const receiverAccount = String(req.body?.receiver_account || "").trim(); // e.g. "FarmAccount2"

  if (!orderId || !payType || !receiverAccount || typeof expected !== "object") {
    return res.status(400).json({ ok: false, error: "order_id, pay_type, expected{}, receiver_account required" });
  }

  const u = await pool.query(`select id from users where token=$1`, [req.userToken]);
  if (!u.rows[0]) return res.status(401).json({ ok: false, error: "bad token" });

  const ord = await pool.query(`select id,status from orders where id=$1 and user_id=$2`, [orderId, u.rows[0].id]);
  if (!ord.rows[0]) return res.status(404).json({ ok: false, error: "order not found" });

  const created = await pool.query(
    `insert into expected_payments (user_id, order_id, pay_type, expected, receiver_account)
     values ($1,$2,$3,$4,$5)
     returning id,status;`,
    [u.rows[0].id, orderId, payType, JSON.stringify(expected), receiverAccount]
  );

  res.json({ ok: true, expected_payment: created.rows[0] });
});

// ------------------- INVENTORY INGEST (SECURED) -------------------
// Your Roblox/executor posts here with x-inventory-key
app.post("/inventory", requireInventoryKey, async (req, res) => {
  const receiver_account = String(req.body?.user || "unknown"); // using your payload.user as receiver account id
  const snapshot = req.body;

  // get last snapshot for delta
  const last = await pool.query(
    `select data from inventory_snapshots where receiver_account=$1 order by id desc limit 1`,
    [receiver_account]
  );

  const prevData = last.rows[0]?.data || null;
  const prevCounts = prevData ? countFromSnapshot(prevData) : {};
  const newCounts = countFromSnapshot(snapshot);
  const delta = deltaCounts(prevCounts, newCounts);

  // store snapshot
  await pool.query(
    `insert into inventory_snapshots (receiver_account, data) values ($1,$2)`,
    [receiver_account, JSON.stringify(snapshot)]
  );

  // try match pending expected payments for this receiver account
  const pending = await pool.query(
    `select id,user_id,order_id,expected from expected_payments
     where receiver_account=$1 and status='pending'
     order by id asc`,
    [receiver_account]
  );

  let matched = [];
  for (const p of pending.rows) {
    const expected = p.expected;
    if (satisfies(delta, expected)) {
      // mark matched + credit user balance by order total (or however you want)
      await pool.query(`update expected_payments set status='matched' where id=$1`, [p.id]);

      const order = await pool.query(`select total_int from orders where id=$1`, [p.order_id]);
      const amount = order.rows[0]?.total_int || 0;

      await pool.query(`update users set balance_int = balance_int + $1 where id=$2`, [amount, p.user_id]);
      await pool.query(`update orders set status='paid' where id=$1`, [p.order_id]);

      matched.push({ expected_payment_id: p.id, credited: amount });
    }
  }

  res.json({ ok: true, delta, matched });
});

// View latest inventory (public for now)
app.get("/inventory/latest/:receiver_account", async (req, res) => {
  const receiver = req.params.receiver_account;
  const { rows } = await pool.query(
    `select received_at,data from inventory_snapshots where receiver_account=$1 order by id desc limit 1`,
    [receiver]
  );
  res.json({ ok: true, latest: rows[0] || null });
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => console.log("✅ listening on", PORT));

initDb().catch((e) => {
  console.error("DB init failed (server still running):", e);
});
