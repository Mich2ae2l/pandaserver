import express from "express";
import cors from "cors";
import helmet from "helmet";
import dotenv from "dotenv";
import fs from "fs";
import path from "path";
import crypto from "crypto";
import { Low } from "lowdb";
import { JSONFile } from "lowdb/node";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import multer from "multer";
import fetch from "node-fetch";
import nodemailer from "nodemailer";
import { Mutex } from "async-mutex";
import { nanoid } from "nanoid";
import { fileURLToPath } from "url";
import archiver from "archiver";
import unzipper from "unzipper";
import { createClient } from "@supabase/supabase-js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config();
const app = express();

/* ---------------- Supabase client (server-side) ---------------- */
const SUPABASE_URL = process.env.SUPABASE_URL || "";
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_KEY || ""; // prefer service role on server
const SUPABASE_BUCKET = process.env.SUPABASE_BUCKET || "pdfs";
let supabase = null;
if (SUPABASE_URL && SUPABASE_KEY) {
  supabase = createClient(SUPABASE_URL, SUPABASE_KEY, {
    auth: { persistSession: false },
  });
} else {
  console.warn("Supabase not configured: set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY (or SUPABASE_KEY)");
}
/* ---------------- Supabase DB helpers (place AFTER the supabase client init above) ---------------- */

const SUPABASE_TABLE = process.env.SUPABASE_TABLE || "pdfs";

/**
 * Insert a pdf record into Supabase (returns inserted row).
 * item should contain: { title, state, year, price_cents, status, file_name, created_at }
 */
async function insertPdfToDb(item) {
  if (!supabase) throw new Error("Supabase client not configured");
  const { data, error } = await supabase
    .from(SUPABASE_TABLE)
    .insert([item])
    .select()
    .single();
  if (error) throw error;
  return data;
}

/**
 * Update a pdf record by id with patch object. Returns updated row.
 */
async function updatePdfInDb(id, patch) {
  if (!supabase) throw new Error("Supabase client not configured");
  const { data, error } = await supabase
    .from(SUPABASE_TABLE)
    .update(patch)
    .eq("id", id)
    .select()
    .single();
  if (error) throw error;
  return data;
}

/**
 * Delete a pdf row from DB by id.
 */
async function deletePdfRowFromDb(id) {
  if (!supabase) throw new Error("Supabase client not configured");
  const { error } = await supabase
    .from(SUPABASE_TABLE)
    .delete()
    .eq("id", id);
  if (error) throw error;
  return true;
}

/**
 * Fetch PDF rows (basic filter for 'unsold' + optional state/year range + pagination)
 * returns { total, items } where items are array of rows
 */
async function queryPdfsFromDb({ state, year_min = 2000, year_max = 2007, page = 1, per_page = 100, status = "unsold", q = "" }) {
  if (!supabase) throw new Error("Supabase client not configured");
  const pg = Math.max(Number(page) || 1, 1);
  const pp = Math.min(Math.max(Number(per_page) || 100, 1), 500);

  let query = supabase.from(SUPABASE_TABLE).select("*", { count: "exact" });

  if (status) query = query.eq("status", status);
  if (state) query = query.eq("state", String(state).toUpperCase());
  if (year_min != null) query = query.gte("year", Number(year_min));
  if (year_max != null) query = query.lte("year", Number(year_max));
  if (q) {
    // simple title search; for multi-field or OR-matching you'll need more sophisticated queries
    query = query.ilike("title", `%${q}%`);
  }

  const from = (pg - 1) * pp;
  const to = from + pp - 1;
  const { data, count, error } = await query.range(from, to);
  if (error) throw error;
  return { total: count || (data ? data.length : 0), items: data || [] };
}

/**
 * Fetch single pdf by id
 */
async function fetchPdfByIdFromDb(id) {
  if (!supabase) throw new Error("Supabase client not configured");
  const { data, error } = await supabase.from(SUPABASE_TABLE).select("*").eq("id", id).single();
  if (error) {
    // normalize not-found to null (Supabase may return error codes depending on config)
    if (error.code === "PGRST116" || error.code === "PGRST102") return null;
    throw error;
  }
  return data;
}


/* ---------------- Basic hardening & CORS ---------------- */
app.set("trust proxy", true);
app.use(
  helmet({
    crossOriginEmbedderPolicy: false,
    crossOriginOpenerPolicy: { policy: "same-origin" },
    crossOriginResourcePolicy: { policy: "cross-origin" },
  })
);

// CORS allow-list via env CORS_ORIGINS (comma-separated).
// If you don't set CORS_ORIGINS, keep a friendly default set for local dev + your Netlify site.
// Replace or add domains in your environment for production.
const RAW_ALLOWED = process.env.CORS_ORIGINS || "http://localhost:5173,https://sprightly-cannoli-74fc49.netlify.app";
const ALLOWED = RAW_ALLOWED
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

const corsOptions = {
  origin: (origin, cb) => {
    if (!origin) return cb(null, true); // curl / mobile apps
    if (ALLOWED.length === 0) return cb(null, true);
    if (ALLOWED.includes(origin)) return cb(null, true);
    return cb(new Error(`CORS blocked for origin: ${origin}`));
  },
  credentials: true,
  allowedHeaders: ["Content-Type", "Authorization"],
  methods: ["GET", "POST", "DELETE", "PUT", "PATCH", "OPTIONS"],
};

app.use(cors(corsOptions));
app.options("*", cors(corsOptions));
app.use(express.json({ limit: "2mb" }));

const PORT = process.env.PORT || 5062;
const DB_FILE = path.join(__dirname, "db.json");

/* ---------------- Ensure storage dirs exist (tmp only) ---------------- */
const STORAGE_ROOT = path.join(__dirname, "storage");
const TMP_DIR = path.join(STORAGE_ROOT, "tmp");
// local PDF_DIR kept for backwards compat but not used for uploaded files when supabase is configured
const PDF_DIR = path.join(STORAGE_ROOT, "pdfs");
for (const d of [STORAGE_ROOT, TMP_DIR, PDF_DIR]) {
  try { fs.mkdirSync(d, { recursive: true }); } catch {}
}

// optionally expose files over HTTPS as /files/*  (this will still serve local PDF_DIR if present)
app.use("/files", express.static(PDF_DIR, {
  maxAge: "1y",
  setHeaders: (res) => {
    res.setHeader("Cache-Control", "public, max-age=31536000, immutable");
  },
}));

/* ---------------- DB ---------------- */
const db = new Low(new JSONFile(DB_FILE), {
  users: [],
  pdfs: [],
  transactions: [],
  downloadTokens: [],
  resetTokens: [],
  inbox: [],
  chats: [],
});
await db.read();
db.data ||= { users: [], pdfs: [], transactions: [], downloadTokens: [], resetTokens: [], inbox: [], chats: [] };
if (!Array.isArray(db.data.inbox)) db.data.inbox = [];
if (!Array.isArray(db.data.chats)) db.data.chats = [];

/* ---------------- Helpers ---------------- */
const PRICE_CENTS = 499;
const mutex = new Mutex();
const nowISO = () => new Date().toISOString();
const cents = (n) => Math.round(Number(n || 0));
const findUserByEmail = (email) => db.data.users.find((u) => u.email.toLowerCase() === String(email).toLowerCase());
const saveDb = () => db.write();

async function uploadToSupabase(localPath, destPath, contentType = "application/pdf") {
  if (!supabase) throw new Error("Supabase client not configured");
  const data = await fs.promises.readFile(localPath);
  const { error } = await supabase.storage.from(SUPABASE_BUCKET).upload(destPath, data, {
    contentType,
    upsert: false,
  });
  if (error) throw error;
  try { await fs.promises.unlink(localPath); } catch {}
  return true;
}

function publicBase(req) {
  if (process.env.PUBLIC_BASE_URL) return process.env.PUBLIC_BASE_URL.replace(/\/+$/, "");
  const proto = (req.headers["x-forwarded-proto"] || req.protocol || "http").split(",")[0].trim();
  const host = req.headers["x-forwarded-host"] || req.headers.host || `localhost:${PORT}`;
  return `${proto}://${host}`;
}
function getJwtFromReq(req) {
  const auth = req.headers.authorization || "";
  if (auth.startsWith("Bearer ")) return auth.slice(7);
  if (typeof req.query?.jwt === "string" && req.query.jwt.length > 10) return req.query.jwt;
  return null;
}

/* ---------------- filename parsing ---------------- */
const US_STATES = new Set([
  "AL","AK","AZ","AR","CA","CO","CT","DE","FL","GA","HI","ID","IL","IN","IA","KS","KY","LA","ME","MD","MA","MI","MN",
  "MS","MO","MT","NE","NV","NH","NJ","NM","NY","NC","ND","OH","OK","OR","PA","RI","SC","SD","TN","TX","UT","VT","VA",
  "WA","WV","WI","WY"
]);

function parseFilenameMeta(originalName) {
  const base = String(originalName).replace(/\.(pdf|png|jpg|jpeg)$/i, "").trim();
  {
    const rx = /^(.*?)\s*[-_ ]+([A-Za-z]{2})\s*[-_ ]+(200[0-7])(?:\D|$)/i;
    const m = base.match(rx);
    if (m) {
      let [, rawTitle, st, yr] = m;
      const state = st.toUpperCase();
      if (US_STATES.has(state)) {
        const title = rawTitle.replace(/[-_]+/g, " ").trim();
        const year = Number(yr);
        if (year >= 2000 && year <= 2007) return { title, state, year };
      }
    }
  }

  const parts = base.split("_").map((p) => p.trim()).filter(Boolean);
  if (parts.length >= 3) {
    const lastPart = parts[parts.length - 1];
    if (/^\d{8}$/.test(lastPart)) {
      const nameParts = parts.slice(0, parts.length - 1);
      if (nameParts.length >= 2) {
        const first = cap(nameParts[0]);
        const last = cap(nameParts[nameParts.length - 1]);
        const middle = nameParts.length === 3 ? cap(nameParts[1]) : undefined;

        const y = lastPart.slice(0, 4);
        const a = lastPart.slice(4, 6);
        const b = lastPart.slice(6, 8);
        let mm = Number(a), dd = Number(b);
        if (!(mm >= 1 && mm <= 12)) { mm = Number(b); dd = Number(a); }
        if (mm >= 1 && mm <= 12 && dd >= 1 && dd <= 31) {
          const mmStr = String(mm).padStart(2, "0");
          const ddStr = String(dd).padStart(2, "0");
          const iso = `${y}-${mmStr}-${ddStr}`;
          const dt = new Date(iso);
          if (!Number.isNaN(dt.getTime())) {
            return {
              title: `${first}${middle ? " " + middle : ""} ${last}`,
              state: null,
              year: Number(y),
              dobISO: iso,
              parsed_name: { first, middle, last },
            };
          }
        }
      }
    }

    if (/^\d{4}$/.test(lastPart)) {
      const possibleYear = Number(lastPart);
      if (possibleYear >= 1900 && possibleYear <= 2100) {
        for (let i = 1; i < parts.length - 1; i++) {
          const candidate = parts[i].toUpperCase();
          if (US_STATES.has(candidate)) {
            const first = cap(parts[0]);
            const last = cap(parts[parts.length - 1 === i ? parts.length - 2 : parts.length - 1]);
            const nameParts = parts.slice(0, i);
            const nameFirst = cap(nameParts[0]);
            const nameLast = cap(nameParts[nameParts.length - 1] || last);
            const title = `${nameFirst} ${nameLast}`.trim();
            return { title, state: candidate, year: possibleYear };
          }
        }
        if (parts.length >= 2) {
          const first = cap(parts[0]);
          const last = cap(parts[1]);
          return { title: `${first} ${last}`, state: null, year: possibleYear };
        }
      }
    }
  }

  return null;
}

function cap(s) {
  if (!s) return "";
  return s.charAt(0).toUpperCase() + s.slice(1).toLowerCase();
}

/* ---------------- Auth guards ---------------- */
function requireAuth(req, res, next) {
  const token = getJwtFromReq(req);
  if (!token) return res.status(401).json({ error: "Missing token" });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET || "dev_secret");
    next();
  } catch {
    return res.status(401).json({ error: "Invalid token" });
  }
}
function requireAdmin(req, res, next) {
  if (!req.user?.is_admin) return res.status(403).json({ error: "Admin only" });
  next();
}

/* ---------------- SMTP helper ---------------- */
function makeMailer() {
  const host = process.env.SMTP_HOST;
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;
  const port = Number(process.env.SMTP_PORT || 587);
  if (!host || !user || !pass) return null;
  return nodemailer.createTransport({ host, port, secure: port === 465, auth: { user, pass } });
}

/* ===================== LIVE CHAT (SSE) ===================== */
const MAX_TEXT = 2000;
const userStreams = new Map();
const adminStreams = new Set();
function sseSend(res, event, data) { res.write(`event: ${event}\n`); res.write(`data: ${JSON.stringify(data)}\n\n`); }
function ssePing(res) { res.write(`: ping\n\n`); }
function pushMessage({ user_id, from, text }) {
  const msg = { id: nanoid(), user_id, from, text: String(text || "").slice(0, MAX_TEXT), created_at: nowISO() };
  db.data.chats.push(msg);
  saveDb().catch((e) => console.error("saveDb error:", e));
  const bucket = userStreams.get(user_id);
  if (bucket) { for (const r of bucket) sseSend(r, "message", msg); }
  for (const r of adminStreams) sseSend(r, "message", msg);
  return msg;
}

/* ---------------- Auth ---------------- */
app.post("/api/auth/register", async (req, res) => {
  const { name, email, password } = req.body || {};
  if (!name || !email || !password) return res.status(400).json({ error: "name, email, password required" });
  if (findUserByEmail(email)) return res.status(409).json({ error: "Email already registered" });

  const hash = await bcrypt.hash(password, 10);
  const user = { id: nanoid(), name, email, password_hash: hash, balance_cents: 0, is_admin: false, created_at: nowISO() };
  db.data.users.push(user);
  await saveDb();
  const token = jwt.sign({ id: user.id, email: user.email, is_admin: user.is_admin }, process.env.JWT_SECRET || "dev_secret", { expiresIn: "7d" });
  res.json({ token, user: { id: user.id, name: user.name, email: user.email, balance_cents: user.balance_cents, is_admin: user.is_admin } });
});

app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body || {};
  const user = findUserByEmail(email || "");
  if (!user) return res.status(401).json({ error: "Invalid credentials" });
  const ok = await bcrypt.compare(password || "", user.password_hash);
  if (!ok) return res.status(401).json({ error: "Invalid credentials" });
  const token = jwt.sign({ id: user.id, email: user.email, is_admin: user.is_admin }, process.env.JWT_SECRET || "dev_secret", { expiresIn: "7d" });
  res.json({ token, user: { id: user.id, name: user.name, email: user.email, balance_cents: user.balance_cents, is_admin: user.is_admin } });
});

app.get("/api/me", requireAuth, (req, res) => {
  const u = db.data.users.find((x) => x.id === req.user.id);
  if (!u) return res.status(404).json({ error: "Not found" });
  res.json({ id: u.id, name: u.name, email: u.email, balance_cents: u.balance_cents, is_admin: u.is_admin });
});

/* -------- Password reset -------- */
app.post("/api/auth/forgot", async (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ error: "email required" });

  await db.read();
  const user = db.data.users.find((u) => u.email.toLowerCase() === String(email).toLowerCase());

  const token = nanoid();
  const expires_at = Date.now() + 60 * 60 * 1000;

  if (user) {
    db.data.resetTokens = db.data.resetTokens.filter((t) => t.user_id !== user.id);
    db.data.resetTokens.push({ token, user_id: user.id, expires_at });
    await db.write();

    const base = process.env.PUBLIC_BASE_URL || `http://localhost:${PORT}`;
    const resetLink = `${base}/reset?token=${token}`;

    const mailer = makeMailer();
    if (mailer) {
      try {
        await mailer.sendMail({
          to: user.email,
          from: `"Panda" <${process.env.SMTP_USER || "no-reply@localhost"}>`,
          subject: "Reset your Panda password",
          text: `Use this link to reset your password (valid 1 hour): ${resetLink}`,
          html: `<p>Use this link to reset your password (valid 1 hour):</p><p><a href="${resetLink}">${resetLink}</a></p>`,
        });
      } catch (e) { console.error("SMTP send error:", e?.message || e); }
    }
  }
  res.json({ ok: true, token, expires_at });
});

app.post("/api/auth/reset", async (req, res) => {
  const { token, new_password } = req.body || {};
  if (!token || !new_password) return res.status(400).json({ error: "token and new_password required" });

  await db.read();
  const rec = db.data.resetTokens.find((t) => t.token === token);
  if (!rec || Date.now() > rec.expires_at) return res.status(400).json({ error: "Invalid or expired token" });

  const user = db.data.users.find((u) => u.id === rec.user_id);
  if (!user) return res.status(400).json({ error: "User not found" });

  const hash = await bcrypt.hash(new_password, 10);
  user.password_hash = hash;
  db.data.resetTokens = db.data.resetTokens.filter((t) => t.token !== token);
  await db.write();
  res.json({ ok: true });
});

/* ------------- Storefront ------------- */
app.get("/api/pdfs", (req, res) => {
  const { state, year_min, year_max, page = 1, per_page = 100 } = req.query;
  let items = db.data.pdfs.filter((p) => p.status === "unsold");
  if (state) items = items.filter((p) => p.state?.toLowerCase() === String(state).toLowerCase());
  const yMin = year_min ? Number(year_min) : 2000;
  const yMax = year_max ? Number(year_max) : 2007;
  items = items.filter((p) => Number(p.year) >= yMin && Number(p.year) <= yMax);
  const pp = Math.min(Math.max(Number(per_page), 1), 500);
  const pg = Math.max(Number(page), 1);
  const total = items.length;
  const start = (pg - 1) * pp;
  res.json({
    total,
    page: pg,
    per_page: pp,
    items: items.slice(start, start + pp).map((p) => ({
      id: p.id, title: p.title, state: p.state, year: p.year, price_cents: PRICE_CENTS,
    })),
  });
});

app.get("/api/inventory/count", (req, res) => {
  res.json({ remaining: db.data.pdfs.filter((p) => p.status === "unsold").length });
});

// richer library + alias
app.get("/api/me/library", requireAuth, (req, res) => {
  const owned = db.data.pdfs
    .filter((p) => p.buyer_user_id === req.user.id)
    .sort((a, b) => new Date(b.sold_at || 0) - new Date(a.sold_at || 0))
    .map((p) => ({ id: p.id, title: p.title, state: p.state, year: p.year, price_cents: PRICE_CENTS }));
  res.json({ items: owned });
});
app.get("/api/library", requireAuth, (req, res) => {
  const owned = db.data.pdfs
    .filter((p) => p.buyer_user_id === req.user.id)
    .sort((a, b) => new Date(b.sold_at || 0) - new Date(a.sold_at || 0))
    .map((p) => ({ id: p.id, title: p.title, state: p.state, year: p.year, price_cents: PRICE_CENTS }));
  res.json({ items: owned });
});

/* ------------- NOWPayments ------------- */
app.post("/api/now/create-invoice", requireAuth, async (req, res) => {
  try {
    const { amount_usd } = req.body || {};
    const amt = Number(amount_usd);
    if (!amt || amt < 2) return res.status(400).json({ error: "amount_usd must be >= 2" });
    const orderId = "dep_" + nanoid();

    const baseApi = (process.env.PUBLIC_API_URL || `http://localhost:${PORT}`).replace(/\/+$/, "");
    const baseSite = (process.env.PUBLIC_BASE_URL || `http://localhost:${PORT}`).replace(/\/+$/, "");
    const ipnUrl = `${baseApi}/api/now/webhook`;

    const payload = {
      price_amount: amt,
      price_currency: "usd",
      order_id: orderId,
      ipn_callback_url: ipnUrl,
      success_url: `${baseSite}/funds/success`,
      cancel_url: `${baseSite}/funds/cancel`,
    };

    const resp = await fetch("https://api.nowpayments.io/v1/invoice", {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-api-key": process.env.NOWPAY_API_KEY || "" },
      body: JSON.stringify(payload),
    });
    const data = await resp.json();
    if (!resp.ok) return res.status(400).json({ error: "NOWPayments error", details: data });

    db.data.transactions.push({
      id: nanoid(),
      user_id: req.user.id,
      type: "deposit",
      amount_cents: Math.round(amt * 100),
      currency: "USD",
      provider: "NOWPayments",
      provider_invoice_id: data.id ?? data.invoice_id ?? null,
      provider_order_id: orderId,
      status: "pending",
      raw: data,
      created_at: nowISO(),
    });
    await saveDb();
    res.json({ invoice_url: data.invoice_url || data.url || null, invoice: data });
  } catch (e) {
    console.error(e); res.status(500).json({ error: "Failed to create invoice" });
  }
});

app.post("/api/now/webhook", express.json({ type: "*/*" }), async (req, res) => {
  try {
    const ipnSecret = process.env.NOWPAY_IPN_SECRET || "";
    const signature = req.headers["x-nowpayments-sig"];
    const body = req.body || {};
    const signedStr = JSON.stringify(body, Object.keys(body).sort());
    const hmac = crypto.createHmac("sha512", ipnSecret).update(signedStr).digest("hex");
    if (!ipnSecret || !signature || hmac !== signature) return res.status(401).json({ error: "Bad signature" });

    const status = String(body.payment_status || body.invoice_status || "").toLowerCase();
    const orderId = body.order_id || body.orderId;
    const priceAmount = Number(body.price_amount || body.priceAmount || 0);
    const ok = ["confirmed", "finished"].includes(status);

    if (ok && orderId) {
      const tx = db.data.transactions.find((t) => t.provider_order_id === orderId && t.type === "deposit");
      if (tx && tx.status !== "completed") {
        const user = db.data.users.find((u) => u.id === tx.user_id);
        if (user) {
          user.balance_cents = cents(user.balance_cents + Math.round(priceAmount * 100));
          tx.status = "completed"; tx.updated_at = nowISO(); tx.raw_last = body;
          await saveDb();
        }
      }
    }
    res.json({ ok: true });
  } catch (e) { console.error(e); res.json({ ok: true }); }
});

/* ------------- Purchasing ------------- */

// Bulk purchase (keep first)
app.post("/api/purchase/bulk", requireAuth, async (req, res) => {
  const release = await mutex.acquire();
  try {
    await db.read();
    const ids = Array.isArray(req.body?.pdf_ids) ? req.body.pdf_ids.map(String) : [];
    if (ids.length === 0) return res.status(400).json({ error: "pdf_ids required" });

    const user = db.data.users.find((u) => u.id === req.user.id);
    if (!user) return res.status(401).json({ error: "User not found" });

    let balance = user.balance_cents || 0;
    const isAdmin = !!req.user.is_admin;

    const purchased_ids = [];
    const skipped_ids = [];

    for (const id of ids) {
      const pdf = db.data.pdfs.find((p) => p.id === id);

      if (!pdf || pdf.status !== "unsold") {
        skipped_ids.push({ id, reason: "Not available" });
        continue;
      }

      if (!isAdmin && balance < PRICE_CENTS) {
        skipped_ids.push({ id, reason: "Insufficient funds" });
        continue;
      }

      pdf.status = "sold";
      pdf.buyer_user_id = user.id;
      pdf.sold_at = nowISO();
      if (!isAdmin) balance -= PRICE_CENTS;

      db.data.transactions.push({
        id: nanoid(),
        user_id: user.id,
        type: "purchase",
        pdf_id: pdf.id,
        amount_cents: PRICE_CENTS,
        currency: "USD",
        status: "completed",
        created_at: nowISO(),
      });

      purchased_ids.push(id);
    }

    if (!isAdmin) user.balance_cents = balance;

    await saveDb();
    return res.json({ purchased_ids, skipped_ids });
  } catch (e) {
    console.error("Bulk purchase error:", e);
    return res.status(500).json({ error: "Bulk purchase failed" });
  } finally {
    release();
  }
});

app.post("/api/purchase/single/:pdfId", requireAuth, async (req, res) => {
  const release = await mutex.acquire();
  try {
    await db.read();
    const pdf = db.data.pdfs.find((p) => p.id === String(req.params.pdfId));
    if (!pdf || pdf.status !== "unsold") return res.status(404).json({ error: "PDF not available" });

    const user = db.data.users.find((u) => u.id === req.user.id);
    if (!user) return res.status(401).json({ error: "User not found" });

    if (!req.user.is_admin) {
      if ((user.balance_cents || 0) < PRICE_CENTS) return res.status(400).json({ error: "Insufficient balance" });
      user.balance_cents = (user.balance_cents || 0) - PRICE_CENTS;
    }

    pdf.status = "sold";
    pdf.buyer_user_id = user.id;
    pdf.sold_at = nowISO();

    db.data.transactions.push({
      id: nanoid(),
      user_id: user.id,
      type: "purchase",
      pdf_id: pdf.id,
      amount_cents: PRICE_CENTS,
      currency: "USD",
      status: "completed",
      created_at: nowISO(),
    });

    await saveDb();
    res.json({ ok: true, pdf: { id: pdf.id, title: pdf.title } });
  } finally {
    release();
  }
});

/* ------------- Downloads (now via Supabase signed URLs) ------------- */
app.post("/api/download/token/:pdfId", requireAuth, (req, res) => {
  const pdf = db.data.pdfs.find((p) => p.id === req.params.pdfId);
  if (!pdf) return res.status(404).json({ error: "Not found" });
  if (!req.user.is_admin && pdf.buyer_user_id !== req.user.id) return res.status(403).json({ error: "Purchase required" });

  const token = nanoid();
  const expires_at = Date.now() + 5 * 60 * 1000;
  db.data.downloadTokens.push({ token, user_id: req.user.id, pdf_id: pdf.id, expires_at });
  saveDb();

  const url = `${publicBase(req)}/api/download/${token}`;
  res.json({ token, expires_at, url });
});

app.get("/api/admin/pdfs/:id/download", requireAuth, requireAdmin, async (req, res) => {
  try {
    await db.read();
    db.data.pdfs ||= [];

    const pdf = db.data.pdfs.find((p) => p.id === req.params.id);
    if (!pdf) {
      return res.status(404).json({ error: "Not found" });
    }

    if (supabase) {
      const { data, error } = await supabase.storage.from(SUPABASE_BUCKET).createSignedUrl(pdf.file_name, 60);
      if (error || !data?.signedUrl) {
        console.error("Supabase signed url error:", error);
        return res.status(500).json({ error: "Failed to generate signed URL" });
      }
      // redirect to signed URL (client will download)
      return res.redirect(data.signedUrl);
    }

    // fallback to local filesystem if supabase not configured
    const file = path.join(PDF_DIR, pdf.file_name);
    if (!fs.existsSync(file)) {
      return res.status(404).json({ error: "File missing" });
    }

    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", `attachment; filename="${pdf.file_name}"`);
    fs.createReadStream(file).pipe(res);
  } catch (err) {
    console.error("Download error:", err);
    res.status(500).json({ error: "Server error during download" });
  }
});

app.get("/api/download/:token", async (req, res) => {
  const tok = db.data.downloadTokens.find((t) => t.token === req.params.token);
  if (!tok || Date.now() > tok.expires_at) return res.status(410).json({ error: "Expired token" });

  const pdf = db.data.pdfs.find((p) => p.id === tok.pdf_id);
  if (!pdf) return res.status(404).json({ error: "Not found" });

  if (supabase) {
    const { data, error } = await supabase.storage.from(SUPABASE_BUCKET).createSignedUrl(pdf.file_name, 60);
    if (error || !data?.signedUrl) {
      console.error("Supabase signed url error:", error);
      return res.status(500).json({ error: "Failed to generate signed URL" });
    }
    // Optionally force attachment via query param handled by supabase CDN — if not honored by remote, client will open inline
    return res.redirect(data.signedUrl);
  }

  const file = path.join(PDF_DIR, pdf.file_name);
  if (!fs.existsSync(file)) return res.status(404).json({ error: "File missing" });

  res.setHeader("Content-Type", "application/octet-stream");
  const asAttachment = String(req.query.dl || "") === "1";
  const disp = asAttachment ? "attachment" : "inline";
  res.setHeader("Content-Disposition", `${disp}; filename="${(pdf.title || pdf.id).replace(/[^a-z0-9_\-\.]+/gi, "_")}.pdf"`);

  fs.createReadStream(file).pipe(res);
  db.data.downloadTokens = db.data.downloadTokens.filter((t) => t.token !== tok.token);
  saveDb();
});

/* === ZIP download of purchased PDFs (streams files from Supabase) === */
app.post("/api/download/zip", requireAuth, async (req, res) => {
  try {
    const ids = Array.isArray(req.body?.pdf_ids) ? req.body.pdf_ids.map(String) : [];
    if (ids.length === 0) return res.status(400).json({ error: "pdf_ids required" });

    await db.read();
    const isAdmin = !!req.user.is_admin;

    const want = new Set(ids);
    const rows = db.data.pdfs.filter(p => want.has(p.id) && (isAdmin || p.buyer_user_id === req.user.id));

    res.setHeader("Content-Type", "application/zip");
    res.setHeader("Content-Disposition", `attachment; filename="panda_pdfs_${Date.now()}.zip"`);

    const archive = archiver("zip", { zlib: { level: 9 } });
    archive.on("error", (err) => { throw err; });
    archive.pipe(res);

    let added = 0;
    for (const p of rows) {
      if (!p.file_name) continue;
      const nice = `${(p.title || p.id).replace(/[^a-z0-9_\-\.]+/gi, "_")}.pdf`;

      if (supabase) {
        try {
          // create a short-lived signed URL then fetch and append stream
          const { data, error } = await supabase.storage.from(SUPABASE_BUCKET).createSignedUrl(p.file_name, 120);
          if (error || !data?.signedUrl) {
            console.error("Signed URL error for zip file", p.file_name, error);
            continue;
          }
          const remoteResp = await fetch(data.signedUrl);
          if (!remoteResp.ok) { console.error("Failed to fetch file for ZIP", p.file_name, remoteResp.status); continue; }
          const stream = remoteResp.body;
          archive.append(stream, { name: nice });
          added++;
        } catch (e) {
          console.error("Error adding remote file to zip:", e);
          continue;
        }
      } else {
        const fp = path.join(PDF_DIR, p.file_name);
        if (!fs.existsSync(fp)) continue;
        archive.file(fp, { name: nice });
        added++;
      }
    }

    if (added === 0) {
      archive.append("No files available in this ZIP.\n", { name: "README.txt" });
    }
    await archive.finalize();
  } catch (e) {
    console.error("ZIP download error:", e);
    if (!res.headersSent) res.status(500).json({ error: "ZIP creation failed" });
  }
});

/* ------------- Admin ------------- */
const upload = multer({ dest: TMP_DIR, limits: { fileSize: 200 * 1024 * 1024 } }); // 200MB per file limit
const uploadM = upload; // alias
const uploadSingleFlexible = uploadM.fields([{ name: "file", maxCount: 1 }, { name: "pdf", maxCount: 1 }]);

app.get("/api/admin/metrics", requireAuth, requireAdmin, (req, res) => {
  const totalSales = db.data.transactions.filter((t) => t.type === "purchase").reduce((s, t) => s + t.amount_cents, 0) / 100;
  const sold = db.data.pdfs.filter((p) => p.status === "sold").length;
  const remaining = db.data.pdfs.filter((p) => p.status === "unsold").length;
  res.json({
    total_sales_usd: totalSales,
    sold,
    remaining,
    users: db.data.users.length,
    deposits: db.data.transactions.filter((t) => t.type === "deposit" && t.status === "completed").length,
  });
});

app.get("/api/admin/metrics/rich", requireAuth, requireAdmin, (req, res) => {
  const today = new Date();
  const days = Number(req.query.days || 30);
  const dayKey = (d) => d.toISOString().slice(0, 10);
  const backDates = Array.from({ length: days }).map((_, i) => {
    const d = new Date(today); d.setDate(d.getDate() - (days - 1 - i)); return dayKey(d);
  });
  const salesByDay = Object.fromEntries(backDates.map((k) => [k, 0]));
  const depositsByDay = Object.fromEntries(backDates.map((k) => [k, 0]));
  for (const t of db.data.transactions) {
    if (!t.created_at) continue;
    const k = dayKey(new Date(t.created_at));
    if (!(k in salesByDay)) continue;
    if (t.type === "purchase") salesByDay[k] += Number(t.amount_cents || 0);
    if (t.type === "deposit" && t.status === "completed") depositsByDay[k] += Number(t.amount_cents || 0);
  }
  const totals = {
    total_sales_usd: db.data.transactions.filter((t) => t.type === "purchase").reduce((s, t) => s + (t.amount_cents || 0), 0) / 100,
    sold: db.data.pdfs.filter((p) => p.status === "sold").length,
    remaining: db.data.pdfs.filter((p) => p.status === "unsold").length,
    users: db.data.users.length,
    deposits: db.data.transactions.filter((t) => t.type === "deposit" && t.status === "completed").length,
  };
  res.json({
    ...totals,
    sales_by_day: backDates.map((k) => ({ date: k, amount_cents: salesByDay[k] })),
    deposits_by_day: backDates.map((k) => ({ date: k, amount_cents: depositsByDay[k] })),
  });
});

// Users
app.get("/api/admin/users", requireAuth, requireAdmin, (req, res) => {
  let { page = 1, per_page = 50, q = "" } = req.query;
  page = Math.max(Number(page) || 1, 1);
  per_page = Math.min(Math.max(Number(per_page) || 50, 1), 500);

  let list = db.data.users.slice();
  if (q) {
    const t = String(q).toLowerCase();
    list = list.filter((u) => String(u.name || "").toLowerCase().includes(t) || String(u.email || "").toLowerCase().includes(t));
  }
  const total = list.length;
  const start = (page - 1) * per_page;
  const items = list.slice(start, start + per_page).map((u) => ({
    id: u.id, name: u.name, email: u.email, balance_cents: u.balance_cents || 0, is_admin: !!u.is_admin, created_at: u.created_at,
  }));
  res.json({ total, page, per_page, items });
});

app.patch("/api/admin/users/:id", requireAuth, requireAdmin, async (req, res) => {
  const u = db.data.users.find((x) => x.id === String(req.params.id));
  if (!u) return res.status(404).json({ error: "Not found" });
  const { name, email, balance_cents, is_admin } = req.body || {};
  if (typeof name === "string") u.name = name.trim();
  if (typeof email === "string") u.email = email.trim();
  if (balance_cents != null && !Number.isNaN(Number(balance_cents))) {
    u.balance_cents = Math.max(0, Math.round(Number(balance_cents)));
  }
  if (typeof is_admin === "boolean") u.is_admin = is_admin;
  await db.write();
  res.json({ id: u.id, name: u.name, email: u.email, balance_cents: u.balance_cents || 0, is_admin: !!u.is_admin, created_at: u.created_at });
});

app.delete("/api/admin/users/:id", requireAuth, requireAdmin, async (req, res) => {
  const id = String(req.params.id);
  const idx = db.data.users.findIndex((x) => x.id === id);
  if (idx === -1) return res.status(404).json({ error: "Not found" });
  db.data.pdfs.forEach((p) => { if (p.buyer_user_id === id) p.buyer_user_id = null; });
  db.data.resetTokens = db.data.resetTokens.filter((t) => t.user_id !== id);
  db.data.downloadTokens = db.data.downloadTokens.filter((t) => t.user_id !== id);
  db.data.transactions.forEach((t) => { if (t.user_id === id) t.user_id = null; });
  const [removed] = db.data.users.splice(idx, 1);
  await db.write();
  res.json({ ok: true, removed: { id: removed.id, email: removed.email } });
});

app.get("/api/admin/transactions", requireAuth, requireAdmin, (req, res) => {
  res.json({ items: db.data.transactions.slice().reverse().slice(0, 500) });
});

// FAST admin list
app.get("/api/admin/pdfs", requireAuth, requireAdmin, (req, res) => {
  let { page = 1, per_page = 60, q = "", state = "", status = "", year_min, year_max } = req.query;
  page = Math.max(Number(page) || 1, 1);
  per_page = Math.min(Math.max(Number(per_page) || 60, 1), 500);

  let items = db.data.pdfs.slice();
  if (q) {
    const needle = String(q).toLowerCase();
    items = items.filter((p) => String(p.title || "").toLowerCase().includes(needle) || String(p.state || "").toLowerCase().includes(needle));
  }
  if (state) { items = items.filter((p) => String(p.state || "").toLowerCase() === String(state).toLowerCase()); }
  if (status) { items = items.filter((p) => String(p.status || "") === String(status)); }
  const yMin = year_min ? Number(year_min) : 2000;
  const yMax = year_max ? Number(year_max) : 2007;
  items = items.filter((p) => Number(p.year) >= yMin && Number(p.year) <= yMax);

  const total = items.length;
  const start = (page - 1) * per_page;
  const pageItems = items.slice(start, start + per_page).map((p) => ({
    id: p.id, title: p.title, state: p.state, year: p.year, status: p.status, created_at: p.created_at, file_name: p.file_name,
  }));
  res.json({ total, page, per_page, items: pageItems });
});

/* ================== ADMIN PDF DELETION (helpers & routes) ================== */
async function removePdfById(id) {
  await db.read();
  const idx = db.data.pdfs.findIndex((p) => p.id === String(id));
  if (idx === -1) return { ok: false, id, reason: "Not found" };
  const p = db.data.pdfs[idx];
  try {
    if (p.file_name) {
      if (supabase) {
        try {
          await supabase.storage.from(SUPABASE_BUCKET).remove([p.file_name]);
        } catch (e) { /* ignore */ }
      } else {
        const fp = path.join(PDF_DIR, p.file_name);
        if (fs.existsSync(fp)) fs.unlinkSync(fp);
      }
    }
  } catch {}
  db.data.downloadTokens = db.data.downloadTokens.filter((t) => t.pdf_id !== p.id);
  db.data.pdfs.splice(idx, 1);
  await db.write();
  return { ok: true, id };
}
app.post("/api/admin/pdfs/delete", requireAuth, requireAdmin, async (req, res) => {
  const ids = Array.isArray(req.body?.ids) ? req.body.ids.map(String) : [];
  if (ids.length === 0) return res.status(400).json({ error: "ids (array) required" });
  const results = { removed: [], skipped: [] };
  for (const id of ids) {
    const r = await removePdfById(id);
    if (r.ok) results.removed.push(id);
    else results.skipped.push({ id, reason: r.reason || "Not found" });
  }
  res.json(results);
});
app.delete("/api/admin/pdfs", requireAuth, requireAdmin, async (req, res) => {
  const ids = String(req.query.ids || "").split(",").map(s => s.trim()).filter(Boolean);
  if (ids.length === 0) return res.status(400).json({ error: "ids query required" });
  const results = { removed: [], skipped: [] };
  for (const id of ids) {
    const r = await removePdfById(id);
    if (r.ok) results.removed.push(id);
    else results.skipped.push({ id, reason: r.reason || "Not found" });
  }
  res.json(results);
});
app.delete("/api/admin/pdfs/:id", requireAuth, requireAdmin, async (req, res) => {
  const r = await removePdfById(req.params.id);
  if (!r.ok) return res.status(404).json({ error: "Not found" });
  res.json({ ok: true, id: r.id });
});
app.delete("/api/admin/pdf/:id", requireAuth, requireAdmin, async (req, res) => {
  const r = await removePdfById(req.params.id);
  if (!r.ok) return res.status(404).json({ error: "Not found" });
  res.json({ ok: true, id: r.id });
});
app.post("/api/admin/pdfs/:id/delete", requireAuth, requireAdmin, async (req, res) => {
  const r = await removePdfById(req.params.id);
  if (!r.ok) return res.status(404).json({ error: "Not found" });
  res.json({ ok: true, id: r.id });
});

/* ---------- Uploads ---------- */
const uploadAny = uploadM.any();

// Single PDF upload (admin)
app.post("/api/admin/pdf", requireAuth, requireAdmin, uploadSingleFlexible, async (req, res) => {
  try {
    await db.read();
    const up = (req.files?.file && req.files.file[0]) || (req.files?.pdf && req.files.pdf[0]);
    const { title, state, year } = req.body || {};
    if (!up) return res.status(400).json({ error: "file required (PDF)" });
    if (!title || !state || !year) return res.status(400).json({ error: "title, state, year required" });
    if (!/^(2000|2001|2002|2003|2004|2005|2006|2007)$/.test(String(year))) return res.status(400).json({ error: "year must be 2000-2007" });

    const filename = nanoid() + path.extname(up.originalname).toLowerCase();

    // Upload to supabase if configured, otherwise fallback to local storage
    if (supabase) {
      try {
        await uploadToSupabase(up.path, filename, up.mimetype || "application/pdf");
      } catch (e) {
        console.error("Supabase upload failed (single):", e);
        // cleanup
        try { if (up?.path && fs.existsSync(up.path)) fs.unlinkSync(up.path); } catch {}
        return res.status(500).json({ error: "Failed to store file" });
      }
    } else {
      const dest = path.join(PDF_DIR, filename);
      try {
        await fs.promises.rename(up.path, dest);
      } catch (err) {
        await fs.promises.copyFile(up.path, dest);
        await fs.promises.unlink(up.path);
      }
    }

    const item = {
      id: nanoid(), title, state: String(state).toUpperCase(), year: Number(year),
      price_cents: PRICE_CENTS, status: "unsold", file_name: filename, created_at: nowISO(),
    };
    db.data.pdfs.push(item);
    await saveDb();
    res.json({ ok: true, pdf: { id: item.id, title: item.title } });
  } catch (e) {
    console.error("Single upload failed:", e);
    try { if (req.files) for (const f of Object.values(req.files).flat()) { if (f?.path && fs.existsSync(f.path)) fs.unlinkSync(f.path); } } catch {}
    res.status(500).json({ error: "Upload failed" });
  }
});

// Batch upload: multiple individual files (multipart form)
app.post("/api/admin/pdf-batch", requireAuth, requireAdmin, uploadAny, async (req, res) => {
  const release = await mutex.acquire();
  const results = { created: [], skipped: [], errors: [] };

  try {
    await db.read();
    db.data.pdfs ||= []; // ✅ Ensure array is always defined

    const files = Array.isArray(req.files) ? req.files : [];

    for (const file of files) {
      try {
        if (!/\.(pdf|png|jpg|jpeg)$/i.test(file.originalname)) {
          results.skipped.push({ file: file.originalname, reason: "Not a supported doc" });
          try { if (file?.path && fs.existsSync(file.path)) { await fs.promises.unlink(file.path); } } catch {}
          continue;
        }

        const meta = parseFilenameMeta(file.originalname);
        if (!meta) {
          results.skipped.push({ file: file.originalname, reason: "Could not parse Title/State/Year" });
          try { if (file?.path && fs.existsSync(file.path)) { await fs.promises.unlink(file.path); } } catch {}
          continue;
        }

        const filename = nanoid() + path.extname(file.originalname).toLowerCase();

        if (supabase) {
          try {
            await uploadToSupabase(file.path, filename, file.mimetype || "application/pdf");
          } catch (e) {
            console.error("Supabase upload failed (batch file):", file.originalname, e);
            results.errors.push({ file: file.originalname, error: String(e?.message || e) });
            try { if (file?.path && fs.existsSync(file.path)) await fs.promises.unlink(file.path); } catch {}
            continue;
          }
        } else {
          const dest = path.join(PDF_DIR, filename);
          try {
            await fs.promises.rename(file.path, dest);
          } catch (err) {
            await fs.promises.copyFile(file.path, dest);
            await fs.promises.unlink(file.path);
          }
        }

        const item = {
          id: nanoid(),
          title: meta.title,
          state: meta.state,
          year: meta.year,
          price_cents: PRICE_CENTS,
          status: "unsold",
          file_name: filename,
          created_at: nowISO(),
        };

        db.data.pdfs.push(item); // ✅ safe now
        results.created.push({ file: file.originalname, parsed: meta, id: item.id });
      } catch (e) {
        console.error("Batch upload error for", file?.originalname, e);
        results.errors.push({ file: file?.originalname || "unknown", error: String(e?.message || e) });
        try { if (file?.path && fs.existsSync(file.path)) { await fs.promises.unlink(file.path); } } catch {}
      }
    }

    await saveDb();
    return res.json(results);
  } catch (e) {
    console.error("Batch upload failed:", e);
    return res.status(500).json({ error: "Batch upload failed" });
  } finally {
    release();
  }
});

// ZIP batch upload: admin uploads a single zip (field name 'zip')
const uploadZip = uploadM.single("zip");

app.post("/api/admin/pdf-batch-zip", requireAuth, requireAdmin, uploadZip, async (req, res) => {
  const release = await mutex.acquire();
  try {
    if (!req.file) return res.status(400).json({ error: "zip file required (field 'zip')" });

    await db.read();
    db.data ||= {};
    db.data.pdfs ||= [];

    const results = { created: [], skipped: [], errors: [] };
    const zipPath = req.file.path;

    let directory;
    try {
      directory = await unzipper.Open.file(zipPath);
    } catch (err) {
      console.error("Failed to open uploaded ZIP:", err);
      try { if (zipPath && fs.existsSync(zipPath)) await fs.promises.unlink(zipPath); } catch {}
      return res.status(400).json({ error: "Invalid ZIP file" });
    }

    for (const entry of directory.files) {
      try {
        if (entry.type !== "File") continue;

        const originalname = entry.path;
        const basename = path.basename(originalname);
        const ext = path.extname(basename).toLowerCase();

        if (![".pdf", ".png", ".jpg", ".jpeg"].includes(ext)) {
          results.skipped.push({ file: originalname, reason: "Unsupported file in zip" });
          continue;
        }

        // write entry to temporary file then upload to supabase or move to local PDF_DIR
        const tempName = nanoid() + ext;
        const tempPath = path.join(TMP_DIR, tempName);

        await new Promise((resolve, reject) =>
          entry.stream()
            .pipe(fs.createWriteStream(tempPath))
            .on('finish', resolve)
            .on('error', reject)
        );

        const meta = parseFilenameMeta(basename);
        if (!meta) {
          results.skipped.push({ file: originalname, reason: "Could not parse Title/State/Year" });
          try { if (fs.existsSync(tempPath)) await fs.promises.unlink(tempPath); } catch {}
          continue;
        }

        const filename = nanoid() + ext;
        if (supabase) {
          try {
            await uploadToSupabase(tempPath, filename, 'application/pdf');
          } catch (e) {
            console.error("Supabase upload failed (zip entry):", originalname, e);
            results.errors.push({ file: originalname, error: String(e?.message || e) });
            try { if (fs.existsSync(tempPath)) await fs.promises.unlink(tempPath); } catch {}
            continue;
          }
        } else {
          const dest = path.join(PDF_DIR, filename);
          try { await fs.promises.rename(tempPath, dest); } catch (err) { await fs.promises.copyFile(tempPath, dest); await fs.promises.unlink(tempPath); }
        }

        const item = {
          id: nanoid(), title: meta.title, state: meta.state, year: meta.year,
          price_cents: PRICE_CENTS, status: "unsold", file_name: filename, created_at: nowISO(),
        };
        db.data.pdfs.push(item);
        results.created.push({ file: originalname, parsed: meta, id: item.id });
      } catch (e) {
        console.error("ZIP entry error:", entry?.path, e);
        results.errors.push({ file: entry?.path || "unknown", error: String(e?.message || e) });
      }
    }
    try { if (zipPath && fs.existsSync(zipPath)) await fs.promises.unlink(zipPath); } catch {}
    await saveDb();
    res.json(results);
  } catch (e) {
    console.error("ZIP upload failed:", e);
    try { if (req.file?.path && fs.existsSync(req.file.path)) await fs.promises.unlink(req.file.path); } catch {}
    res.status(500).json({ error: "ZIP upload failed" });
  } finally {
    release();
  }
});

/* ===================== CONTACT → INBOX ===================== */
function sanitizeMessage(s) {
  if (!s) return "";
  const str = String(s);
  return str.slice(0, 5000);
}

app.delete("/api/admin/inbox/:id", requireAuth, requireAdmin, async (req, res) => {
  const id = String(req.params.id);
  const idx = db.data.inbox.findIndex((x) => x.id === id);
  if (idx === -1) return res.status(404).json({ error: "Not found" });
  const [removed] = db.data.inbox.splice(idx, 1);
  await saveDb();
  res.json({ ok: true, removed: { id: removed.id, email: removed.email } });
});


/* ========= CHAT ROUTES ========= */
app.post("/api/chat/send", requireAuth, (req, res) => {
  const text = String(req.body?.text || "").trim();
  if (!text) return res.status(400).json({ error: "text required" });
  const msg = pushMessage({ user_id: req.user.id, from: "user", text });
  res.json({ ok: true, message: msg });
});
app.get("/api/chat/history", requireAuth, (req, res) => {
  const limit = Math.min(Math.max(Number(req.query.limit) || 200, 1), 1000);
  let items = db.data.chats.filter((m) => m.user_id === req.user.id);
  items = items.sort((a, b) => new Date(a.created_at) - new Date(b.created_at));
  res.json({ items: items.slice(-limit) });
});
app.get("/api/chat/stream", requireAuth, (req, res) => {
  res.writeHead(200, { "Content-Type": "text/event-stream", "Cache-Control": "no-cache, no-transform", Connection: "keep-alive" });
  sseSend(res, "hello", { ok: true, user_id: req.user.id });
  const uid = req.user.id;
  if (!userStreams.has(uid)) userStreams.set(uid, new Set());
  userStreams.get(uid).add(res);
  const keepAlive = setInterval(() => ssePing(res), 15000);
  req.on("close", () => {
    clearInterval(keepAlive);
    const set = userStreams.get(uid);
    if (set) { set.delete(res); if (set.size === 0) userStreams.delete(uid); }
  });
});
app.get("/api/admin/chat/:userId/history", requireAuth, requireAdmin, (req, res) => {
  const userId = String(req.params.userId);
  const limit = Math.min(Math.max(Number(req.query.limit) || 1000, 1), 5000);
  let items = db.data.chats.filter((m) => m.user_id === userId);
  items = items.sort((a, b) => new Date(a.created_at) - new Date(b.created_at));
  res.json({ items: items.slice(-limit) });
});
app.post("/api/admin/chat/:userId/send", requireAuth, requireAdmin, (req, res) => {
  const userId = String(req.params.userId);
  const u = db.data.users.find((x) => x.id === userId);
  if (!u) return res.status(404).json({ error: "User not found" });
  const text = String(req.body?.text || "").trim();
  if (!text) return res.status(400).json({ error: "text required" });
  const msg = pushMessage({ user_id: userId, from: "admin", text });
  res.json({ ok: true, message: msg });
});
app.get("/api/admin/chat/stream", requireAuth, requireAdmin, (req, res) => {
  res.writeHead(200, { "Content-Type": "text/event-stream", "Cache-Control": "no-cache, no-transform", Connection: "keep-alive" });
  sseSend(res, "hello", { ok: true, admin: true });
  adminStreams.add(res);
  const keepAlive = setInterval(() => ssePing(res), 15000);
  req.on("close", () => { clearInterval(keepAlive); adminStreams.delete(res); });
});

/* ------------- Health & bootstrap ------------- */
app.get("/api/health", (req, res) =>
  res.json({ ok: true, time: new Date().toISOString() })
);
app.get("/", (req, res) =>
  res.json({ ok: true, app: "Panda PDF API", try: "/api/health" })
);

/* ---------- Serve built SPA (web/dist) ---------- */
const clientDir = process.env.CLIENT_DIR || path.join(__dirname, "../web/dist");
const clientIndex = path.join(clientDir, "index.html");

if (fs.existsSync(clientIndex)) {
  app.use(express.static(clientDir));
  app.get(/^(?!\/api).+/, (req, res) => res.sendFile(clientIndex));
} else {
  app.get(/^(?!\/api).+/, (req, res) => {
    res.status(200).send("Frontend is hosted separately. Visit the Netlify site.");
  });
}

/* ------------ FINAL: /api catch-all 404 (LAST) ------------ */
app.use("/api", (req, res) => {
  res.status(404).json({ error: "Not found", path: req.originalUrl });
});

app.listen(PORT, "0.0.0.0", () =>
  console.log(`API listening on 0.0.0.0:${PORT}`)
);
