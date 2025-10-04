// server.js - Panda API (all data in Supabase)
// Notes:
// - Supply env vars in .env (no secrets inline!)
// - Requires the following tables (default names, override with envs):
//   pdfs, users, transactions, reset_tokens, download_tokens, inbox, chats
// - Storage bucket (default): pdf
//
// Env (common):
// PORT, SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY
// SUPABASE_BUCKET=pdf
// SUPABASE_STORAGE_PREFIX= (optional folder prefix)
// SUPABASE_TABLE_PDFS=pdfs
// SUPABASE_TABLE_USERS=users
// SUPABASE_TABLE_TX=transactions
// SUPABASE_TABLE_RESET=reset_tokens
// SUPABASE_TABLE_DLTOK=download_tokens
// SUPABASE_TABLE_INBOX=inbox
// SUPABASE_TABLE_CHATS=chats
// JWT_SECRET, CORS_ORIGINS
// SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS (optional)
// NOWPAY_API_KEY, NOWPAY_IPN_SECRET (optional)
// PUBLIC_BASE_URL, PUBLIC_API_URL (optional)
// CLIENT_DIR (optional)

import os from "os";
import express from "express";
import cors from "cors";
import helmet from "helmet";
import dotenv from "dotenv";
import fs from "fs";
import path from "path";
import crypto from "crypto";
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

/* ---------------- Basic hardening & CORS ---------------- */
app.set("trust proxy", true);
app.use(
  helmet({
    crossOriginEmbedderPolicy: false,
    crossOriginOpenerPolicy: { policy: "same-origin" },
    crossOriginResourcePolicy: { policy: "cross-origin" },
  })
);

const RAW_ALLOWED =
  process.env.CORS_ORIGINS ||
  "http://localhost:5173,https://sprightly-cannoli-74fc49.netlify.app";
const ALLOWED = RAW_ALLOWED.split(",").map((s) => s.trim()).filter(Boolean);

const corsOptions = {
  origin: (origin, cb) => {
    if (!origin) return cb(null, true);
    if (ALLOWED.length === 0) return cb(null, true);
    const norm = origin.replace(/\/+$/, "");
    const ok = ALLOWED.some(a => a.replace(/\/+$/, "") === norm);
    return ok ? cb(null, true) : cb(new Error(`CORS blocked for origin: ${origin}`));
  },
  credentials: true,
  // widened slightly to make preflights happy without changing logic
  allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With", "Accept"],
  methods: ["GET", "POST", "DELETE", "PUT", "PATCH", "OPTIONS"],
};
app.use(cors(corsOptions));
app.options("*", cors(corsOptions));
app.use(express.json({ limit: "5mb" }));
app.use(express.urlencoded({ extended: true, limit: "5mb" }));

const PORT = process.env.PORT || 5062;

/* ---------------- Ensure storage dirs (only for local temp + admin fallback) ---------------- */
const STORAGE_ROOT = path.join(__dirname, "storage");
const TMP_DIR = path.join(STORAGE_ROOT, "tmp");
const PDF_DIR = path.join(STORAGE_ROOT, "pdfs");
for (const d of [STORAGE_ROOT, TMP_DIR, PDF_DIR]) {
  try { fs.mkdirSync(d, { recursive: true }); } catch {}
}
app.use("/files", express.static(PDF_DIR));

/* ---------------- Helpers ---------------- */
const PRICE_CENTS = 499;
const mutex = new Mutex();
const nowISO = () => new Date().toISOString();
const cents = (n) => Math.round(Number(n || 0));
const publicBase = (req) => {
  if (process.env.PUBLIC_BASE_URL) return process.env.PUBLIC_BASE_URL.replace(/\/+$/, "");
  const proto = (req.headers["x-forwarded-proto"] || req.protocol || "http").split(",")[0].trim();
  const host = req.headers["x-forwarded-host"] || req.headers.host || `localhost:${PORT}`;
  return `${proto}://${host}`;
};
const getJwtFromReq = (req) => {
  const auth = req.headers.authorization || "";
  if (auth.startsWith("Bearer ")) return auth.slice(7);
  if (typeof req.query?.jwt === "string" && req.query.jwt.length > 10) return req.query.jwt;
  return null;
};
// NEW: strict UUID check used to prevent uuid-cast errors
const isUuid = (s) =>
  typeof s === "string" &&
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(s);

/* ---------------- Supabase init & table/bucket names ---------------- */
const SUPABASE_URL = process.env.SUPABASE_URL || "";
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || "";
const SUPABASE_BUCKET = process.env.SUPABASE_BUCKET || "pdf";
const SUPABASE_PREFIX = process.env.SUPABASE_STORAGE_PREFIX || "";

const T_PDFS = process.env.SUPABASE_TABLE_PDFS || "pdfs";
const T_USERS = process.env.SUPABASE_TABLE_USERS || "users";
const T_TX = process.env.SUPABASE_TABLE_TX || "transactions";
const T_RESET = process.env.SUPABASE_TABLE_RESET || "reset_tokens";
const T_DLTOK = process.env.SUPABASE_TABLE_DLTOK || "download_tokens";
const T_INBOX = process.env.SUPABASE_TABLE_INBOX || "inbox";
const T_CHATS = process.env.SUPABASE_TABLE_CHATS || "chats";

if (!SUPABASE_URL || !SUPABASE_KEY) {
  console.error("Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY");
  process.exit(1);
}
const supabase = createClient(SUPABASE_URL, SUPABASE_KEY, { auth: { persistSession: false } });

/* ---------------- filename parsing ---------------- */
const US_STATES = new Set([
  "AL","AK","AZ","AR","CA","CO","CT","DE","FL","GA","HI","ID","IL","IN","IA","KS","KY","LA","ME","MD","MA","MI","MN",
  "MS","MO","MT","NE","NV","NH","NJ","NM","NY","NC","ND","OH","OK","OR","PA","RI","SC","SD","TN","TX","UT","VT","VA",
  "WA","WV","WI","WY"
]);
const cap = (s) => (!s ? "" : s.charAt(0).toUpperCase() + s.slice(1).toLowerCase());
function parseFilenameMeta(originalName) {
  const base = String(originalName).replace(/\.(pdf|png|jpg|jpeg)$/i, "").trim();
  // "<title>-<ST>-<2000..2007>"
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
  // "first_last_ST_YYYY" or "first_last_YYYY" (and YYYYMMDD ending)
  const parts = base.split("_").map((p) => p.trim()).filter(Boolean);
  if (parts.length >= 3) {
    const lastPart = parts[parts.length - 1];
    if (/^\d{8}$/.test(lastPart)) {
      const nameParts = parts.slice(0, parts.length - 1);
      if (nameParts.length >= 2) {
        const first = cap(nameParts[0]);
        const last = cap(nameParts[nameParts.length - 1] || parts[1]);
        const y = lastPart.slice(0, 4), mm = lastPart.slice(4, 6), dd = lastPart.slice(6, 8);
        const iso = `${y}-${mm}-${dd}`;
        const dt = new Date(iso);
        if (!Number.isNaN(dt.getTime())) return { title: `${first} ${last}`, state: null, year: Number(y), dobISO: iso };
      }
    }
    if (/^\d{4}$/.test(lastPart)) {
      const y = Number(lastPart);
      if (y >= 1900 && y <= 2100) {
        for (let i = 1; i < parts.length - 1; i++) {
          const cand = parts[i].toUpperCase();
          if (US_STATES.has(cand)) {
            const nameParts = parts.slice(0, i);
            const title = `${cap(nameParts[0])} ${cap(nameParts[nameParts.length - 1] || parts[1])}`.trim();
            return { title, state: cand, year: y };
          }
        }
        if (parts.length >= 2) return { title: `${cap(parts[0])} ${cap(parts[1])}`, state: null, year: y };
      }
    }
  }
  return null;
}

/* ---------------- Supabase helpers ---------------- */
const normalizePdfRow = (row = {}) => ({
  id: String(row.id || row._id || row.uuid || nanoid()),
  title: String(row.title || "").trim(),
  state: row.state == null ? "" : String(row.state).toUpperCase(),
  year: row.year == null ? null : Number(row.year),
  price_cents: Number(row.price_cents || row.price || PRICE_CENTS) || PRICE_CENTS,
  status: String(row.status ?? "unsold").toLowerCase(),
  file_name: row.file_name || row.filename || "",
  storage_path: row.storage_path || (row.file_name ? (SUPABASE_PREFIX ? `${SUPABASE_PREFIX}/${row.file_name}` : row.file_name) : ""),
  created_at: row.created_at || row.createdAt || null,
  sold_at: row.sold_at || row.soldAt || null,
  buyer_user_id: row.buyer_user_id || row.buyer || null,
  raw: row,
});

async function uploadFileBufferToSupabase(localPath, destFilename) {
  const bucket = SUPABASE_BUCKET;
  const prefix = SUPABASE_PREFIX || "";
  const destPath = prefix ? `${prefix}/${destFilename}` : `${destFilename}`;
  const buf = await fs.promises.readFile(localPath);
  const ext = path.extname(destFilename || "").toLowerCase();
  let contentType = "application/octet-stream";
  if (ext === ".pdf") contentType = "application/pdf";
  else if (ext === ".png") contentType = "image/png";
  else if (ext === ".jpg" || ext === ".jpeg") contentType = "image/jpeg";
  const { error } = await supabase.storage.from(bucket).upload(destPath, buf, { upsert: false, contentType });
  if (error) throw error;
  return destPath;
}

/* ADDED: only_available flag to ensure buyer_user_id IS NULL when needed */
async function queryPdfsFromDb({
  state,
  year_min = null,
  year_max = null,
  page = 1,
  per_page = 100,
  status = "unsold",
  q = "",
  only_available = false, // NEW
} = {}) {
  const pg = Math.max(Number(page) || 1, 1);
  const pp = Math.min(Math.max(Number(per_page) || 100, 1), 500);

  let query = supabase.from(T_PDFS).select("*", { count: "exact" });

  if (status) {
    const s = String(status).toLowerCase();
    query = query.in("status", [s, s.toUpperCase(), s.charAt(0).toUpperCase() + s.slice(1)]);
  }
  if (only_available) {
    query = query.is("buyer_user_id", null); // critical guard
  }
  if (state) query = query.eq("state", String(state).toUpperCase());
  if (year_min != null) query = query.gte("year", Number(year_min));
  if (year_max != null) query = query.lte("year", Number(year_max));
  if (q) query = query.ilike("title", `%${q}%`);

  const from = (pg - 1) * pp;
  const to = from + pp - 1;
  const { data, count, error } = await query.range(from, to);
  if (error) throw error;
  const items = (data || []).map(normalizePdfRow);
  return { total: count ?? items.length, items };
}

async function fetchPdfByIdFromDb(id) {
  const { data, error } = await supabase.from(T_PDFS).select("*").eq("id", id).single();
  if (error) return null;
  return normalizePdfRow(data);
}

/* ---------- Users (Supabase) ---------- */
async function findUserByEmail(email) {
  const { data, error } = await supabase.from(T_USERS).select("*").ilike("email", email).maybeSingle();
  if (error) throw error;
  return data || null;
}
async function getUserById(id) {
  const { data, error } = await supabase.from(T_USERS).select("*").eq("id", id).single();
  if (error) return null;
  return data;
}
// CHANGED: generate UUIDs for user ids (matches buyer_user_id uuid column)
async function createUser({ name, email, password_hash }) {
  const row = { id: crypto.randomUUID(), name, email, password_hash, balance_cents: 0, is_admin: false, created_at: nowISO() };
  const { data, error } = await supabase.from(T_USERS).insert(row).select().single();
  if (error) throw error;
  return data;
}
async function updateUser(id, patch) {
  const { data, error } = await supabase.from(T_USERS).update(patch).eq("id", id).select().single();
  if (error) throw error;
  return data;
}

/* ---------- Transactions / Tokens / Inbox / Chats ---------- */
async function insertTransaction(row) {
  const { data, error } = await supabase.from(T_TX).insert(row).select().single();
  if (error) throw error;
  return data;
}
async function listTransactions(limit = 500) {
  const { data, error } = await supabase.from(T_TX).select("*").order("created_at", { ascending: false }).limit(limit);
  if (error) throw error;
  return data || [];
}

/* ------------- FIXED: token helpers (store timestamps as ISO strings) ------------- */
async function createResetToken({ token, user_id, expires_at }) {
  const expISO = typeof expires_at === "number" ? new Date(expires_at).toISOString() : String(expires_at);
  const { error } = await supabase.from(T_RESET).insert({ token, user_id, expires_at: expISO });
  if (error) throw error;
}
async function consumeValidResetToken(token) {
  const { data, error } = await supabase.from(T_RESET).select("*").eq("token", token).single();
  if (error || !data) return null;
  const expMs = typeof data.expires_at === "number" ? data.expires_at : Date.parse(data.expires_at);
  if (!expMs || Date.now() > expMs) {
    await supabase.from(T_RESET).delete().eq("token", token);
    return null;
  }
  await supabase.from(T_RESET).delete().eq("token", token);
  return data;
}
async function createDownloadToken({ token, user_id, pdf_id, expires_at }) {
  const expISO = typeof expires_at === "number" ? new Date(expires_at).toISOString() : String(expires_at);
  const { error } = await supabase.from(T_DLTOK).insert({ token, user_id, pdf_id, expires_at: expISO });
  if (error) throw error;
}
async function takeDownloadToken(token) {
  const { data, error } = await supabase.from(T_DLTOK).select("*").eq("token", token).single();
  if (error || !data) return null;
  const expMs = typeof data.expires_at === "number" ? data.expires_at : Date.parse(data.expires_at);
  if (!expMs || Date.now() > expMs) {
    await supabase.from(T_DLTOK).delete().eq("token", token);
    return null;
  }
  await supabase.from(T_DLTOK).delete().eq("token", token); // one-time
  return data;
}

async function inboxInsert({ name, email, message, source }) {
  const row = { id: nanoid(), name, email, message, source, read: false, archived: false, created_at: nowISO() };
  const { data, error } = await supabase.from(T_INBOX).insert(row).select().single();
  if (error) throw error;
  return data;
}
async function inboxList({ q = "", status = "all", page = 1, per_page = 50 }) {
  let query = supabase.from(T_INBOX).select("*", { count: "exact" });
  if (status === "unread") query = query.eq("read", false).eq("archived", false);
  else if (status === "archived") query = query.eq("archived", true);
  if (q) {
    const { data, error } = await query.order("created_at", { ascending: false }).limit(2000);
    if (error) throw error;
    const term = q.toLowerCase();
    const filtered = (data || []).filter(
      (m) =>
        String(m.name || "").toLowerCase().includes(term) ||
        String(m.email || "").toLowerCase().includes(term) ||
        String(m.message || "").toLowerCase().includes(term)
    );
    const start = (page - 1) * per_page;
    return { total: filtered.length, items: filtered.slice(start, start + per_page) };
  } else {
    const from = (page - 1) * per_page;
    const to = from + per_page - 1;
    const { data, count, error } = await query.order("created_at", { ascending: false }).range(from, to);
    if (error) throw error;
    return { total: count ?? (data || []).length, items: data || [] };
  }
}
async function inboxPatch(id, patch) {
  const { data, error } = await supabase.from(T_INBOX).update(patch).eq("id", id).select().single();
  if (error) throw error;
  return data;
}
async function inboxDelete(id) {
  const { error } = await supabase.from(T_INBOX).delete().eq("id", id);
  if (error) throw error;
}
async function chatInsert({ user_id, from, text }) {
  const row = { id: nanoid(), user_id, from, text, created_at: nowISO() };
  const { data, error } = await supabase.from(T_CHATS).insert(row).select().single();
  if (error) throw error;
  return data;
}
async function chatListForUser(user_id, limit = 1000) {
  const { data, error } = await supabase
    .from(T_CHATS)
    .select("*")
    .eq("user_id", user_id)
    .order("created_at", { ascending: true })
    .limit(limit);
  if (error) throw error;
  return data || [];
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
const sseSend = (res, event, data) => {
  res.write(`event: ${event}\n`);
  res.write(`data: ${JSON.stringify(data)}\n\n`);
};
const ssePing = (res) => { res.write(`: ping\n\n`); };
async function pushMessage({ user_id, from, text }) {
  const msg = await chatInsert({ user_id, from, text: String(text || "").slice(0, MAX_TEXT) });
  const bucket = userStreams.get(user_id);
  if (bucket) for (const r of bucket) sseSend(r, "message", msg);
  for (const r of adminStreams) sseSend(r, "message", msg);
  return msg;
}

/* ---------------- Auth (register/login/me) ---------------- */
app.post("/api/auth/register", async (req, res) => {
  try {
    const { name, email, password } = req.body || {};
    if (!name || !email || !password) return res.status(400).json({ error: "name, email, password required" });
    const existing = await findUserByEmail(String(email).toLowerCase());
    if (existing) return res.status(409).json({ error: "Email already registered" });

    const password_hash = await bcrypt.hash(password, 10);
    const user = await createUser({ name, email, password_hash }); // UUID id
    const token = jwt.sign({ id: user.id, email: user.email, is_admin: !!user.is_admin }, process.env.JWT_SECRET || "dev_secret", { expiresIn: "7d" });
    res.json({ token, user: { id: user.id, name: user.name, email: user.email, balance_cents: user.balance_cents || 0, is_admin: !!user.is_admin } });
  } catch (e) {
    console.error("/api/auth/register error:", e?.message || e);
    res.status(500).json({ error: "Registration failed" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    const user = await findUserByEmail(String(email || "").toLowerCase());
    if (!user) return res.status(401).json({ error: "Invalid credentials" });
    const ok = await bcrypt.compare(password || "", user.password_hash || "");
    if (!ok) return res.status(401).json({ error: "Invalid credentials" });
    const token = jwt.sign({ id: user.id, email: user.email, is_admin: !!user.is_admin }, process.env.JWT_SECRET || "dev_secret", { expiresIn: "7d" });
    res.json({ token, user: { id: user.id, name: user.name, email: user.email, balance_cents: user.balance_cents || 0, is_admin: !!user.is_admin } });
  } catch (e) {
    console.error("/api/auth/login error:", e?.message || e);
    res.status(500).json({ error: "Login failed" });
  }
});

app.get("/api/me", requireAuth, async (req, res) => {
  try {
    const u = await getUserById(req.user.id);
    if (!u) return res.status(404).json({ error: "Not found" });
    res.json({ id: u.id, name: u.name, email: u.email, balance_cents: u.balance_cents || 0, is_admin: !!u.is_admin });
  } catch (e) {
    console.error("/api/me error:", e?.message || e);
    res.status(500).json({ error: "Failed to fetch user" });
  }
});

/* -------- Password reset -------- */
app.post("/api/auth/forgot", async (req, res) => {
  try {
    const { email } = req.body || {};
    if (!email) return res.status(400).json({ error: "email required" });
    const user = await findUserByEmail(String(email).toLowerCase());
    const token = nanoid();
    const expires_at = Date.now() + 60 * 60 * 1000;

    if (user) {
      await supabase.from(T_RESET).delete().eq("user_id", user.id);
      await createResetToken({ token, user_id: user.id, expires_at });

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
        } catch (e) {
          console.error("SMTP send error:", e?.message || e);
        }
      }
    }
    res.json({ ok: true, token, expires_at });
  } catch (e) {
    console.error("/api/auth/forgot error:", e?.message || e);
    res.status(500).json({ error: "Failed to process forgot request" });
  }
});

app.post("/api/auth/reset", async (req, res) => {
  try {
    const { token, new_password } = req.body || {};
    if (!token || !new_password) return res.status(400).json({ error: "token and new_password required" });

    const rec = await consumeValidResetToken(token);
    if (!rec) return res.status(400).json({ error: "Invalid or expired token" });

    const user = await getUserById(rec.user_id);
    if (!user) return res.status(400).json({ error: "User not found" });

    const password_hash = await bcrypt.hash(new_password, 10);
    await updateUser(user.id, { password_hash });
    res.json({ ok: true });
  } catch (e) {
    console.error("/api/auth/reset error:", e?.message || e);
    res.status(500).json({ error: "Reset failed" });
  }
});

/* ------------- Storefront (Supabase) ------------- */
app.get("/api/pdfs", async (req, res) => {
  try {
    const { state, year_min, year_max, page = 1, per_page = 100, q = "" } = req.query;
    const result = await queryPdfsFromDb({
      state,
      year_min: year_min ? Number(year_min) : null,
      year_max: year_max ? Number(year_max) : null,
      page: Number(page),
      per_page: Number(per_page),
      status: "unsold",
      q,
      only_available: true, // ensure buyer_user_id IS NULL
    });
    const items = (result.items || []).map((p) => ({
      id: p.id, title: p.title, state: p.state || "", year: p.year,
      price_cents: p.price_cents ?? PRICE_CENTS, file_name: p.file_name || "", storage_path: p.storage_path || "",
    }));
    return res.json({ total: result.total, page: Number(page), per_page: Number(per_page), items });
  } catch (e) {
    console.error("GET /api/pdfs error:", e?.message || e);
    res.status(500).json({ error: "Failed to fetch PDFs" });
  }
});

app.get("/api/inventory/count", async (_req, res) => {
  try {
    const { count, error } = await supabase
      .from(T_PDFS)
      .select("id", { count: "exact" })
      .in("status", ["unsold", "UNSOLD", "Unsold"])
      .is("buyer_user_id", null); // only truly available
    if (error) throw error;
    res.json({ remaining: count ?? 0 });
  } catch (e) {
    console.error("inventory count supabase error:", e?.message || e);
    res.status(500).json({ error: "Failed to count inventory" });
  }
});

/* ---------------- Library ---------------- */
// NEW: avoid uuid cast error for legacy nanoid accounts
app.get("/api/me/library", requireAuth, async (req, res) => {
  try {
    if (!isUuid(req.user.id)) return res.json({ items: [] });
    const { data, error } = await supabase
      .from(T_PDFS)
      .select("*")
      .eq("buyer_user_id", req.user.id)
      .order("sold_at", { ascending: false });
    if (error) throw error;
    const items = (data || []).map(normalizePdfRow).map((p) => ({
      id: p.id, title: p.title, state: p.state, year: p.year, price_cents: p.price_cents, storage_path: p.storage_path,
    }));
    res.json({ items });
  } catch (e) {
    console.error("/api/me/library error:", e?.message || e);
    res.status(500).json({ error: "Failed to fetch library" });
  }
});
app.get("/api/library", requireAuth, async (req, res) => {
  try {
    if (!isUuid(req.user.id)) return res.json({ items: [] });
    const { data, error } = await supabase
      .from(T_PDFS)
      .select("*")
      .eq("buyer_user_id", req.user.id)
      .order("sold_at", { ascending: false });
    if (error) throw error;
    const items = (data || []).map(normalizePdfRow).map((p) => ({
      id: p.id, title: p.title, state: p.state, year: p.year, price_cents: p.price_cents, storage_path: p.storage_path,
    }));
    res.json({ items });
  } catch (e) {
    console.error("/api/library error:", e?.message || e);
    res.status(500).json({ error: "Failed to fetch library" });
  }
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

    await insertTransaction({
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

    res.json({ invoice_url: data.invoice_url || data.url || null, invoice: data });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Failed to create invoice" });
  }
});

app.post("/api/now/webhook", express.json({ type: "*/*" }), async (req, res) => {
  try {
    const ipnSecret = process.env.NOWPAY_IPN_SECRET || "";
    const signature = String(req.headers["x-nowpayments-sig"] || "");
    const body = req.body || {};
    const signedStr = JSON.stringify(body, Object.keys(body).sort());
    const hmac = crypto.createHmac("sha512", ipnSecret).update(signedStr).digest("hex");
    if (!ipnSecret || !signature || hmac !== signature) return res.status(401).json({ error: "Bad signature" });

    const status = String(body.payment_status || body.invoice_status || "").toLowerCase();
    const orderId = body.order_id || body.orderId;
    const priceAmount = Number(body.price_amount || body.priceAmount || 0);
    const ok = ["confirmed", "finished"].includes(status);

    if (ok && orderId) {
      const { data: txs } = await supabase.from(T_TX).select("*").eq("provider_order_id", orderId).eq("type", "deposit").limit(1);
      const tx = txs && txs[0];
      if (tx && tx.status !== "completed") {
        const user = await getUserById(tx.user_id);
        if (user) {
          const newBal = cents(user.balance_cents) + Math.round(priceAmount * 100);
          await updateUser(user.id, { balance_cents: newBal });
          await supabase.from(T_TX).update({ status: "completed", updated_at: nowISO(), raw_last: body }).eq("id", tx.id);
        }
      }
    }
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.json({ ok: true });
  }
});

/* ------------------ PURCHASE (single + bulk) ------------------ */
async function getPdfById(id) {
  return await fetchPdfByIdFromDb(String(id));
}

// Single purchase with optimistic locking
app.post("/api/purchase/single/:pdfId", requireAuth, async (req, res) => {
  // NEW: fail fast for legacy non-UUID users
  if (!isUuid(req.user.id)) {
    return res.status(400).json({ error: "This account cannot purchase until upgraded to a UUID user. Please create a new account." });
  }
  const release = await mutex.acquire();
  try {
    const pdfId = String(req.params.pdfId || "");
    if (!pdfId) return res.status(400).json({ error: "pdfId required" });

    let pdf = await getPdfById(pdfId);
    if (!pdf) return res.status(404).json({ error: "PDF not found" });

    // ensure not already owned
    if ((pdf.status ?? "unsold").toString().toLowerCase() !== "unsold" || pdf.buyer_user_id) {
      return res.status(409).json({ error: "PDF not available" });
    }

    const user = await getUserById(req.user.id);
    if (!user) return res.status(401).json({ error: "User not found" });

    const isAdmin = !!req.user.is_admin;
    const price = Number(pdf.price_cents || PRICE_CENTS);

    // Check balance (non-admin)
    let newBalance = user.balance_cents || 0;
    if (!isAdmin) {
      if (Number(newBalance) < price) return res.status(400).json({ error: "Insufficient balance" });
      newBalance = Math.max(0, Math.round(Number(newBalance) - price));
    }

    const sold_at = nowISO();

    // Mark PDF sold ONLY if still unsold and unowned
    const { data: soldRow, error: updErr } = await supabase
      .from(T_PDFS)
      .update({ status: "sold", buyer_user_id: user.id, sold_at })
      .eq("id", pdf.id)
      .in("status", ["unsold", "UNSOLD", "Unsold"])
      .is("buyer_user_id", null)
      .select()
      .maybeSingle();

    if (updErr) throw updErr;
    if (!soldRow) return res.status(409).json({ error: "PDF not available" });

    // Update user balance (if needed)
    if (!isAdmin) await updateUser(user.id, { balance_cents: newBalance });

    // Record transaction
    await insertTransaction({
      id: nanoid(),
      user_id: user.id,
      type: "purchase",
      pdf_id: pdf.id,
      amount_cents: price,
      currency: "USD",
      status: "completed",
      created_at: nowISO(),
    });

    const normalized = normalizePdfRow(soldRow);
    return res.json({
      ok: true,
      pdf: {
        id: normalized.id,
        title: normalized.title,
        state: normalized.state,
        year: normalized.year,
        storage_path:
          normalized.storage_path ||
          (normalized.file_name
            ? SUPABASE_PREFIX
              ? `${SUPABASE_PREFIX}/${normalized.file_name}`
              : normalized.file_name
            : ""),
      },
      new_balance_cents: isAdmin ? (user.balance_cents || 0) : newBalance,
      supabase_synced: true,
    });
  } catch (e) {
    console.error("purchase single error:", e?.message || e);
    return res.status(500).json({ error: "Purchase failed" });
  } finally {
    release();
  }
});

// Bulk purchase (best-effort; stops when balance insufficient)
app.post("/api/purchase/bulk", requireAuth, async (req, res) => {
  // NEW: fail fast for legacy non-UUID users
  if (!isUuid(req.user.id)) {
    return res.status(400).json({ error: "This account cannot purchase until upgraded to a UUID user. Please create a new account." });
  }
  const release = await mutex.acquire();
  try {
    const ids = Array.isArray(req.body?.pdf_ids) ? req.body.pdf_ids.map(String) : [];
    if (ids.length === 0) return res.status(400).json({ error: "pdf_ids required" });

    const user = await getUserById(req.user.id);
    if (!user) return res.status(401).json({ error: "User not found" });

    const isAdmin = !!req.user.is_admin;
    let balance = Number(user.balance_cents || 0);

    const purchased_ids = [];
    const skipped_ids = [];

    // Pre-fetch
    const pdfLookups = await Promise.all(ids.map((id) => getPdfById(id)));
    const pairs = ids.map((id, i) => ({ id, pdf: pdfLookups[i] }));

    for (const { id, pdf } of pairs) {
      if (!pdf) { skipped_ids.push({ id, reason: "Not found" }); continue; }

      // ensure both unsold and unowned
      if ((pdf.status ?? "unsold").toString().toLowerCase() !== "unsold" || pdf.buyer_user_id) {
        skipped_ids.push({ id, reason: "Not available" }); continue;
      }

      const price = Number(pdf.price_cents || PRICE_CENTS);
      if (!isAdmin && balance < price) { skipped_ids.push({ id, reason: "Insufficient funds" }); continue; }

      const sold_at = nowISO();
      const { data: soldRow } = await supabase
        .from(T_PDFS)
        .update({ status: "sold", buyer_user_id: user.id, sold_at })
        .eq("id", pdf.id)
        .in("status", ["unsold", "UNSOLD", "Unsold"])
        .is("buyer_user_id", null)
        .select()
        .maybeSingle();

      if (!soldRow) { skipped_ids.push({ id, reason: "Just sold by someone else" }); continue; }

      await insertTransaction({
        id: nanoid(),
        user_id: user.id,
        type: "purchase",
        pdf_id: pdf.id,
        amount_cents: price,
        currency: "USD",
        status: "completed",
        created_at: nowISO(),
      });

      if (!isAdmin) balance = Math.max(0, Math.round(balance - price));
      purchased_ids.push({ id: pdf.id, title: pdf.title || "" });
    }

    if (!isAdmin) await updateUser(user.id, { balance_cents: balance });

    return res.json({ ok: true, purchased: purchased_ids, skipped: skipped_ids, new_balance_cents: isAdmin ? (user.balance_cents || 0) : balance });
  } catch (e) {
    console.error("Bulk purchase error:", e?.message || e);
    return res.status(500).json({ error: "Bulk purchase failed" });
  } finally {
    release();
  }
});

/* ------------- Downloads ------------- */
app.post("/api/download/token/:pdfId", requireAuth, async (req, res) => {
  try {
    const pdf = await fetchPdfByIdFromDb(req.params.pdfId);
    if (!pdf) return res.status(404).json({ error: "Not found" });
    if (!req.user.is_admin && pdf.buyer_user_id !== req.user.id) return res.status(403).json({ error: "Purchase required" });

    const token = nanoid();
    const expires_at = Date.now() + 5 * 60 * 1000;
    await createDownloadToken({ token, user_id: req.user.id, pdf_id: pdf.id, expires_at });

    const url = `${publicBase(req)}/api/download/${token}`;
    res.json({ token, expires_at, url });
  } catch (e) {
    console.error("/api/download/token error:", e?.message || e);
    res.status(500).json({ error: "Failed to create token" });
  }
});

app.get("/api/admin/pdfs/:id/download", requireAuth, requireAdmin, async (req, res) => {
  try {
    const pdf = await fetchPdfByIdFromDb(req.params.id);
    if (!pdf) return res.status(404).json({ error: "Not found" });

    const storagePath = (
      pdf.storage_path ||
      (pdf.file_name ? (SUPABASE_PREFIX ? `${SUPABASE_PREFIX}/${pdf.file_name}` : pdf.file_name) : "")
    ).replace(/^\/+/, "");

    if (storagePath) {
      const { data, error } = await supabase.storage.from(SUPABASE_BUCKET).createSignedUrl(storagePath, 60);
      if (!error && data?.signedUrl) return res.redirect(302, data.signedUrl);
    }

    const file = path.join(PDF_DIR, pdf.file_name || "");
    if (!pdf.file_name || !fs.existsSync(file)) return res.status(404).json({ error: "File missing" });
    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", `attachment; filename="${pdf.file_name}"`);
    fs.createReadStream(file).pipe(res);
  } catch (err) {
    console.error("Download error:", err?.message || err);
    res.status(500).json({ error: "Server error during download" });
  }
});

app.get("/api/download/:token", async (req, res) => {
  try {
    const tok = await takeDownloadToken(req.params.token);
    if (!tok) return res.status(410).json({ error: "Expired or invalid token" });

    const pdf = await fetchPdfByIdFromDb(tok.pdf_id);
    if (!pdf) return res.status(404).json({ error: "Not found" });

    const storagePath = (
      pdf.storage_path ||
      (pdf.file_name ? (SUPABASE_PREFIX ? `${SUPABASE_PREFIX}/${pdf.file_name}` : pdf.file_name) : "")
    ).replace(/^\/+/, "");

    if (storagePath) {
      const { data, error } = await supabase.storage.from(SUPABASE_BUCKET).createSignedUrl(storagePath, 60);
      if (!error && data?.signedUrl) return res.redirect(302, data.signedUrl);
    }

    const file = path.join(PDF_DIR, pdf.file_name || "");
    if (!pdf.file_name || !fs.existsSync(file)) return res.status(404).json({ error: "File missing" });

    res.setHeader("Content-Type", "application/octet-stream");
    const asAttachment = String(req.query.dl || "") === "1";
    const disp = asAttachment ? "attachment" : "inline";
    res.setHeader("Content-Disposition", `${disp}; filename="${(pdf.title || pdf.id).replace(/[^a-z0-9_\-\.]+/gi, "_")}.pdf"`);
    fs.createReadStream(file).pipe(res);
  } catch (e) {
    console.error("/api/download/:token error:", e?.message || e);
    res.status(500).json({ error: "Download failed" });
  }
});

/* === ZIP download of purchased PDFs === */
app.post("/api/download/zip", requireAuth, async (req, res) => {
  try {
    const ids = Array.isArray(req.body?.pdf_ids) ? req.body.pdf_ids.map(String) : [];
    if (ids.length === 0) return res.status(400).json({ error: "pdf_ids required" });

    const isAdmin = !!req.user.is_admin;

    const { data, error } = await supabase.from(T_PDFS).select("*").in("id", ids);
    if (error) throw error;
    const rows = (data || []).filter((p) => isAdmin || p.buyer_user_id === req.user.id);

    res.setHeader("Content-Type", "application/zip");
    res.setHeader("Content-Disposition", `attachment; filename="panda_pdfs_${Date.now()}.zip"`);

    const archive = archiver("zip", { zlib: { level: 9 } });
    archive.on("error", (err) => { throw err; });
    archive.pipe(res);

    let added = 0;
    for (const p of rows) {
      const storagePath = (
        p.storage_path ||
        (p.file_name ? (SUPABASE_PREFIX ? `${SUPABASE_PREFIX}/${p.file_name}` : p.file_name) : "")
      ).replace(/^\/+/, "");

      const nice = `${(p.title || p.id).replace(/[^a-z0-9_\-\.]+/gi, "_")}.pdf`;

      if (storagePath) {
        try {
          const { data: signed } = await supabase.storage.from(SUPABASE_BUCKET).createSignedUrl(storagePath, 120);
          if (signed?.signedUrl) {
            const r = await fetch(signed.signedUrl);
            if (r.ok) {
              const buf = Buffer.from(await r.arrayBuffer());
              archive.append(buf, { name: nice });
              added++;
              continue;
            }
          }
        } catch (e) {
          console.error("ZIP supabase fetch append failed:", e?.message || e);
        }
      }
      const fp = path.join(PDF_DIR, p.file_name || "");
      if (p.file_name && fs.existsSync(fp)) {
        archive.file(fp, { name: nice });
        added++;
      }
    }

    if (added === 0) archive.append("No files available in this ZIP.\n", { name: "README.txt" });
    await archive.finalize();
  } catch (e) {
    console.error("ZIP download error:", e?.message || e);
    if (!res.headersSent) res.status(500).json({ error: "ZIP creation failed" });
  }
});

/* ------------- Admin ------------- */
const upload = multer({ dest: TMP_DIR, limits: { fileSize: 200 * 1024 * 1024 } });
const uploadM = upload;
const uploadSingleFlexible = uploadM.fields([{ name: "file", maxCount: 1 }, { name: "pdf", maxCount: 1 }]);

app.get("/api/admin/metrics", requireAuth, requireAdmin, async (_req, res) => {
  try {
    const { count: remaining } = await supabase
      .from(T_PDFS)
      .select("id", { count: "exact" })
      .in("status", ["unsold", "UNSOLD", "Unsold"])
      .is("buyer_user_id", null); // ensure truly available

    const [{ data: txPurchase }, { data: txDeposits }, { data: users }, { data: soldPdfs }] = await Promise.all([
      supabase.from(T_TX).select("amount_cents").eq("type", "purchase"),
      supabase.from(T_TX).select("id").eq("type", "deposit").eq("status", "completed"),
      supabase.from(T_USERS).select("id"),
      supabase.from(T_PDFS).select("id").eq("status", "sold"),
    ]);

    const totalSales = (txPurchase || []).reduce((s, t) => s + (t.amount_cents || 0), 0) / 100;
    res.json({
      total_sales_usd: totalSales,
      sold: (soldPdfs || []).length,
      remaining: remaining ?? 0,
      users: (users || []).length,
      deposits: (txDeposits || []).length,
    });
  } catch (e) {
    console.error("/api/admin/metrics error:", e?.message || e);
    res.status(500).json({ error: "Failed to fetch metrics" });
  }
});

app.get("/api/admin/metrics/rich", requireAuth, requireAdmin, async (req, res) => {
  try {
    const days = Number(req.query.days || 30);
    const today = new Date();
    const dayKey = (d) => d.toISOString().slice(0, 10);
    const backDates = Array.from({ length: days }).map((_, i) => {
      const d = new Date(today); d.setDate(d.getDate() - (days - 1 - i)); return dayKey(d);
    });
    const salesByDay = Object.fromEntries(backDates.map((k) => [k, 0]));
    const depositsByDay = Object.fromEntries(backDates.map((k) => [k, 0]));

    const { data: txs, error } = await supabase.from(T_TX).select("*").gte("created_at", backDates[0] + "T00:00:00.000Z");
    if (error) throw error;
    for (const t of txs || []) {
      if (!t.created_at) continue;
      const k = dayKey(new Date(t.created_at));
      if (!(k in salesByDay)) continue;
      if (t.type === "purchase") salesByDay[k] += Number(t.amount_cents || 0);
      if (t.type === "deposit" && t.status === "completed") depositsByDay[k] += Number(t.amount_cents || 0);
    }

    const [{ data: txPurchase }, { data: soldPdfs }, { data: users }, { data: txDepositCount }] = await Promise.all([
      supabase.from(T_TX).select("amount_cents").eq("type", "purchase"),
      supabase.from(T_PDFS).select("id").eq("status", "sold"),
      supabase.from(T_USERS).select("id"),
      supabase.from(T_TX).select("id").eq("type", "deposit").eq("status", "completed"),
    ]);
    const totals = {
      total_sales_usd: (txPurchase || []).reduce((s, t) => s + (t.amount_cents || 0), 0) / 100,
      sold: (soldPdfs || []).length,
      remaining: (await supabase
        .from(T_PDFS)
        .select("id", { count: "exact" })
        .in("status", ["unsold", "UNSOLD", "Unsold"])
        .is("buyer_user_id", null)).count ?? 0, // ensure availability
      users: (users || []).length,
      deposits: (txDepositCount || []).length,
    };

    res.json({
      ...totals,
      sales_by_day: backDates.map((k) => ({ date: k, amount_cents: salesByDay[k] })),
      deposits_by_day: backDates.map((k) => ({ date: k, amount_cents: depositsByDay[k] })),
    });
  } catch (e) {
    console.error("/api/admin/metrics/rich error:", e?.message || e);
    res.status(500).json({ error: "Failed to fetch rich metrics" });
  }
});

// admin users list/patch/delete
app.get("/api/admin/users", requireAuth, requireAdmin, async (req, res) => {
  try {
    let { page = 1, per_page = 50, q = "" } = req.query;
    page = Math.max(Number(page) || 1, 1);
    per_page = Math.min(Math.max(Number(per_page) || 50, 1), 500);

    let { data, error } = await supabase.from(T_USERS).select("*").order("created_at", { ascending: false });
    if (error) throw error;
    let list = data || [];
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
  } catch (e) {
    console.error("/api/admin/users error:", e?.message || e);
    res.status(500).json({ error: "Failed to list users" });
  }
});

app.patch("/api/admin/users/:id", requireAuth, requireAdmin, async (req, res) => {
  try {
    const { name, email, balance_cents, is_admin } = req.body || {};
    const patch = {};
    if (typeof name === "string") patch.name = name.trim();
    if (typeof email === "string") patch.email = email.trim();
    if (balance_cents != null && !Number.isNaN(Number(balance_cents))) patch.balance_cents = Math.max(0, Math.round(Number(balance_cents)));
    if (typeof is_admin === "boolean") patch.is_admin = is_admin;
    const u = await updateUser(String(req.params.id), patch);
    res.json({ id: u.id, name: u.name, email: u.email, balance_cents: u.balance_cents || 0, is_admin: !!u.is_admin, created_at: u.created_at });
  } catch (e) {
    console.error("/api/admin/users/:id patch error:", e?.message || e);
    res.status(500).json({ error: "Failed to patch user" });
  }
});

app.delete("/api/admin/users/:id", requireAuth, requireAdmin, async (req, res) => {
  try {
    const id = String(req.params.id);
    await supabase.from(T_PDFS).update({ buyer_user_id: null }).eq("buyer_user_id", id);
    await supabase.from(T_RESET).delete().eq("user_id", id);
    await supabase.from(T_DLTOK).delete().eq("user_id", id);
    await supabase.from(T_TX).update({ user_id: null }).eq("user_id", id);
    const { data, error } = await supabase.from(T_USERS).delete().eq("id", id).select().maybeSingle();
    if (error) throw error;
    if (!data) return res.status(404).json({ error: "Not found" });
    res.json({ ok: true, removed: { id: data.id, email: data.email } });
  } catch (e) {
    console.error("/api/admin/users/:id delete error:", e?.message || e);
    res.status(500).json({ error: "Failed to delete user" });
  }
});

app.get("/api/admin/transactions", requireAuth, requireAdmin, async (_req, res) => {
  try {
    const items = await listTransactions(500);
    res.json({ items });
  } catch (e) {
    console.error("/api/admin/transactions error:", e?.message || e);
    res.status(500).json({ error: "Failed to fetch transactions" });
  }
});

// Admin PDFs list
app.get("/api/admin/pdfs", requireAuth, requireAdmin, async (req, res) => {
  try {
    const { page = 1, per_page = 60, q = "", state = "", status = "", year_min = null, year_max = null } = req.query;
    const result = await queryPdfsFromDb({
      state: state || null,
      year_min: year_min ? Number(year_min) : null,
      year_max: year_max ? Number(year_max) : null,
      page: Number(page),
      per_page: Number(per_page),
      status: status || null,
      q: q || "",
    });
    const items = (result.items || []).map((p) => ({
      id: p.id, title: p.title, state: p.state, year: p.year, status: p.status, created_at: p.created_at, file_name: p.file_name, storage_path: p.storage_path,
    }));
    return res.json({ total: result.total, page: Number(page), per_page: Number(per_page), items });
  } catch (e) {
    console.error("/api/admin/pdfs error:", e?.message || e);
    res.status(500).json({ error: "Failed to list PDFs" });
  }
});

/* ================== ADMIN PDF DELETION ================== */
async function removePdfById(id) {
  const { data, error } = await supabase.from(T_PDFS).select("*").eq("id", id).maybeSingle();
  if (error || !data) return { ok: false, id, reason: "Not found" };

  const p = data;
  const storagePath = p.storage_path || (p.file_name ? (SUPABASE_PREFIX ? `${SUPABASE_PREFIX}/${p.file_name}` : p.file_name) : "");
  if (storagePath) {
    try {
      const { error: rmErr } = await supabase.storage.from(SUPABASE_BUCKET).remove([storagePath]);
      if (rmErr) console.error("Warning: failed to remove storage object:", rmErr);
    } catch (e) {
      console.error("Warning: storage remove failed:", e?.message || e);
    }
  }
  try {
    const { error: delErr } = await supabase.from(T_PDFS).delete().eq("id", id);
    if (delErr) throw delErr;
  } catch (e) {
    return { ok: false, id, reason: "Delete failed" };
  }
  try {
    if (p.file_name) {
      const fp = path.join(PDF_DIR, p.file_name);
      if (fs.existsSync(fp)) fs.unlinkSync(fp);
    }
  } catch {}
  return { ok: true, id };
}

app.post("/api/admin/pdfs/delete", requireAuth, requireAdmin, async (req, res) => {
  try {
    const ids = Array.isArray(req.body?.ids) ? req.body.ids.map(String) : [];
    if (ids.length === 0) return res.status(400).json({ error: "ids (array) required" });
    const results = { removed: [], skipped: [] };
    for (const id of ids) {
      const r = await removePdfById(id);
      if (r.ok) results.removed.push(id);
      else results.skipped.push({ id, reason: r.reason || "Not found" });
    }
    res.json(results);
  } catch (e) {
    console.error("/api/admin/pdfs/delete error:", e?.message || e);
    res.status(500).json({ error: "Delete failed" });
  }
});

app.delete("/api/admin/pdfs", requireAuth, requireAdmin, async (req, res) => {
  try {
    const ids = String(req.query.ids || "").split(",").map((s) => s.trim()).filter(Boolean);
    if (ids.length === 0) return res.status(400).json({ error: "ids query required" });
    const results = { removed: [], skipped: [] };
    for (const id of ids) {
      const r = await removePdfById(id);
      if (r.ok) results.removed.push(id);
      else results.skipped.push({ id, reason: r.reason || "Not found" });
    }
    res.json(results);
  } catch (e) {
    console.error("/api/admin/pdfs delete query error:", e?.message || e);
    res.status(500).json({ error: "Delete failed" });
  }
});

app.delete("/api/admin/pdfs/:id", requireAuth, requireAdmin, async (req, res) => {
  try {
    const r = await removePdfById(req.params.id);
    if (!r.ok) return res.status(404).json({ error: "Not found" });
    res.json({ ok: true, id: r.id });
  } catch (e) {
    console.error("/api/admin/pdfs/:id delete error:", e?.message || e);
    res.status(500).json({ error: "Delete failed" });
  }
});
app.delete("/api/admin/pdf/:id", requireAuth, requireAdmin, async (req, res) => {
  try {
    const r = await removePdfById(req.params.id);
    if (!r.ok) return res.status(404).json({ error: "Not found" });
    res.json({ ok: true, id: r.id });
  } catch (e) {
    console.error("/api/admin/pdf/:id delete error:", e?.message || e);
    res.status(500).json({ error: "Delete failed" });
  }
});
app.post("/api/admin/pdfs/:id/delete", requireAuth, requireAdmin, async (req, res) => {
  try {
    const r = await removePdfById(req.params.id);
    if (!r.ok) return res.status(404).json({ error: "Not found" });
    res.json({ ok: true, id: r.id });
  } catch (e) {
    console.error("/api/admin/pdfs/:id/delete error:", e?.message || e);
    res.status(500).json({ error: "Delete failed" });
  }
});

/* ---------- Uploads ---------- */
const uploadAny = uploadM.any();

async function insertPdfToDb(item) {
  const { data, error } = await supabase.from(T_PDFS).insert(item).select().single();
  if (error) throw error;
  return data;
}

app.post("/api/admin/pdf", requireAuth, requireAdmin, uploadSingleFlexible, async (req, res) => {
  try {
    const up = (req.files?.file && req.files.file[0]) || (req.files?.pdf && req.files.pdf[0]);
    const { title, state, year } = req.body || {};
    if (!up) return res.status(400).json({ error: "file required (PDF)" });
    if (!title || !state || !year) return res.status(400).json({ error: "title, state, year required" });
    if (!/^(2000|2001|2002|2003|2004|2005|2006|2007)$/.test(String(year)))
      return res.status(400).json({ error: "year must be 2000-2007" });

    const filename = nanoid() + path.extname(up.originalname).toLowerCase();
    const dest = path.join(PDF_DIR, filename);
    try { await fs.promises.rename(up.path, dest); } catch { await fs.promises.copyFile(up.path, dest); await fs.promises.unlink(up.path); }

    const storage_path = SUPABASE_PREFIX ? `${SUPABASE_PREFIX}/${filename}` : filename;

    try {
      await uploadFileBufferToSupabase(dest, filename);
    } catch (uploadErr) {
      console.error("Warning: failed to upload to Supabase storage:", uploadErr?.message || uploadErr);
    }

    const itemRow = {
      title: String(title).trim(),
      state: String(state).toUpperCase(),
      year: Number(year),
      price_cents: PRICE_CENTS,
      status: "unsold",
      file_name: filename,
      storage_path,
      created_at: nowISO(),
    };
    const created = await insertPdfToDb(itemRow);
    return res.json({ ok: true, pdf: { id: created.id, title: created.title } });
  } catch (e) {
    console.error("Single upload failed:", e?.message || e);
    try {
      if (req.files) for (const f of Object.values(req.files).flat()) {
        if (f?.path && fs.existsSync(f.path)) fs.unlinkSync(f.path);
      }
    } catch {}
    res.status(500).json({ error: "Upload failed" });
  }
});

app.post("/api/admin/pdf-batch", requireAuth, requireAdmin, uploadAny, async (req, res) => {
  const release = await mutex.acquire();
  const results = { created: [], skipped: [], errors: [] };
  try {
    const files = Array.isArray(req.files) ? req.files : [];
    for (const file of files) {
      try {
        if (!/\.(pdf|png|jpg|jpeg)$/i.test(file.originalname)) {
          results.skipped.push({ file: file.originalname, reason: "Not a supported doc" });
          try { if (file?.path && fs.existsSync(file.path)) await fs.promises.unlink(file.path); } catch {}
          continue;
        }
        const meta = parseFilenameMeta(file.originalname);
        if (!meta) {
          results.skipped.push({ file: file.originalname, reason: "Could not parse Title/State/Year" });
          try { if (file?.path && fs.existsSync(file.path)) await fs.promises.unlink(file.path); } catch {}
          continue;
        }
        const filename = nanoid() + path.extname(file.originalname).toLowerCase();
        const dest = path.join(PDF_DIR, filename);
        try { await fs.promises.rename(file.path, dest); } catch { await fs.promises.copyFile(file.path, dest); await fs.promises.unlink(file.path); }

        const storage_path = SUPABASE_PREFIX ? `${SUPABASE_PREFIX}/${filename}` : filename;
        try {
          await uploadFileBufferToSupabase(dest, filename);
        } catch (uploadErr) {
          console.error("Warning: failed to upload to Supabase storage:", file.originalname, uploadErr?.message || uploadErr);
        }
        const itemRow = {
          title: meta.title, state: meta.state, year: meta.year,
          price_cents: PRICE_CENTS, status: "unsold", file_name: filename, storage_path, created_at: nowISO(),
        };
        const created = await insertPdfToDb(itemRow);
        results.created.push({ file: file.originalname, parsed: meta, id: created.id });
      } catch (e) {
        console.error("Batch upload error for", file?.originalname, e);
        results.errors.push({ file: file?.originalname || "unknown", error: String(e?.message || e) });
        try { if (file?.path && fs.existsSync(file.path)) await fs.promises.unlink(file.path); } catch {}
      }
    }
    return res.json(results);
  } catch (e) {
    console.error("Batch upload failed:", e?.message || e);
    return res.status(500).json({ error: "Batch upload failed" });
  } finally {
    release();
  }
});

// ZIP batch upload
const uploadZip = uploadM.single("zip");
app.post("/api/admin/pdf-batch-zip", requireAuth, requireAdmin, uploadZip, async (req, res) => {
  const release = await mutex.acquire();
  try {
    if (!req.file) return res.status(400).json({ error: "zip file required (field 'zip')" });

    const results = { created: [], skipped: [], errors: [] };
    const zipPath = req.file.path;

    let directory;
    try { directory = await unzipper.Open.file(zipPath); }
    catch (err) {
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
        const meta = parseFilenameMeta(basename);
        if (!meta) { results.skipped.push({ file: originalname, reason: "Could not parse Title/State/Year" }); continue; }

        const filename = nanoid() + ext;
        const dest = path.join(PDF_DIR, filename);
        await new Promise((resolve, reject) =>
          entry.stream().pipe(fs.createWriteStream(dest)).on("finish", resolve).on("error", reject)
        );

        const storage_path = SUPABASE_PREFIX ? `${SUPABASE_PREFIX}/${filename}` : filename;
        try { await uploadFileBufferToSupabase(dest, filename); } catch (uploadErr) { console.error("Warning: failed to upload zip-entry:", uploadErr?.message || uploadErr); }

        const itemRow = {
          title: meta.title, state: meta.state, year: meta.year,
          price_cents: PRICE_CENTS, status: "unsold", file_name: filename, storage_path, created_at: nowISO(),
        };
        const created = await insertPdfToDb(itemRow);
        results.created.push({ file: originalname, parsed: meta, id: created.id });
      } catch (e) {
        console.error("ZIP entry error:", entry?.path, e);
        results.errors.push({ file: entry?.path || "unknown", error: String(e?.message || e) });
      }
    }

    try { if (zipPath && fs.existsSync(zipPath)) await fs.promises.unlink(zipPath); } catch {}
    res.json(results);
  } catch (e) {
    console.error("ZIP upload failed:", e?.message || e);
    try { if (req.file?.path && fs.existsSync(req.file.path)) await fs.promises.unlink(req.file.path); } catch {}
    res.status(500).json({ error: "ZIP upload failed" });
  } finally {
    release();
  }
});

/* ===================== CONTACT → INBOX ===================== */
const sanitizeMessage = (s) => (!s ? "" : String(s).slice(0, 5000));
async function createInboxMessage({ name, email, message, source = "contact_page" }) {
  return await inboxInsert({ name: String(name || "").trim().slice(0, 200), email: String(email || "").trim().slice(0, 320), message: sanitizeMessage(message), source });
}
function maybeEmailAdmin(msg) {
  const mailer = makeMailer(); if (!mailer) return;
  const to = process.env.SUPPORT_EMAIL || process.env.ADMIN_EMAIL || process.env.SMTP_USER; if (!to) return;
  mailer.sendMail({
    to,
    from: `"Panda" <${process.env.SMTP_USER || "no-reply@localhost"}>`,
    subject: `New contact message from ${msg.name || msg.email || "Unknown"}`,
    text: `Source: ${msg.source || "contact_page"}\nName: ${msg.name}\nEmail: ${msg.email}\nWhen: ${msg.created_at}\n\n${msg.message}`,
  }).catch((e) => console.error("Failed to send admin email:", e?.message || e));
}

app.post(["/api/contact", "/api/support", "/api/messages", "/api/admin/inbox"], async (req, res) => {
  try {
    const { name, email, message } = req.body || {};
    if (!String(name || "").trim()) return res.status(400).json({ error: "name required" });
    if (!String(email || "").trim()) return res.status(400).json({ error: "email required" });
    if (!String(message || "").trim() || String(message).trim().length < 10) return res.status(400).json({ error: "message too short" });
    const msg = await createInboxMessage({ name, email, message, source: "contact_page" });
    maybeEmailAdmin(msg);
    res.json({ ok: true, id: msg.id });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Failed to submit message" });
  }
});

app.get("/api/admin/inbox", requireAuth, requireAdmin, async (req, res) => {
  try {
    let { page = 1, per_page = 50, q = "", status = "all" } = req.query;
    page = Math.max(Number(page) || 1, 1);
    per_page = Math.min(Math.max(Number(per_page) || 50, 1), 500);
    const { total, items } = await inboxList({ q, status, page, per_page });
    res.json({ total, page, per_page, items });
  } catch (e) {
    console.error("/api/admin/inbox GET error:", e?.message || e);
    res.status(500).json({ error: "Failed to fetch inbox" });
  }
});

app.patch("/api/admin/inbox/:id", requireAuth, requireAdmin, async (req, res) => {
  try {
    const id = String(req.params.id);
    const { read, archived } = req.body || {};
    const patch = {};
    if (typeof read === "boolean") patch.read = read;
    if (typeof archived === "boolean") patch.archived = archived;
    const item = await inboxPatch(id, patch);
    res.json({ ok: true, item });
  } catch (e) {
    console.error("/api/admin/inbox/:id patch error:", e?.message || e);
    res.status(500).json({ error: "Failed to update inbox item" });
  }
});

app.delete("/api/admin/inbox/:id", requireAuth, requireAdmin, async (req, res) => {
  try {
    await inboxDelete(String(req.params.id));
    res.json({ ok: true });
  } catch (e) {
    console.error("/api/admin/inbox/:id delete error:", e?.message || e);
    res.status(500).json({ error: "Failed to delete inbox item" });
  }
});

/* ========= CHAT ROUTES ========= */
app.post("/api/chat/send", requireAuth, async (req, res) => {
  try {
    const text = String(req.body?.text || "").trim();
    if (!text) return res.status(400).json({ error: "text required" });
    const msg = await pushMessage({ user_id: req.user.id, from: "user", text });
    res.json({ ok: true, message: msg });
  } catch (e) {
    console.error("/api/chat/send error:", e?.message || e);
    res.status(500).json({ error: "Failed to send message" });
  }
});
app.get("/api/chat/history", requireAuth, async (req, res) => {
  try {
    const limit = Math.min(Math.max(Number(req.query.limit) || 200, 1), 1000);
    const items = await chatListForUser(req.user.id, limit);
    res.json({ items: items.slice(-limit) });
  } catch (e) {
    console.error("/api/chat/history error:", e?.message || e);
    res.status(500).json({ error: "Failed to fetch chat history" });
  }
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
app.get("/api/admin/chat/:userId/history", requireAuth, requireAdmin, async (req, res) => {
  try {
    const userId = String(req.params.userId);
    const limit = Math.min(Math.max(Number(req.query.limit) || 1000, 1), 5000);
    const items = await chatListForUser(userId, limit);
    res.json({ items: items.slice(-limit) });
  } catch (e) {
    console.error("/api/admin/chat/:userId/history error:", e?.message || e);
    res.status(500).json({ error: "Failed to fetch admin chat history" });
  }
});
app.post("/api/admin/chat/:userId/send", requireAuth, requireAdmin, async (req, res) => {
  try {
    const userId = String(req.params.userId);
    const u = await getUserById(userId);
    if (!u) return res.status(404).json({ error: "User not found" });
    const text = String(req.body?.text || "").trim();
    if (!text) return res.status(400).json({ error: "text required" });
    const msg = await pushMessage({ user_id: userId, from: "admin", text });
    res.json({ ok: true, message: msg });
  } catch (e) {
    console.error("/api/admin/chat/:userId/send error:", e?.message || e);
    res.status(500).json({ error: "Failed to send admin message" });
  }
});
app.get("/api/admin/chat/stream", requireAuth, requireAdmin, (req, res) => {
  res.writeHead(200, { "Content-Type": "text/event-stream", "Cache-Control": "no-cache, no-transform", Connection: "keep-alive" });
  sseSend(res, "hello", { ok: true, admin: true });
  adminStreams.add(res);
  const keepAlive = setInterval(() => ssePing(res), 15000);
  req.on("close", () => { clearInterval(keepAlive); adminStreams.delete(res); });
});

/* ------------- Health & bootstrap ------------- */
app.get("/api/health", (_req, res) => res.json({ ok: true, time: new Date().toISOString() }));
app.get("/", (_req, res) => res.json({ ok: true, app: "Panda PDF API", try: "/api/health" }));

/* ---------- Serve built SPA (web/dist) ---------- */
const clientDir = process.env.CLIENT_DIR || path.join(__dirname, "../web/dist");
const clientIndex = path.join(clientDir, "index.html");
if (fs.existsSync(clientIndex)) {
  app.use(express.static(clientDir));
  app.get(/^(?!\/api).+/, (_req, res) => res.sendFile(clientIndex));
} else {
  app.get(/^(?!\/api).+/, (_req, res) => res.status(200).send("Frontend is hosted separately. Visit the Netlify site."));
}

/* ------------ FINAL: /api catch-all 404 ------------ */
app.use("/api", (req, res) => res.status(404).json({ error: "Not found", path: req.originalUrl }));

app.listen(PORT, "0.0.0.0", () => {
  console.log(`API listening on 0.0.0.0:${PORT}`);
});
