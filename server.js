// server.js - Supabase-enabled Panda API (patched)
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
const RAW_ALLOWED = process.env.CORS_ORIGINS || "http://localhost:5173,https://sprightly-cannoli-74fc49.netlify.app";
const ALLOWED = RAW_ALLOWED.split(",").map((s) => s.trim()).filter(Boolean);

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

/* ---------------- Ensure storage dirs exist ---------------- */
const STORAGE_ROOT = path.join(__dirname, "storage");
const TMP_DIR = path.join(STORAGE_ROOT, "tmp");
const PDF_DIR = path.join(STORAGE_ROOT, "pdfs");
for (const d of [STORAGE_ROOT, TMP_DIR, PDF_DIR]) {
  try { fs.mkdirSync(d, { recursive: true }); } catch {}
}

// optionally expose files over HTTPS as /files/* (local fallback)
app.use("/files", express.static(PDF_DIR, {
  maxAge: "1y",
  setHeaders: (res) => {
    res.setHeader("Cache-Control", "public, max-age=31536000, immutable");
  },
}));

/* ---------------- DB (LowDB fallback) ---------------- */
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

/* ---------------- Supabase init & helpers ---------------- */
const SUPABASE_URL = process.env.SUPABASE_URL || "";
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || "";
const SUPABASE_TABLE = process.env.SUPABASE_TABLE || "pdfs";
const SUPABASE_BUCKET = process.env.SUPABASE_BUCKET || "pdf";
const SUPABASE_STORAGE_PREFIX = typeof process.env.SUPABASE_STORAGE_PREFIX === "string" ? process.env.SUPABASE_STORAGE_PREFIX : "files";

let supabase = null;
if (SUPABASE_URL && SUPABASE_KEY) {
  supabase = createClient(SUPABASE_URL, SUPABASE_KEY, { auth: { persistSession: false } });
}

async function insertPdfToDb(item) {
  if (!supabase) throw new Error("Supabase client not configured");
  const { data, error } = await supabase.from(SUPABASE_TABLE).insert([item]).select().single();
  if (error) throw error;
  return data;
}

async function updatePdfInDb(id, patch) {
  if (!supabase) throw new Error("Supabase client not configured");
  const { data, error } = await supabase.from(SUPABASE_TABLE).update(patch).eq("id", id).select().single();
  if (error) throw error;
  return data;
}

async function deletePdfRowFromDb(id) {
  if (!supabase) throw new Error("Supabase client not configured");
  const { error } = await supabase.from(SUPABASE_TABLE).delete().eq("id", id);
  if (error) throw error;
  return true;
}

async function fetchPdfByIdFromDb(id) {
  if (!supabase) throw new Error("Supabase client not configured");
  const { data, error } = await supabase.from(SUPABASE_TABLE).select("*").eq("id", id).single();
  if (error) {
    // Normalize not-found
    if (error.code === "PGRST116" || error.status === 406 || error.status === 404 || /No rows/.test(String(error.message || ""))) return null;
    throw error;
  }
  return data;
}

/**
 * Query pdfs with basic filters + pagination
 * returns { total, items }
 */
async function queryPdfsFromDb({ state, year_min = null, year_max = null, page = 1, per_page = 100, status = "unsold", q = "" } = {}) {
  if (!supabase) throw new Error("Supabase client not configured");
  const pg = Math.max(Number(page) || 1, 1);
  const pp = Math.min(Math.max(Number(per_page) || 100, 1), 500);

  let query = supabase.from(SUPABASE_TABLE).select("*", { count: "exact" });

  if (status) query = query.eq("status", status);
  if (state) query = query.eq("state", String(state).toUpperCase());
  if (year_min != null) query = query.gte("year", Number(year_min));
  if (year_max != null) query = query.lte("year", Number(year_max));
  if (q) query = query.ilike("title", `%${q}%`);

  const from = (pg - 1) * pp;
  const to = from + pp - 1;
  const { data, count, error } = await query.range(from, to);
  if (error) throw error;
  return { total: count || (data ? data.length : 0), items: data || [] };
}

/* ===================== SUPABASE STORAGE HELPER ===================== */
/**
 * Upload a local file buffer to Supabase storage and return storage path.
 * This reads the file into a buffer (avoids node-fetch duplex issues).
 */
async function uploadFileBufferToSupabase(localPath, destFilename) {
  if (!supabase) throw new Error("Supabase client not configured");
  const bucket = SUPABASE_BUCKET || "pdf";
  const prefix = SUPABASE_STORAGE_PREFIX || "files";
  const destPath = prefix ? `${prefix}/${destFilename}` : `${destFilename}`;

  const buf = await fs.promises.readFile(localPath);
  const { data, error } = await supabase.storage.from(bucket).upload(destPath, buf, {
    upsert: false,
    contentType: "application/pdf",
  });
  if (error) throw error;
  return { path: destPath, data };
}

/**
 * Create a signed URL for a storage path (expiresSec seconds).
 * Returns an object { url } or throws.
 */
async function createSignedUrlForPath(storagePath, expiresSec = 60) {
  if (!supabase) throw new Error("Supabase client not configured");
  if (!storagePath) throw new Error("storagePath required");
  const { data, error } = await supabase.storage.from(SUPABASE_BUCKET).createSignedUrl(storagePath, expiresSec);
  if (error) throw error;
  return data?.signedUrl || data?.signed_url || data?.signed;
}

/* ---------------- Helpers ---------------- */
const PRICE_CENTS = 499;
const mutex = new Mutex();
const nowISO = () => new Date().toISOString();
const cents = (n) => Math.round(Number(n || 0));
const findUserByEmail = (email) => db.data.users.find((u) => u.email && u.email.toLowerCase() === String(email).toLowerCase());
const saveDb = () => db.write();

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

  // 1) Title_State_YYYY
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
            const nameParts = parts.slice(0, i);
            const nameFirst = cap(nameParts[0]);
            const nameLast = cap(nameParts[nameParts.length - 1] || parts[1]);
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

/* ---------------- Auth (register/login/me) ---------------- */
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

/* ------------- Storefront (prefer Supabase, fallback LowDB) ------------- */
app.get("/api/pdfs", async (req, res) => {
  try {
    if (supabase) {
      const { state, year_min, year_max, page = 1, per_page = 100, q = "" } = req.query;
      const result = await queryPdfsFromDb({
        state,
        year_min: year_min ? Number(year_min) : null,
        year_max: year_max ? Number(year_max) : null,
        page: Number(page), per_page: Number(per_page), status: "unsold", q
      });
      const items = (result.items || []).map((p) => ({ id: p.id, title: p.title, state: p.state, year: p.year, price_cents: p.price_cents ?? PRICE_CENTS }));
      return res.json({ total: result.total, page: Number(req.query.page || 1), per_page: Number(req.query.per_page || 100), items });
    }

    // fallback LowDB
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
      items: items.slice(start, start + pp).map((p) => ({ id: p.id, title: p.title, state: p.state, year: p.year, price_cents: PRICE_CENTS })),
    });
  } catch (e) {
    console.error("GET /api/pdfs error:", e);
    res.status(500).json({ error: "Failed to fetch PDFs" });
  }
});

app.get("/api/inventory/count", async (req, res) => {
  try {
    if (supabase) {
      const { data, count, error } = await supabase.from(SUPABASE_TABLE).select("id", { count: "exact" }).eq("status", "unsold");
      if (error) throw error;
      return res.json({ remaining: count || (data ? data.length : 0) });
    }
    return res.json({ remaining: db.data.pdfs.filter((p) => p.status === "unsold").length });
  } catch (e) {
    console.error("inventory count supabase error:", e);
    return res.json({ remaining: db.data.pdfs.filter((p) => p.status === "unsold").length });
  }
});

// richer library + alias
app.get("/api/me/library", requireAuth, async (req, res) => {
  try {
    if (supabase) {
      const { data, error } = await supabase.from(SUPABASE_TABLE).select("*").eq("buyer_user_id", req.user.id).order("sold_at", { ascending: false });
      if (error) throw error;
      return res.json({ items: (data || []).map(p => ({ id: p.id, title: p.title, state: p.state, year: p.year, price_cents: p.price_cents })) });
    }
    const owned = db.data.pdfs
      .filter((p) => p.buyer_user_id === req.user.id)
      .sort((a, b) => new Date(b.sold_at || 0) - new Date(a.sold_at || 0))
      .map((p) => ({ id: p.id, title: p.title, state: p.state, year: p.year, price_cents: PRICE_CENTS }));
    res.json({ items: owned });
  } catch (e) {
    console.error("/api/me/library error:", e);
    res.status(500).json({ error: "Failed to fetch library" });
  }
});
app.get("/api/library", requireAuth, async (req, res) => {
  try {
    if (supabase) {
      const { data, error } = await supabase.from(SUPABASE_TABLE).select("*").eq("buyer_user_id", req.user.id).order("sold_at", { ascending: false });
      if (error) throw error;
      return res.json({ items: (data || []).map(p => ({ id: p.id, title: p.title, state: p.state, year: p.year, price_cents: p.price_cents })) });
    }
    const owned = db.data.pdfs
      .filter((p) => p.buyer_user_id === req.user.id)
      .sort((a, b) => new Date(b.sold_at || 0) - new Date(a.sold_at || 0))
      .map((p) => ({ id: p.id, title: p.title, state: p.state, year: p.year, price_cents: PRICE_CENTS }));
    res.json({ items: owned });
  } catch (e) {
    console.error("/api/library error:", e);
    res.status(500).json({ error: "Failed to fetch library" });
  }
});

/* ------------- NOWPayments ------------- */
// ... (unchanged) - keep the same code you already have (omitted here for brevity; it's present above)

/// ... rest of purchasing, chat, admin, etc remain unchanged until uploads/downloads (they are present above unchanged)
/// UPDATED: upload/download handlers below
/* ---------- Uploads ---------- */
const upload = multer({ dest: TMP_DIR, limits: { fileSize: 200 * 1024 * 1024 } }); // 200MB per file limit
const uploadM = upload; // alias
const uploadSingleFlexible = uploadM.fields([{ name: "file", maxCount: 1 }, { name: "pdf", maxCount: 1 }]);
const uploadAny = uploadM.any();
const uploadZip = uploadM.single("zip");

// Single PDF upload (admin) - now uploads to Supabase storage and inserts metadata with storage_path
app.post("/api/admin/pdf", requireAuth, requireAdmin, uploadSingleFlexible, async (req, res) => {
  try {
    await db.read();
    const up = (req.files?.file && req.files.file[0]) || (req.files?.pdf && req.files.pdf[0]);
    const { title, state, year } = req.body || {};
    if (!up) return res.status(400).json({ error: "file required (PDF)" });
    if (!title || !state || !year) return res.status(400).json({ error: "title, state, year required" });
    if (!/^(2000|2001|2002|2003|2004|2005|2006|2007)$/.test(String(year))) return res.status(400).json({ error: "year must be 2000-2007" });

    const filename = nanoid() + path.extname(up.originalname).toLowerCase();
    const tmpPath = up.path;

    // upload to Supabase storage (buffer helper)
    if (supabase) {
      try {
        await uploadFileBufferToSupabase(tmpPath, filename);
      } catch (e) {
        console.error("Warning: Supabase storage upload failed:", e?.message || e);
        // we continue to insert metadata in DB — but note file may be missing in storage
      }
    } else {
      // fallback: move file to local PDF_DIR
      const dest = path.join(PDF_DIR, filename);
      try {
        await fs.promises.rename(tmpPath, dest);
      } catch (err) {
        await fs.promises.copyFile(tmpPath, dest);
        try { await fs.promises.unlink(tmpPath); } catch {}
      }
    }

    // canonical item row to insert into Supabase
    const itemRow = {
      title,
      state: String(state).toUpperCase(),
      year: Number(year),
      price_cents: PRICE_CENTS,
      status: "unsold",
      file_name: filename,
      storage_path: SUPABASE_STORAGE_PREFIX ? `${SUPABASE_STORAGE_PREFIX}/${filename}` : filename,
      created_at: nowISO(),
    };

    if (supabase) {
      try {
        const created = await insertPdfToDb(itemRow);
        const item = { id: created.id, ...itemRow };
        db.data.pdfs.push(item);
        await saveDb();

        // cleanup tmp
        try { if (fs.existsSync(tmpPath)) await fs.promises.unlink(tmpPath); } catch {}

        return res.json({ ok: true, pdf: { id: item.id, title: item.title } });
      } catch (e) {
        console.error("Failed to insert pdf row into Supabase:", e);
        // Fallback to LowDB so admin still sees it (keeps behavior safe)
        const item = { id: nanoid(), ...itemRow };
        db.data.pdfs.push(item);
        await saveDb();
        return res.status(500).json({ error: "Uploaded file but failed to save metadata to Supabase (fallback saved locally)" });
      }
    } else {
      const item = { id: nanoid(), ...itemRow };
      db.data.pdfs.push(item);
      await saveDb();
      try { if (fs.existsSync(tmpPath)) await fs.promises.unlink(tmpPath); } catch {}
      return res.json({ ok: true, pdf: { id: item.id, title: item.title } });
    }
  } catch (e) {
    console.error("Single upload failed:", e);
    try { if (req.files) for (const f of Object.values(req.files).flat()) { if (f?.path && fs.existsSync(f.path)) fs.unlinkSync(f.path); } } catch {}
    res.status(500).json({ error: "Upload failed" });
  }
});

// Batch upload - uses parseFilenameMeta, uploads to Supabase storage via buffer helper and inserts rows
app.post("/api/admin/pdf-batch", requireAuth, requireAdmin, uploadAny, async (req, res) => {
  const release = await mutex.acquire();
  const results = { created: [], skipped: [], errors: [] };

  try {
    await db.read();
    db.data.pdfs ||= [];

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
        const tmpPath = file.path;

        // upload to Supabase storage (if configured)
        if (supabase) {
          try {
            await uploadFileBufferToSupabase(tmpPath, filename);
          } catch (uploadErr) {
            console.error("Warning: failed to upload to Supabase storage for", file.originalname, uploadErr);
            // continue; we'll still insert metadata
          }
        } else {
          const dest = path.join(PDF_DIR, filename);
          try {
            await fs.promises.rename(tmpPath, dest);
          } catch (err) {
            await fs.promises.copyFile(tmpPath, dest);
            await fs.promises.unlink(tmpPath);
          }
        }

        const itemRow = {
          title: meta.title,
          state: meta.state,
          year: meta.year,
          price_cents: PRICE_CENTS,
          status: "unsold",
          file_name: filename,
          storage_path: SUPABASE_STORAGE_PREFIX ? `${SUPABASE_STORAGE_PREFIX}/${filename}` : filename,
          created_at: nowISO(),
        };

        if (supabase) {
          try {
            const created = await insertPdfToDb(itemRow);
            const item = { id: created.id, ...itemRow };
            db.data.pdfs.push(item);
            results.created.push({ file: file.originalname, parsed: meta, id: item.id });
          } catch (e) {
            console.error("Failed to insert batch pdf into Supabase:", e);
            const item = { id: nanoid(), ...itemRow };
            db.data.pdfs.push(item);
            results.created.push({ file: file.originalname, parsed: meta, id: item.id, fallback: true });
          }
        } else {
          const item = { id: nanoid(), ...itemRow };
          db.data.pdfs.push(item);
          results.created.push({ file: file.originalname, parsed: meta, id: item.id });
        }

        try { if (file?.path && fs.existsSync(file.path)) await fs.promises.unlink(file.path); } catch {}
      } catch (e) {
        console.error("Batch upload error for", file?.originalname, e);
        results.errors.push({ file: file?.originalname || "unknown", error: String(e?.message || e) });
        try { if (file?.path && fs.existsSync(file.path)) await fs.promises.unlink(file.path); } catch {}
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
// we extract entries to tmp, upload to storage, insert rows
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

        const meta = parseFilenameMeta(basename);
        if (!meta) {
          results.skipped.push({ file: originalname, reason: "Could not parse Title/State/Year" });
          continue;
        }

        const filename = nanoid() + ext;
        const dest = path.join(TMP_DIR, filename);

        // stream entry to tmp file
        await new Promise((resolve, reject) =>
          entry.stream()
            .pipe(fs.createWriteStream(dest))
            .on("finish", resolve)
            .on("error", reject)
        );

        // upload to Supabase storage if configured
        if (supabase) {
          try {
            await uploadFileBufferToSupabase(dest, filename);
          } catch (uploadErr) {
            console.error("Warning: failed to upload zip-entry to Supabase storage for", originalname, uploadErr);
          }
        } else {
          // move to permanent pdf dir
          const finalDest = path.join(PDF_DIR, filename);
          try {
            await fs.promises.rename(dest, finalDest);
          } catch (err) {
            await fs.promises.copyFile(dest, finalDest);
            try { await fs.promises.unlink(dest); } catch {}
          }
        }

        const itemRow = {
          title: meta.title,
          state: meta.state,
          year: meta.year,
          price_cents: PRICE_CENTS,
          status: "unsold",
          file_name: filename,
          storage_path: SUPABASE_STORAGE_PREFIX ? `${SUPABASE_STORAGE_PREFIX}/${filename}` : filename,
          created_at: nowISO(),
        };

        if (supabase) {
          try {
            const created = await insertPdfToDb(itemRow);
            const item = { id: created.id, ...itemRow };
            db.data.pdfs.push(item);
            results.created.push({ file: originalname, parsed: meta, id: item.id });
          } catch (e) {
            console.error("Failed to insert zip-entry pdf into Supabase:", e);
            const item = { id: nanoid(), ...itemRow };
            db.data.pdfs.push(item);
            results.created.push({ file: originalname, parsed: meta, id: item.id, fallback: true });
          }
        } else {
          const item = { id: nanoid(), ...itemRow };
          db.data.pdfs.push(item);
          results.created.push({ file: originalname, parsed: meta, id: item.id });
        }

        try { if (fs.existsSync(dest)) await fs.promises.unlink(dest); } catch {}
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

/* ------------- Downloads (UPDATED to use Supabase signed URLs) ------------- */
app.post("/api/download/token/:pdfId", requireAuth, async (req, res) => {
  await db.read();
  let pdf = null;
  if (supabase) {
    try { pdf = await fetchPdfByIdFromDb(req.params.pdfId); } catch (e) { console.error("fetchPdfByIdFromDb error:", e); }
  }
  if (!pdf) pdf = db.data.pdfs.find((p) => p.id === req.params.pdfId);
  if (!pdf) return res.status(404).json({ error: "Not found" });
  if (!req.user.is_admin && pdf.buyer_user_id !== req.user.id) return res.status(403).json({ error: "Purchase required" });

  const token = nanoid();
  const expires_at = Date.now() + 5 * 60 * 1000;
  db.data.downloadTokens.push({ token, user_id: req.user.id, pdf_id: pdf.id, expires_at });
  await saveDb();

  const url = `${publicBase(req)}/api/download/${token}`;
  res.json({ token, expires_at, url });
});

app.get("/api/admin/pdfs/:id/download", requireAuth, requireAdmin, async (req, res) => {
  try {
    await db.read();

    let pdf = null;
    if (supabase) {
      try { pdf = await fetchPdfByIdFromDb(req.params.id); } catch (e) { console.error("fetchPdfByIdFromDb error:", e); }
    }
    if (!pdf) pdf = db.data.pdfs.find((p) => p.id === req.params.id);
    if (!pdf) return res.status(404).json({ error: "Not found" });

    // Prefer Supabase signed URL if storage_path present
    if (supabase && pdf.storage_path) {
      try {
        const signed = await createSignedUrlForPath(pdf.storage_path, 60);
        return res.redirect(signed);
      } catch (e) {
        console.error("Failed to create signed url:", e);
        // fallback to local file serve below
      }
    }

    // fallback to local file
    const file = path.join(PDF_DIR, pdf.file_name || "");
    if (!fs.existsSync(file)) return res.status(404).json({ error: "File missing" });

    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", `attachment; filename="${pdf.file_name}"`);
    fs.createReadStream(file).pipe(res);
  } catch (err) {
    console.error("Download error:", err);
    res.status(500).json({ error: "Server error during download" });
  }
});

app.get("/api/download/:token", async (req, res) => {
  await db.read();
  const tok = db.data.downloadTokens.find((t) => t.token === req.params.token);
  if (!tok || Date.now() > tok.expires_at) return res.status(410).json({ error: "Expired token" });

  let pdf = null;
  if (supabase) {
    try { pdf = await fetchPdfByIdFromDb(tok.pdf_id); } catch (e) { console.error("fetchPdfByIdFromDb error:", e); }
  }
  if (!pdf) pdf = db.data.pdfs.find((p) => p.id === tok.pdf_id);
  if (!pdf) return res.status(404).json({ error: "Not found" });

  // Try Supabase signed URL first
  if (supabase && pdf.storage_path) {
    try {
      const signed = await createSignedUrlForPath(pdf.storage_path, 60);
      // Optionally allow inline view or attachment
      const asAttachment = String(req.query.dl || "") === "1";
      if (asAttachment) {
        return res.redirect(signed); // browser will download if content-disposition set by storage or you can fetch and pipe.
      } else {
        return res.redirect(signed);
      }
    } catch (e) {
      console.error("Signed URL creation failed:", e);
      // fallback to local
    }
  }

  const file = path.join(PDF_DIR, pdf.file_name || "");
  if (!fs.existsSync(file)) return res.status(404).json({ error: "File missing" });

  res.setHeader("Content-Type", "application/octet-stream");
  const asAttachment = String(req.query.dl || "") === "1";
  const disp = asAttachment ? "attachment" : "inline";
  res.setHeader("Content-Disposition", `${disp}; filename="${(pdf.title || pdf.id).replace(/[^a-z0-9_\\-\\.]+/gi, "_")}.pdf"`);

  fs.createReadStream(file).pipe(res);
  db.data.downloadTokens = db.data.downloadTokens.filter((t) => t.token !== tok.token);
  await saveDb();
});

/* === ZIP download of purchased PDFs === */
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
      // if Supabase and storage_path present, stream via signed URL
      if (supabase && p.storage_path) {
        try {
          const signed = await createSignedUrlForPath(p.storage_path, 60);
          const r = await fetch(signed);
          if (!r.ok) throw new Error(`Fetch failed ${r.status}`);
          const nice = `${(p.title || p.id).replace(/[^a-z0-9_\\-\\.]+/gi, "_")}.pdf`;
          archive.append(r.body, { name: nice });
          added++;
          continue;
        } catch (e) {
          console.error("Failed to fetch signed url for zip entry:", p.id, e);
          // fallback to local below
        }
      }

      // fallback to local file add
      const fp = path.join(PDF_DIR, p.file_name || "");
      if (!p.file_name || !fs.existsSync(fp)) continue;
      const nice = `${(p.title || p.id).replace(/[^a-z0-9_\\-\\.]+/gi, "_")}.pdf`;
      archive.file(fp, { name: nice });
      added++;
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
// ... rest of admin routes unchanged (deletion, metrics, users, etc) - present above in full file

/* ===================== CONTACT → INBOX ===================== */
// ... unchanged - keep the same code you already have

/* ========= CHAT ROUTES ========= */
// ... unchanged

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
