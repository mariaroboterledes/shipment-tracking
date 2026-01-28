import express from "express";
import sqlite3 from "sqlite3";
import { open } from "sqlite";
import cookieParser from "cookie-parser";
import path from "path";
import { fileURLToPath } from "url";
import crypto from "crypto";

// ====== إعداد المسارات ======
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ====== إعداد التطبيق ======
const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

// ====== إعدادات الإدارة (غيّرها لاحقًا) ======
app.post("/api/admin/login", (req, res) => {
  const { email, password } = req.body;

  if (email !== ADMIN_USERNAME || password !== ADMIN_PASSWORD) {
    return res.status(401).json({ error: "Invalid username or password" });
  }

  const token = `${email}|${sign(email)}`;
  res.cookie("admin_token", token, {
    httpOnly: true,
    sameSite: "lax"
  });

  res.json({ ok: true });
});


// ====== قاعدة البيانات (SQLite) ======
const db = await open({
  filename: path.join(__dirname, "tracking.db"),
  driver: sqlite3.Database
});

// إنشاء الجداول إن لم تكن موجودة
await db.exec(`
CREATE TABLE IF NOT EXISTS shipments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  trackingId TEXT UNIQUE NOT NULL,
  currentStatus TEXT NOT NULL,
  updatedAt TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  trackingId TEXT NOT NULL,
  status TEXT NOT NULL,
  note TEXT,
  createdAt TEXT NOT NULL
);
`);

// ====== أدوات مساعدة ======
function nowISO() {
  return new Date().toISOString();
}

function sign(value) {
  return crypto
    .createHmac("sha256", SESSION_SECRET)
    .update(value)
    .digest("hex");
}

// ====== Middleware حماية الإدارة ======
function requireAdmin(req, res, next) {
  const token = req.cookies.admin_token;
  if (!token) return res.status(401).json({ error: "غير مصرح" });

  const [email, sig] = token.split("|");
  if (email !== ADMIN_EMAIL) return res.status(401).json({ error: "غير مصرح" });
  if (sign(email) !== sig) return res.status(401).json({ error: "جلسة غير صالحة" });

  next();
}

// ====== API عامة (للعميل) ======
app.get("/api/track/:trackingId", async (req, res) => {
  const trackingId = req.params.trackingId;

  const shipment = await db.get(
    "SELECT trackingId, currentStatus, updatedAt FROM shipments WHERE trackingId = ?",
    trackingId
  );

  if (!shipment) {
    return res.status(404).json({ error: "رقم التتبع غير موجود" });
  }

  const events = await db.all(
    "SELECT status, note, createdAt FROM events WHERE trackingId = ? ORDER BY createdAt DESC",
    trackingId
  );

  res.json({
    ...shipment,
    events
  });
});

// ====== API الإدارة ======
app.post("/api/admin/login", (req, res) => {
  const { email, password } = req.body;

  if (email !== ADMIN_EMAIL || password !== ADMIN_PASSWORD) {
    return res.status(401).json({ error: "بيانات الدخول غير صحيحة" });
  }

  const token = `${email}|${sign(email)}`;
  res.cookie("admin_token", token, {
    httpOnly: true,
    sameSite: "lax"
  });

  res.json({ ok: true });
});

app.post("/api/admin/create", requireAdmin, async (req, res) => {
  const { trackingId, status, note } = req.body;

  if (!trackingId || !status) {
    return res.status(400).json({ error: "Tracking ID والحالة مطلوبة" });
  }

  try {
    await db.run(
      "INSERT INTO shipments (trackingId, currentStatus, updatedAt) VALUES (?, ?, ?)",
      trackingId,
      status,
      nowISO()
    );

    await db.run(
      "INSERT INTO events (trackingId, status, note, createdAt) VALUES (?, ?, ?, ?)",
      trackingId,
      status,
      note || "",
      nowISO()
    );

    res.json({ ok: true });
  } catch (e) {
    res.status(400).json({ error: "Tracking ID موجود مسبقًا" });
  }
});

app.post("/api/admin/update", requireAdmin, async (req, res) => {
  const { trackingId, status, note } = req.body;

  if (!trackingId || !status) {
    return res.status(400).json({ error: "Tracking ID والحالة مطلوبة" });
  }

  const shipment = await db.get(
    "SELECT id FROM shipments WHERE trackingId = ?",
    trackingId
  );

  if (!shipment) {
    return res.status(404).json({ error: "الشحنة غير موجودة" });
  }

  await db.run(
    "UPDATE shipments SET currentStatus = ?, updatedAt = ? WHERE trackingId = ?",
    status,
    nowISO(),
    trackingId
  );

  await db.run(
    "INSERT INTO events (trackingId, status, note, createdAt) VALUES (?, ?, ?, ?)",
    trackingId,
    status,
    note || "",
    nowISO()
  );

  res.json({ ok: true });
});

// ====== تشغيل السيرفر ======
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
