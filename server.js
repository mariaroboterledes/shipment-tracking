import express from "express";
import sqlite3 from "sqlite3";
import { open } from "sqlite";
import cookieParser from "cookie-parser";
import path from "path";
import { fileURLToPath } from "url";
import crypto from "crypto";

// ====== Paths ======
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ====== App ======
const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

// ====== BASE URL (OPTIONAL: for generating full links) ======
const BASE_URL = process.env.BASE_URL || "https://shipment-tracking-mrj2.onrender.com";

// ====== ADMIN CREDENTIALS (STATIC) ======
const ADMIN_USERNAME = "admin";
const ADMIN_PASSWORD = "Maria@2026";

// ====== Session secret (keep this) ======
const SESSION_SECRET = process.env.SESSION_SECRET || "super-secret-key";

// ====== Database (SQLite) ======
const db = await open({
  filename: path.join(__dirname, "tracking.db"),
  driver: sqlite3.Database,
});

// Create tables if not exist
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

// ===== Helpers =====
function nowISO() {
  return new Date().toISOString();
}

function sign(value) {
  return crypto.createHmac("sha256", SESSION_SECRET).update(value).digest("hex");
}

// ===== Admin guard =====
function requireAdmin(req, res, next) {
  const token = req.cookies.admin_token;
  if (!token) return res.status(401).json({ error: "Not authorized" });

  const [username, sig] = token.split("|");
  if (username !== ADMIN_USERNAME) return res.status(401).json({ error: "Not authorized" });
  if (sign(username) !== sig) return res.status(401).json({ error: "Invalid session" });

  next();
}

// ===== Pretty routes (professional URLs) =====

// Open admin login page via /admin/login
app.get("/admin/login", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "admin.html"));
});

// Optional: open tracking page via /track
app.get("/track", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "track.html"));
});

// Optional: redirect home to tracking page (so base URL isn't blank)
app.get("/", (req, res) => {
  res.redirect("/track");
});

// ===== Public API (customer) =====
app.get("/api/track/:trackingId", async (req, res) => {
  const trackingId = req.params.trackingId;

  const shipment = await db.get(
    "SELECT trackingId, currentStatus, updatedAt FROM shipments WHERE trackingId = ?",
    trackingId
  );

  if (!shipment) {
    return res.status(404).json({ error: "Tracking ID not found" });
  }

  const events = await db.all(
    "SELECT status, note, createdAt FROM events WHERE trackingId = ? ORDER BY createdAt DESC",
    trackingId
  );

  res.json({ ...shipment, events });
});

// ===== Admin API =====
app.post("/api/admin/login", (req, res) => {
  const { email, password } = req.body; // "email" field is used as username in admin.html

  if (email !== ADMIN_USERNAME || password !== ADMIN_PASSWORD) {
    return res.status(401).json({ error: "Invalid username or password" });
  }

  const token = `${email}|${sign(email)}`;
  res.cookie("admin_token", token, {
    httpOnly: true,
    sameSite: "lax",
    // secure: true, // Render uses HTTPS. You can enable this later if needed.
  });

  res.json({ ok: true });
});

// Create shipment
app.post("/api/admin/create", requireAdmin, async (req, res) => {
  const { trackingId, status, note } = req.body;

  if (!trackingId || !status) {
    return res.status(400).json({ error: "Tracking ID and status are required" });
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

    // Full customer link (optional)
    const trackingLink = `${BASE_URL}/track.html?tid=${encodeURIComponent(trackingId)}`;

    res.json({ ok: true, trackingLink });
  } catch (e) {
    res.status(400).json({ error: "Tracking ID already exists" });
  }
});

// Add update
app.post("/api/admin/update", requireAdmin, async (req, res) => {
  const { trackingId, status, note } = req.body;

  if (!trackingId || !status) {
    return res.status(400).json({ error: "Tracking ID and status are required" });
  }

  const shipment = await db.get("SELECT id FROM shipments WHERE trackingId = ?", trackingId);
  if (!shipment) {
    return res.status(404).json({ error: "Shipment not found" });
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

// ===== Start server =====
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Admin (pretty): ${BASE_URL}/admin/login`);
  console.log(`Admin (file):   ${BASE_URL}/admin.html`);
  console.log(`Track (file):   ${BASE_URL}/track.html`);
  console.log(`Track (pretty): ${BASE_URL}/track`);
});

