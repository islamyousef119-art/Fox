import "node:process";
import express from "express";
import cookieParser from "cookie-parser";
import crypto from "node:crypto";
import { db } from "./db.js";
import { signAdmin, requireAdmin, safeEqual } from "./auth.js";

const app = express();
const PORT = Number(process.env.PORT || 3000);
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "admin";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
if (!ADMIN_PASSWORD) throw new Error("Set ADMIN_PASSWORD in .env");

app.use(express.json({ limit: "64kb" }));
app.use(cookieParser());
app.use(express.static("public"));

function normalizeKey(v) {
  return String(v || "").trim().toUpperCase();
}
function makeKey(type) {
  const prefix = type === "admin" ? "ADM" : "F";
  return `${prefix}-${crypto.randomBytes(6).toString("hex").toUpperCase()}`;
}

app.post("/api/auth/login", (req, res) => {
  const { username, password } = req.body || {};
  if (!safeEqual(username, ADMIN_USERNAME) || !safeEqual(password, ADMIN_PASSWORD)) {
    return res.status(401).json({ error: "invalid_credentials" });
  }
  const token = signAdmin(username);
  res.cookie("admin_token", token, {
    httpOnly: true,
    sameSite: "strict",
    secure: process.env.NODE_ENV === "production",
    maxAge: 8 * 60 * 60 * 1000
  });
  res.json({ ok: true });
});

app.post("/api/auth/logout", (req, res) => {
  res.clearCookie("admin_token");
  res.json({ ok: true });
});

app.get("/api/admin/licenses", requireAdmin, (req, res) => {
  const rows = db.prepare(`
    SELECT id,key,type,active,max_uses,used_count,expires_at,note,device_id,created_at,updated_at
    FROM licenses ORDER BY id DESC
  `).all();
  res.json(rows);
});

app.post("/api/admin/licenses", requireAdmin, (req, res) => {
  const body = req.body || {};
  const type = body.type === "admin" ? "admin" : "user";
  const key = normalizeKey(body.key) || makeKey(type);
  const maxUses = Math.max(1, Number(body.max_uses || 1));
  const expiresAt = body.expires_at ? String(body.expires_at) : null;
  const note = String(body.note || "").slice(0, 500);

  try {
    const info = db.prepare(`
      INSERT INTO licenses (key,type,max_uses,expires_at,note)
      VALUES (?,?,?,?,?)
    `).run(key, type, maxUses, expiresAt, note);
    res.status(201).json(db.prepare("SELECT * FROM licenses WHERE id=?").get(info.lastInsertRowid));
  } catch (e) {
    if (String(e.message).includes("UNIQUE")) return res.status(409).json({ error: "key_exists" });
    throw e;
  }
});

app.patch("/api/admin/licenses/:id", requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const current = db.prepare("SELECT * FROM licenses WHERE id=?").get(id);
  if (!current) return res.status(404).json({ error: "not_found" });

  const active = req.body.active === undefined ? current.active : (req.body.active ? 1 : 0);
  const maxUses = req.body.max_uses === undefined ? current.max_uses : Math.max(1, Number(req.body.max_uses));
  const expiresAt = req.body.expires_at === undefined ? current.expires_at : (req.body.expires_at || null);
  const note = req.body.note === undefined ? current.note : String(req.body.note).slice(0,500);
  const deviceId = req.body.device_id === undefined ? current.device_id : (req.body.device_id || null);

  db.prepare(`
    UPDATE licenses SET active=?,max_uses=?,expires_at=?,note=?,device_id=?,updated_at=CURRENT_TIMESTAMP
    WHERE id=?
  `).run(active,maxUses,expiresAt,note,deviceId,id);
  res.json(db.prepare("SELECT * FROM licenses WHERE id=?").get(id));
});

app.delete("/api/admin/licenses/:id", requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const info = db.prepare("DELETE FROM licenses WHERE id=?").run(id);
  if (!info.changes) return res.status(404).json({ error: "not_found" });
  res.json({ ok: true });
});

/*
  Client-facing validation endpoint.
  IMPORTANT: rate-limit this endpoint at your reverse proxy in production.
*/
app.post("/api/license/validate", (req, res) => {
  const key = normalizeKey(req.body?.key);
  const deviceId = String(req.body?.device_id || "").trim().slice(0, 200);
  if (!key) return res.status(400).json({ valid:false, error:"missing_key" });

  const row = db.prepare("SELECT * FROM licenses WHERE key=?").get(key);
  if (!row) return res.status(404).json({ valid:false, error:"invalid_key" });
  if (!row.active) return res.status(403).json({ valid:false, error:"inactive_key" });
  if (row.expires_at && new Date(row.expires_at) <= new Date()) {
    return res.status(403).json({ valid:false, error:"expired_key" });
  }
  if (row.used_count >= row.max_uses) {
    return res.status(403).json({ valid:false, error:"usage_limit_reached" });
  }
  if (row.device_id && deviceId && row.device_id !== deviceId) {
    return res.status(403).json({ valid:false, error:"device_mismatch" });
  }

  const newCount = row.used_count + 1;
  const newDevice = row.device_id || (deviceId || null);
  db.prepare(`
    UPDATE licenses SET used_count=?,device_id=?,updated_at=CURRENT_TIMESTAMP WHERE id=?
  `).run(newCount, newDevice, row.id);

  res.json({
    valid: true,
    type: row.type,
    expires_at: row.expires_at,
    remaining_uses: Math.max(0, row.max_uses - newCount)
  });
});


// Legacy compatibility endpoints for the Android client.
// They mirror the old Firebase JSON shape while using the same SQLite database.
app.get("/codes.json", (req,res) => {
  const rows = db.prepare("SELECT * FROM licenses ORDER BY id DESC").all();
  const out = {};
  for (const row of rows) {
    const key = normalizeKey(row.key).replace(/[.#$\[\]/]/g, "_");
    out[key] = {
      code: row.key,
      maxUses: row.max_uses,
      usedCount: row.used_count,
      note: row.note || "",
      isActive: !!row.active,
      createdAt: row.created_at,
      expiresAt: row.expires_at
    };
  }
  res.json(out);
});

app.get("/codes/:key.json", (req,res) => {
  const key = normalizeKey(req.params.key).replace(/[.#$\[\]/]/g, "_");
  const row = db.prepare("SELECT * FROM licenses WHERE key=?").get(key);
  if (!row) return res.status(404).json({error:"not_found"});
  res.json({
    code: row.key,
    maxUses: row.max_uses,
    usedCount: row.used_count,
    note: row.note || "",
    isActive: !!row.active,
    createdAt: row.created_at,
    expiresAt: row.expires_at
  });
});

app.put("/codes/:key.json", (req,res) => {
  const key = normalizeKey(req.params.key).replace(/[.#$\[\]/]/g, "_");
  const body = req.body || {};
  const current = db.prepare("SELECT * FROM licenses WHERE key=?").get(key);
  const code = normalizeKey(body.code || key);
  const maxUses = Math.max(1, Number(body.maxUses ?? current?.max_uses ?? 1));
  const usedCount = Math.max(0, Number(body.usedCount ?? current?.used_count ?? 0));
  const note = String(body.note ?? current?.note ?? "").slice(0,500);
  const isActive = body.isActive === undefined ? (current ? !!current.active : true) : !!body.isActive;
  const expiresAt = body.expiresAt === undefined ? (current?.expires_at ?? null) : (body.expiresAt || null);
  if (current) {
    db.prepare("UPDATE licenses SET active=?,max_uses=?,used_count=?,expires_at=?,note=?,updated_at=CURRENT_TIMESTAMP WHERE key=?")
      .run(isActive?1:0,maxUses,usedCount,expiresAt,note,key);
  } else {
    try {
      db.prepare("INSERT INTO licenses (key,type,active,max_uses,used_count,expires_at,note) VALUES (?,?,?,?,?,?,?)")
        .run(code, code.startsWith("ADM-") ? "admin" : "user", isActive?1:0,maxUses,usedCount,expiresAt,note);
    } catch (e) {
      return res.status(409).json({error:"key_exists"});
    }
  }
  res.json({code,maxUses,usedCount,note,isActive,createdAt:current?.created_at || new Date().toISOString(),expiresAt});
});

app.delete("/codes/:key.json", (req,res) => {
  const key = normalizeKey(req.params.key).replace(/[.#$\[\]/]/g, "_");
  db.prepare("DELETE FROM licenses WHERE key=?").run(key);
  res.json({ok:true});
});

let maintenanceState = { isEnabled:false, message:"" };
app.get("/maintenance.json", (req,res) => res.json(maintenanceState));
app.put("/maintenance.json", (req,res) => {
  maintenanceState = { isEnabled:!!req.body?.isEnabled, message:String(req.body?.message || "") };
  res.json(maintenanceState);
});

app.get("/health", (req,res) => res.json({ok:true}));

app.listen(PORT, () => console.log(`License server listening on :${PORT}`));
