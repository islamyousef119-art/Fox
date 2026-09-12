import jwt from "jsonwebtoken";
import crypto from "node:crypto";

const secret = process.env.JWT_SECRET;
if (!secret || secret.length < 32) {
  throw new Error("JWT_SECRET must be at least 32 characters");
}

export function signAdmin(username) {
  return jwt.sign({ sub: username, role: "admin" }, secret, { expiresIn: "8h" });
}
export function requireAdmin(req, res, next) {
  try {
    const token = req.cookies?.admin_token;
    if (!token) return res.status(401).json({ error: "unauthorized" });
    req.admin = jwt.verify(token, secret);
    next();
  } catch {
    res.status(401).json({ error: "unauthorized" });
  }
}
export function safeEqual(a, b) {
  const x = Buffer.from(String(a));
  const y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}
