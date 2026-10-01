const express = require("express");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, "data");
const USERS_FILE = path.join(DATA_DIR, "users.json");
const REQUESTS_FILE = path.join(DATA_DIR, "emergency-requests.json");

fs.mkdirSync(DATA_DIR, { recursive: true });
function ensureJson(file, fallback) {
  if (!fs.existsSync(file)) fs.writeFileSync(file, JSON.stringify(fallback, null, 2));
}
ensureJson(USERS_FILE, []);
ensureJson(REQUESTS_FILE, []);

app.use(express.json({ limit: "1mb" }));
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", req.headers.origin || "*");
  res.header("Vary", "Origin");
  res.header("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.header("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});
app.use(express.static(path.join(__dirname, "public")));

const sessions = new Map();
const SESSION_MS = 7 * 24 * 60 * 60 * 1000;

function readJson(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, "utf8")); } catch { return fallback; }
}
function writeJson(file, value) {
  const temp = file + ".tmp";
  fs.writeFileSync(temp, JSON.stringify(value, null, 2));
  fs.renameSync(temp, file);
}
function publicUser(user) {
  return { id: user.id, name: user.name, email: user.email, phone: user.phone || "", createdAt: user.createdAt, donorProfile: user.donorProfile || null };
}
function hashPassword(password, saltHex) {
  const salt = saltHex ? Buffer.from(saltHex, "hex") : crypto.randomBytes(16);
  const hash = crypto.scryptSync(password, salt, 64);
  return { salt: salt.toString("hex"), hash: hash.toString("hex") };
}
function verifyPassword(password, user) {
  const derived = crypto.scryptSync(password, Buffer.from(user.passwordSalt, "hex"), 64);
  const stored = Buffer.from(user.passwordHash, "hex");
  return stored.length === derived.length && crypto.timingSafeEqual(stored, derived);
}
function createSession(userId) {
  const token = crypto.randomBytes(32).toString("hex");
  sessions.set(token, { userId, expiresAt: Date.now() + SESSION_MS });
  return token;
}
function authUser(req, res) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  const session = sessions.get(token);
  if (!session || session.expiresAt < Date.now()) {
    if (token) sessions.delete(token);
    res.status(401).json({ error: "Please log in again." });
    return null;
  }
  const users = readJson(USERS_FILE, []);
  const user = users.find(u => u.id === session.userId);
  if (!user) { sessions.delete(token); res.status(401).json({ error: "Account not found." }); return null; }
  req.authToken = token;
  return user;
}

app.get("/api/health", (req, res) => res.json({ status: "ok", project: "VEMU Blood Donation Platform", time: new Date().toISOString() }));

app.post("/api/auth/register", (req, res) => {
  const { name, email, phone, password } = req.body || {};
  if (!name || !email || !password) return res.status(400).json({ error: "Name, email and password are required." });
  if (String(password).length < 6) return res.status(400).json({ error: "Password must be at least 6 characters." });
  const normalizedEmail = String(email).trim().toLowerCase();
  const users = readJson(USERS_FILE, []);
  if (users.some(u => u.email === normalizedEmail)) return res.status(409).json({ error: "An account with this email already exists." });
  const { salt, hash } = hashPassword(String(password));
  const user = {
    id: `user-${Date.now()}-${crypto.randomBytes(4).toString("hex")}`,
    name: String(name).trim(), email: normalizedEmail, phone: String(phone || "").trim(),
    passwordSalt: salt, passwordHash: hash, createdAt: new Date().toISOString(), donorProfile: null
  };
  users.push(user); writeJson(USERS_FILE, users);
  const token = createSession(user.id);
  res.status(201).json({ token, user: publicUser(user) });
});

app.post("/api/auth/login", (req, res) => {
  const { email, password } = req.body || {};
  const users = readJson(USERS_FILE, []);
  const user = users.find(u => u.email === String(email || "").trim().toLowerCase());
  if (!user || !verifyPassword(String(password || ""), user)) return res.status(401).json({ error: "Invalid email or password." });
  const token = createSession(user.id);
  res.json({ token, user: publicUser(user) });
});

app.post("/api/auth/logout", (req, res) => {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  if (token) sessions.delete(token);
  res.json({ ok: true });
});

app.get("/api/auth/me", (req, res) => {
  const user = authUser(req, res); if (!user) return;
  res.json({ user: publicUser(user) });
});

app.get("/api/profile", (req, res) => {
  const user = authUser(req, res); if (!user) return;
  res.json({ user: publicUser(user) });
});

app.put("/api/profile", (req, res) => {
  const user = authUser(req, res); if (!user) return;
  const users = readJson(USERS_FILE, []);
  const index = users.findIndex(u => u.id === user.id);
  const incoming = req.body || {};
  users[index].name = String(incoming.name || users[index].name).trim();
  users[index].phone = String(incoming.phone || "").trim();
  if (incoming.donorProfile) users[index].donorProfile = { ...incoming.donorProfile, userId: user.id, updatedAt: new Date().toISOString() };
  writeJson(USERS_FILE, users);
  res.json({ user: publicUser(users[index]) });
});

app.get("/api/donors", (req, res) => {
  const users = readJson(USERS_FILE, []);
  const group = String(req.query.group || "").trim();
  const city = String(req.query.city || "").trim().toLowerCase();
  const donors = users.filter(u => u.donorProfile && u.donorProfile.group && u.donorProfile.city && u.donorProfile.dob && u.donorProfile.age >= 18 && u.donorProfile.available !== false)
    .map(u => ({ id: u.id, name: u.name, phone: u.phone, source: "people-portal", registeredAt: u.createdAt, verifiedByPeoplePortal: true, ...u.donorProfile }))
    .filter(d => !group || group === "All Groups" || d.group === group)
    .filter(d => !city || String(d.city || "").toLowerCase().includes(city));
  res.json({ donors });
});

app.post("/api/emergency-requests", (req, res) => {
  const user = authUser(req, res); if (!user) return;
  const b = req.body || {};
  if (!b.patient || !b.group || !b.phone || !b.latitude || !b.longitude) return res.status(400).json({ error: "Patient, blood group, phone and location are required." });
  const requests = readJson(REQUESTS_FILE, []).filter(r => new Date(r.expiresAt).getTime() > Date.now());
  const request = {
    id: `request-${Date.now()}-${crypto.randomBytes(4).toString("hex")}`,
    userId: user.id, patient: String(b.patient).trim(), group: b.group, hospital: String(b.hospital || "").trim(),
    city: String(b.city || "").trim(), phone: String(b.phone).trim(), units: String(b.units || "1"),
    latitude: Number(b.latitude), longitude: Number(b.longitude), locationAddress: String(b.locationAddress || "").trim(),
    createdAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString()
  };
  requests.unshift(request); writeJson(REQUESTS_FILE, requests);
  res.status(201).json({ request });
});

app.get("/api/emergency-requests", (req, res) => {
  const requests = readJson(REQUESTS_FILE, []).filter(r => new Date(r.expiresAt).getTime() > Date.now());
  res.json({ requests });
});

app.get("/api/my-emergency-requests", (req, res) => {
  const user = authUser(req, res); if (!user) return;
  const requests = readJson(REQUESTS_FILE, []).filter(r => r.userId === user.id && new Date(r.expiresAt).getTime() > Date.now());
  res.json({ requests });
});

app.get("*", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));
app.listen(PORT, () => console.log(`VEMU Blood Donation Platform running at http://localhost:${PORT}`));
