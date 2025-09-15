const express = require("express");
const fs = require("fs");
const path = require("path");
const session = require("express-session");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");

const app = express();
const PORT = process.env.PORT || 3000;
const LOG_FILE = path.join(__dirname, "visits.json");

const ADMIN_USER = process.env.ADMIN_USER || "wxrmane";
const ADMIN_PASS = process.env.ADMIN_PASS || "ddos";

app.use(helmet());
app.set("trust proxy", 1);
app.use(express.urlencoded({ extended: true }));
app.use(
  session({
    secret: process.env.SESSION_SECRET || "change_this_secret",
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, maxAge: 24 * 60 * 60 * 1000 },
  })
);

app.use(
  rateLimit({
    windowMs: 15 * 1000,
    max: 200,
    standardHeaders: true,
    legacyHeaders: false,
  })
);

function getClientIP(req) {
  const xf = req.headers["x-forwarded-for"];
  if (xf) return xf.split(",")[0].trim();
  if (req.ip && req.ip.includes("::ffff:")) return req.ip.split("::ffff:")[1];
  return req.ip || req.connection.remoteAddress || "unknown";
}

function readLogs() {
  try {
    if (!fs.existsSync(LOG_FILE)) return [];
    return JSON.parse(fs.readFileSync(LOG_FILE, "utf8") || "[]");
  } catch {
    return [];
  }
}
function writeLogs(arr) {
  fs.writeFileSync(LOG_FILE, JSON.stringify(arr, null, 2), "utf8");
}
function appendLog(entry) {
  const arr = readLogs();
  arr.push(entry);
  writeLogs(arr);
}
function escapeHtml(s) {
  if (!s) return "";
  return String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}

app.get("/", (req, res) => {
  const ip = getClientIP(req);
  const ua = (req.get("User-Agent") || "").slice(0, 800);
  appendLog({ ip, ts: new Date().toISOString(), ua, path: req.path });
  res.sendFile(path.join(__dirname, "index.html"));
});

app.post("/login", (req, res) => {
  const { login, password } = req.body || {};
  if (login === ADMIN_USER && password === ADMIN_PASS) {
    req.session.auth = true;
    req.session.user = login;
    return res.redirect("/admin");
  }
  res.status(401).send(`<p>Неверный логин/пароль. <a href="/">Назад</a></p>`);
});

function requireAuth(req, res, next) {
  if (req.session && req.session.auth) return next();
  res.redirect("/");
}

app.get("/admin", requireAuth, (req, res) => {
  const logs = readLogs().slice().reverse();
  const rows = logs
    .map(
      (v, i) => `<tr>
      <td>${i + 1}</td>
      <td>${escapeHtml(v.ip)}</td>
      <td>${escapeHtml(v.ts)}</td>
      <td>${escapeHtml(v.ua)}</td>
    </tr>`
    )
    .join("\n");

  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(`<!doctype html>
<html>
<head><meta charset="utf-8"><title>Admin — Logs</title>
<style>
body { font-family: Arial, sans-serif; padding: 16px; }
table { border-collapse: collapse; width: 100%; }
th, td { border: 1px solid #ddd; padding: 8px; }
th { background: #f4f4f4; }
</style>
</head>
<body>
  <h2>Логи посещений</h2>
  <p>Вы вошли как <strong>${escapeHtml(req.session.user)}</strong>. <a href="/logout">Выйти</a></p>
  <form method="post" action="/admin/clear" onsubmit="return confirm('Очистить логи?')">
    <button type="submit">Очистить логи</button>
  </form>
  <table>
    <thead><tr><th>#</th><th>IP</th><th>Время</th><th>User-Agent</th></tr></thead>
    <tbody>${rows}</tbody>
  </table>
</body>
</html>`);
});

app.post("/admin/clear", requireAuth, (req, res) => {
  writeLogs([]);
  res.redirect("/admin");
});

app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/"));
});

app.listen(PORT, () => {
  console.log(`Server listening on http://localhost:${PORT}`);
}); 
