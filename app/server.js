/**
 * Admin Feedback System — INTENTIONALLY VULNERABLE
 * Scenario: "Cookie Reuse & MFA Bypass"
 *
 * This app is a training target for a Red vs. Blue cyber range lab.
 * Every "vulnerability" below is deliberate and documented — do not use
 * any of these patterns in a real application.
 */

const express = require('express');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3075;

// ---------------------------------------------------------------------------
// "Legit" credentials for the simulated admin user (lab only, not a secret)
// ---------------------------------------------------------------------------
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'FeedbackAdm1n!2025';
const MFA_CODE = process.env.MFA_CODE || '482913'; // shown on-screen for lab convenience

// ---------------------------------------------------------------------------
// In-memory "database" — fine for a disposable training lab
// ---------------------------------------------------------------------------
const feedbackStore = []; // { id, message, submittedAt }
const adminSessions = new Map(); // token -> { username, mfaVerified, createdAt }
const collectedCookies = []; // attacker-side exfil inbox, for the live demo
let authState = { username: null, passwordVerified: false };

// ---------------------------------------------------------------------------
// Logging — writes real nginx/app style lines as the lab is actually used,
// on top of the seeded historical attack narrative (see /logs-seed).
// ---------------------------------------------------------------------------
const LOG_DIR = process.env.LOG_DIR || '/opt/admin/logs';
const ACCESS_LOG = path.join(LOG_DIR, 'access.log');
const ERROR_LOG = path.join(LOG_DIR, 'error.log');

function ensureLogDir() {
  try { fs.mkdirSync(LOG_DIR, { recursive: true }); } catch (e) { /* ignore */ }
}
ensureLogDir();

function nowStamp() {
  return new Date().toISOString();
}

function logAccess(req, status) {
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '-';
  const ua = req.headers['user-agent'] || '-';
  const line = `${ip} - - [${nowStamp()}] "${req.method} ${req.originalUrl} HTTP/1.1" ${status} "-" "${ua}"\n`;
  try { fs.appendFileSync(ACCESS_LOG, line); } catch (e) { /* ignore */ }
}

function logError(level, message) {
  const line = `[${nowStamp()}] [${level}] ${message}\n`;
  try { fs.appendFileSync(ERROR_LOG, line); } catch (e) { /* ignore */ }
}

// ---------------------------------------------------------------------------
// VULN (Recon): expose backend tech via X-Powered-By, on every response
// ---------------------------------------------------------------------------
app.disable('x-powered-by');
app.use((req, res, next) => {
  res.setHeader('X-Powered-By', 'Node.js');
  next();
});

app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Log every request as it completes
app.use((req, res, next) => {
  res.on('finish', () => logAccess(req, res.statusCode));
  next();
});

// ---------------------------------------------------------------------------
// VULN (Recon): robots.txt discloses the "protected" admin routes
// ---------------------------------------------------------------------------
app.get('/robots.txt', (req, res) => {
  res.type('text/plain').send(
    'User-agent: *\n' +
    'Disallow: /api/verify-mfa\n' +
    'Disallow: /dashboard\n'
  );
});

// ---------------------------------------------------------------------------
// VULN (Session Initialization): every visitor gets a fixed, shared,
// non-HttpOnly "pre_mfa_session" cookie — there's no real per-user binding
// before MFA even begins.
// ---------------------------------------------------------------------------
app.use((req, res, next) => {
  if (!req.cookies || !req.cookies.pre_mfa_session) {
    res.cookie('pre_mfa_session', 'pending_mfa_verification', {
      httpOnly: false, // VULN: readable by JavaScript -> stealable via XSS
      path: '/',
    });
  }
  next();
});

// ---------------------------------------------------------------------------
// Static-ish front end (feedback form) — contains an ASCII-art comment
// hinting to check robots.txt (Phase 1 recon breadcrumb)
// ---------------------------------------------------------------------------
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// ---------------------------------------------------------------------------
// Real (if weak) auth: username/password -> MFA code -> adm_sess cookie
// ---------------------------------------------------------------------------
app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  if (username === ADMIN_USER && password === ADMIN_PASS) {
    authState = { username, passwordVerified: true };
    return res.json({ status: 'mfa_required', hint: `MFA code (lab demo only): ${MFA_CODE}` });
  }
  logError('WARN', `Failed login attempt for username="${username}"`);
  return res.status(401).json({ status: 'invalid_credentials' });
});

// This is the path robots.txt disallows, and the path the exploit chain skips
app.post('/api/verify-mfa', (req, res) => {
  const { code } = req.body || {};
  if (!authState.passwordVerified) {
    return res.status(400).json({ status: 'login_required' });
  }
  if (code !== MFA_CODE) {
    logError('WARN', `Invalid MFA code attempt for username="${authState.username}"`);
    return res.status(401).json({ status: 'invalid_code' });
  }
  // VULN (Cookie Vulnerability): issued non-HttpOnly, and — critically — the
  // backend never re-checks this endpoint was hit before trusting the cookie
  // later. That's the actual "MFA bypass": there is no MFA *freshness* or
  // *binding* check on /dashboard, only "does this adm_sess token exist".
  const token = 'adm_sess_' + crypto.randomBytes(12).toString('hex');
  adminSessions.set(token, { username: authState.username, mfaVerified: true, createdAt: Date.now() });
  res.cookie('adm_sess', token, {
    httpOnly: false, // VULN: readable by JavaScript -> stealable via XSS
    path: '/',
  });
  authState = { username: null, passwordVerified: false };
  return res.json({ status: 'ok', redirect: '/dashboard' });
});

// ---------------------------------------------------------------------------
// VULN (Defense Evasion / WAF): naive keyword-based filter.
// Blocks literal "<script" but does nothing for other injection vectors,
// notably <svg onload=...>. This is Phase 2 of the attack path.
// ---------------------------------------------------------------------------
function wafCheck(message) {
  return /<script/i.test(message || '');
}

app.post('/api/feedback', (req, res) => {
  const { message } = req.body || {};

  if (wafCheck(message)) {
    logError('WARN', `WAF blocked <script> payload from ${req.headers['x-forwarded-for'] || req.socket.remoteAddress}`);
    return res.status(403).json({ status: 'blocked', reason: 'WAF: forbidden pattern detected' });
  }

  const entry = { id: feedbackStore.length + 1, message: message || '', submittedAt: new Date().toISOString() };
  feedbackStore.push(entry);
  return res.json({ status: 'received', id: entry.id });
});

// ---------------------------------------------------------------------------
// Attacker's own exfiltration inbox — kept inside the same app so the whole
// exploit chain is demonstrable without any external infrastructure.
// A real attacker would use their own listener; this is a lab convenience.
// ---------------------------------------------------------------------------
app.get('/collect', (req, res) => {
  const cookie = req.query.c || '';
  collectedCookies.push({ cookie, at: new Date().toISOString(), from: req.headers['x-forwarded-for'] || req.socket.remoteAddress });
  logError('CRITICAL', `Cookie reuse / exfiltration event observed. Stolen token fragment captured via /collect.`);
  res.json({ status: 'collected' });
});

app.get('/collected', (req, res) => {
  res.json(collectedCookies);
});

// ---------------------------------------------------------------------------
// Admin-only view of submitted feedback — this is what a *real* admin would
// browse while logged in. It reflects stored messages with NO output
// encoding, so a stored XSS payload fires in the admin's own browser,
// against the admin's own real, non-HttpOnly adm_sess cookie.
// ---------------------------------------------------------------------------
app.get('/admin/review', (req, res) => {
  const token = req.cookies && req.cookies.adm_sess;
  if (!token || !adminSessions.has(token)) {
    return res.status(401).send('<h1>401 - Admin login required</h1><p><a href="/login">Login</a></p>');
  }
  const items = feedbackStore.map(f =>
    `<li>#${f.id} (${f.submittedAt})<br>${f.message}</li>` // VULN: unescaped
  ).join('\n');
  res.send(`<!DOCTYPE html><html><head><title>Feedback Review</title></head>
  <body>
    <h1>Admin: Review Submitted Feedback</h1>
    <nav style="margin-bottom:1em;"><a href="/dashboard">Back to Dashboard</a></nav>
    <ul>${items}</ul>
  </body></html>`);
});

// ---------------------------------------------------------------------------
// VULN (Initial Access / MFA bypass): grants access purely on possession of
// a known adm_sess token. Never calls back into /api/verify-mfa. A replayed
// / stolen cookie is indistinguishable from the legitimate session.
// ---------------------------------------------------------------------------
app.get('/dashboard', (req, res) => {
  const token = req.cookies && req.cookies.adm_sess;
  const session = token && adminSessions.get(token);

  if (!session) {
    return res.status(401).send('<h1>401 - Unauthorized</h1><p><a href="/login">Login</a></p>');
  }

  const lastPayload = feedbackStore.length ? feedbackStore[feedbackStore.length - 1].message : '';

  res.send(`<!DOCTYPE html><html><head><title>Admin Dashboard</title></head>
  <body>
    <h1>Admin Dashboard</h1>
    <p>Welcome back, ${session.username}.</p>
    <nav style="margin:1em 0;"><a href="/admin/review">Review submitted feedback</a></nav>
    <div class="xss-payload">${lastPayload}</div>

    <!-- SCENARIO75{RED_C00k13_MFA_Byp4ss_0wn3d} -->
    <footer style="margin-top:2em;color:#888;font-size:0.8em;">
      Admin Feedback System v1.0
    </footer>
  </body></html>`);
});

app.listen(PORT, () => {
  console.log(`Admin Feedback System listening on port ${PORT}`);
  console.log(`Lab credentials -> ${ADMIN_USER} / ${ADMIN_PASS} | MFA code: ${MFA_CODE}`);
});
