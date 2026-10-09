/* ========================================================================
 * WAREHOUSE IMS — MINIMAL ADMIN SERVER
 * ------------------------------------------------------------------------
 * This tiny Node.js server does two jobs:
 *   1. Serves the static HTML files (index.html, manager.html, auditor.html)
 *   2. Exposes admin-only endpoints that require the Supabase service_role key
 *
 * Everything else (CRUD, approvals, auth, reports) is handled by Supabase
 * directly from the HTML page via @supabase/supabase-js.
 * ======================================================================== */

'use strict';

// ---------------------------------------------------------------------
// IMPORTS
// ---------------------------------------------------------------------
const express = require('express');
const cors    = require('cors');
const path    = require('path');
const { createClient } = require('@supabase/supabase-js');

// ---------------------------------------------------------------------
// CONFIG  (read from environment variables — set these in Render .env)
// ---------------------------------------------------------------------
const PORT             = process.env.PORT || 4000;
const SUPABASE_URL     = process.env.SUPABASE_URL;
const SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY; // ⚠️ SECRET — never expose
const CRON_SECRET      = process.env.CRON_SECRET || 'change-me';

if (!SUPABASE_URL || !SERVICE_ROLE_KEY) {
  console.error('❌ Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY environment variables.');
  process.exit(1);
}

// ---------------------------------------------------------------------
// SUPABASE ADMIN CLIENT
// ---------------------------------------------------------------------
const admin = createClient(SUPABASE_URL, SERVICE_ROLE_KEY, {
  auth: { autoRefreshToken: false, persistSession: false },
});

// ---------------------------------------------------------------------
// EXPRESS APP  (⚠️ app must be declared BEFORE any app.use / app.get)
// ---------------------------------------------------------------------
const app = express();

// --- Global middleware (order matters) ---
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true }));

// ---------------------------------------------------------------------
// STATIC FILE SERVING
// Serves the HTML files from the project root.
// This is what makes https://your-app.onrender.com/ work.
// ---------------------------------------------------------------------
app.use(express.static(__dirname));

// Root route
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Friendly routes for the other pages
app.get('/manager', (req, res) => {
  res.sendFile(path.join(__dirname, 'manager.html'));
});

app.get('/auditor', (req, res) => {
  res.sendFile(path.join(__dirname, 'auditor.html'));
});

// ---------------------------------------------------------------------
// AUTH MIDDLEWARE  (verifies Supabase JWT and loads user profile)
// ---------------------------------------------------------------------
async function requireAuth(req, res, next) {
  const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  if (!token) return res.status(401).json({ error: 'NOT_AUTHENTICATED' });

  try {
    const { data: { user }, error } = await admin.auth.getUser(token);
    if (error || !user) return res.status(401).json({ error: 'INVALID_TOKEN' });

    const { data: profile, error: pErr } = await admin
      .from('profiles')
      .select('id,name,role,active')
      .eq('id', user.id)
      .single();

    if (pErr || !profile || !profile.active) {
      return res.status(403).json({ error: 'FORBIDDEN' });
    }

    req.user = profile;
    next();
  } catch (e) {
    return res.status(500).json({ error: 'AUTH_FAILED', message: e.message });
  }
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'ROLE_NOT_ALLOWED' });
    }
    next();
  };
}

// ---------------------------------------------------------------------
// ADMIN-ONLY ENDPOINTS
// ---------------------------------------------------------------------

/**
 * POST /admin/users
 * Creates a new user in Supabase Auth (hashed password) + matching profile row.
 */
app.post('/admin/users', requireAuth, requireRole('super_admin'), async (req, res) => {
  const { username, password, name, role } = req.body || {};

  if (!username || !password || !name || !role) {
    return res.status(422).json({ error: 'VALIDATION', message: 'All fields required.' });
  }
  if (!['super_admin', 'warehouse_manager', 'storekeeper', 'auditor'].includes(role)) {
    return res.status(422).json({ error: 'VALIDATION', message: 'Invalid role.' });
  }

  const email = `${username}@wms.local`;

  // 1. Create the auth user
  const { data: created, error: authErr } = await admin.auth.admin.createUser({
    email,
    password,
    email_confirm: true,
    user_metadata: { username, name, role },
  });
  if (authErr) return res.status(400).json({ error: authErr.message });

  // 2. Upsert the profile row (the DB trigger may also create it)
  const { error: profErr } = await admin.from('profiles').upsert({
    id: created.user.id,
    username,
    name,
    role,
    active: true,
  });
  if (profErr) return res.status(400).json({ error: profErr.message });

  // 3. Audit log
  await admin.from('audit_logs').insert([{
    user_id: req.user.id,
    user_name: req.user.name,
    action: 'USER_CREATED',
    note: `${username} (${role})`,
  }]);

  res.status(201).json({ success: true, data: { id: created.user.id } });
});

/**
 * POST /admin/users/:id/deactivate
 * Deactivates a user — never physically deletes (audit integrity).
 */
app.post('/admin/users/:id/deactivate', requireAuth, requireRole('super_admin'), async (req, res) => {
  const { error } = await admin
    .from('profiles')
    .update({ active: false })
    .eq('id', req.params.id);
  if (error) return res.status(400).json({ error: error.message });

  await admin.from('audit_logs').insert([{
    user_id: req.user.id,
    user_name: req.user.name,
    action: 'USER_DEACTIVATED',
    note: req.params.id,
  }]);

  res.json({ success: true });
});

/**
 * GET /admin/users
 * Lists all users (super_admin only).
 */
app.get('/admin/users', requireAuth, requireRole('super_admin'), async (req, res) => {
  const { data, error } = await admin
    .from('profiles')
    .select('id,username,name,role,active,created_at')
    .order('name');
  if (error) return res.status(400).json({ error: error.message });
  res.json({ success: true, data });
});

/**
 * POST /admin/notify
 * Placeholder for email/SMS — wire in Resend, SendGrid, Twilio, etc.
 */
app.post('/admin/notify', requireAuth, requireRole('super_admin', 'warehouse_manager'), async (req, res) => {
  const { to, subject, body } = req.body || {};
  // TODO: hook into your email/SMS provider here
  console.log('📧 Would notify:', { to, subject, body });
  res.json({ success: true });
});

/**
 * POST /cron/sla-check
 * Scheduled job — marks/escalates overdue approvals.
 * Trigger from a cron on Render/Fly/Upstash QStash/etc.
 */
app.post('/cron/sla-check', async (req, res) => {
  if (req.headers['x-cron-secret'] !== CRON_SECRET) {
    return res.status(403).json({ error: 'FORBIDDEN' });
  }

  const cutoff = new Date(Date.now() - 24 * 3600 * 1000).toISOString();
  const { data: overdue, error } = await admin
    .from('transactions')
    .select('id,number,required_role,submitted_at')
    .eq('status', 'Pending Approval')
    .lt('submitted_at', cutoff);

  if (error) return res.status(500).json({ error: error.message });

  // Broadcast a notification to managers (userId null = broadcast convention)
  for (const t of overdue || []) {
    await admin.from('notifications').insert([{
      user_id: null,
      title: 'Approval overdue',
      message: `${t.number} has been pending > 24h`,
      link: t.number,
    }]);
  }

  res.json({ success: true, overdue: overdue?.length || 0 });
});

// ---------------------------------------------------------------------
// HEALTH CHECK  (Render uses this to verify the service is up)
// ---------------------------------------------------------------------
app.get('/health', (_req, res) => {
  res.json({ ok: true, time: new Date().toISOString() });
});

// ---------------------------------------------------------------------
// 404 + ERROR HANDLERS  (must be last)
// ---------------------------------------------------------------------
app.use((req, res) => {
  res.status(404).sendFile(path.join(__dirname, 'index.html'));
});

app.use((err, _req, res, _next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'INTERNAL_ERROR', message: err.message });
});

// ---------------------------------------------------------------------
// BOOT
// ---------------------------------------------------------------------
app.listen(PORT, () => {
  console.log(`🏭 Warehouse IMS admin server listening on http://localhost:${PORT}`);
  console.log(`   Serving static files from: ${__dirname}`);
  console.log('   All warehouse operations are handled by Supabase directly.');
  console.log('   This server only handles admin-only operations.');
});
