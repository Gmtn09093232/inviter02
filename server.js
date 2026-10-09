/* ========================================================================
 * WAREHOUSE IMS — MINIMAL ADMIN SERVER
 * ------------------------------------------------------------------------
 * This tiny Node.js server is ONLY needed for operations that require
 * the Supabase service_role key (which must never be in the browser).
 *
 * Everything else (CRUD, approvals, auth, reports) is handled by Supabase
 * directly from the HTML page via @supabase/supabase-js.
 * ======================================================================== */

'use strict';

const express = require('express');
const cors    = require('cors');
const { createClient } = require('@supabase/supabase-js');

// ---------------------------------------------------------------------
// CONFIG
// ---------------------------------------------------------------------
const PORT             = process.env.PORT || 4000;
const SUPABASE_URL     = process.env.SUPABASE_URL;
const SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY; // ⚠️ SECRET — never expose

if (!SUPABASE_URL || !SERVICE_ROLE_KEY) {
  console.error('Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY env vars.');
  process.exit(1);
}

const admin = createClient(SUPABASE_URL, SERVICE_ROLE_KEY, {
  auth: { autoRefreshToken: false, persistSession: false },
});

// ---------------------------------------------------------------------
// EXPRESS
// ---------------------------------------------------------------------
const app = express();
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '2mb' }));

// Verify a user's JWT and return their profile + role
async function requireAuth(req, res, next) {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'NOT_AUTHENTICATED' });

  const { data: { user }, error } = await admin.auth.getUser(token);
  if (error || !user) return res.status(401).json({ error: 'INVALID_TOKEN' });

  const { data: profile } = await admin
    .from('profiles')
    .select('id,name,role,active')
    .eq('id', user.id)
    .single();

  if (!profile || !profile.active) return res.status(403).json({ error: 'FORBIDDEN' });

  req.user = profile;
  next();
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
 * Creates a new user with a hashed password in Supabase Auth,
 * then inserts a matching profile row.
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

  // 1. Create auth user
  const { data: created, error: authErr } = await admin.auth.admin.createUser({
    email,
    password,
    email_confirm: true,
    user_metadata: { username, name, role },
  });
  if (authErr) return res.status(400).json({ error: authErr.message });

  // 2. Create profile row (the trigger may also do this — use upsert to be safe)
  const { error: profErr } = await admin.from('profiles').upsert({
    id: created.user.id,
    username,
    name,
    role,
    active: true,
  });
  if (profErr) return res.status(400).json({ error: profErr.message });

  // 3. Audit
  await admin.from('audit_logs').insert([{
    user_id: req.user.id,
    user_name: req.user.name,
    action: 'USER_CREATED',
    note: `${username} (${role})`,
  }]);

  res.status(201).json({ success: true, data: { id: created.user.id } });
});

/**
 * DELETE /admin/users/:id
 * Deactivates a user (never physically deletes for audit integrity).
 */
app.post('/admin/users/:id/deactivate', requireAuth, requireRole('super_admin'), async (req, res) => {
  const { error } = await admin.from('profiles').update({ active: false }).eq('id', req.params.id);
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
 * POST /admin/notify
 * Sends email/SMS using an external provider — server-side only.
 * (Wire in Resend, SendGrid, Twilio, etc.)
 */
app.post('/admin/notify', requireAuth, requireRole('super_admin', 'warehouse_manager'), async (req, res) => {
  const { to, subject, body } = req.body || {};
  // TODO: hook into your email/SMS provider here
  console.log('Would notify:', { to, subject, body });
  res.json({ success: true });
});

/**
 * POST /cron/sla-check
 * Scheduled job — escalate overdue approvals.
 * Trigger from cron on Render/Fly/Upstash QStash/etc.
 */
app.post('/cron/sla-check', async (req, res) => {
  // Simple shared-secret guard
  if (req.headers['x-cron-secret'] !== process.env.CRON_SECRET) {
    return res.status(403).json({ error: 'FORBIDDEN' });
  }

  const { data: overdue } = await admin
    .from('transactions')
    .select('id,number,required_role,submitted_at')
    .eq('status', 'Pending Approval')
    .lt('submitted_at', new Date(Date.now() - 24*3600*1000).toISOString());

  for (const t of overdue || []) {
    await admin.from('notifications').insert([{
      user_id: null, // broadcast — or find manager IDs
      title: 'Approval overdue',
      message: `${t.number} has been pending > 24h`,
      link: t.number,
    }]);
  }

  res.json({ success: true, overdue: overdue?.length || 0 });
});

// Health check
app.get('/health', (_, res) => res.json({ ok: true, time: new Date().toISOString() }));

// ---------------------------------------------------------------------
// BOOT
// ---------------------------------------------------------------------
app.listen(PORT, () => {
  console.log(`🏭 Minimal admin server listening on http://localhost:${PORT}`);
  console.log('   All warehouse operations are handled by Supabase directly.');
  console.log('   This server only handles admin-only operations.');
});
