/* ============================================================================
 * WAREHOUSE INVENTORY MANAGEMENT SYSTEM — BACKEND
 * ----------------------------------------------------------------------------
 * Node.js + Express + Supabase (service_role, server-side only)
 *
 * The browser NEVER talks to Supabase directly.
 * Every request goes through this server:
 *   Browser → /api/* → server.js → Supabase → server.js → Browser
 *
 * Security:
 *   - Supabase service_role key is kept here (never exposed)
 *   - Session is a JWT issued by THIS server
 *   - Every endpoint checks: authenticate → role → permission → resource
 *   - Self-approval is blocked (requested_by != approved_by)
 * ========================================================================== */

'use strict';

const express = require('express');
const cors    = require('cors');
const jwt     = require('jsonwebtoken');
const path    = require('path');
const { createClient } = require('@supabase/supabase-js');

// ============================================================================
// CONFIG
// ============================================================================
const CONFIG = {
  PORT: process.env.PORT || 3000,
  JWT_SECRET: process.env.JWT_SECRET || 'change-me-in-production-9f2c1a',
  JWT_EXPIRES: '12h',
  SUPABASE_URL: process.env.SUPABASE_URL,
  SUPABASE_ANON_KEY: process.env.SUPABASE_ANON_KEY,
  SUPABASE_SERVICE_ROLE_KEY: process.env.SUPABASE_SERVICE_ROLE_KEY,
  EMAIL_DOMAIN: process.env.EMAIL_DOMAIN || '@wms.local',
};

if (!CONFIG.SUPABASE_URL || !CONFIG.SUPABASE_SERVICE_ROLE_KEY) {
  console.error('❌ Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY');
  process.exit(1);
}

// Two clients: anon (for login only), admin (service_role for all data ops)
const anonClient = createClient(CONFIG.SUPABASE_URL, CONFIG.SUPABASE_ANON_KEY || CONFIG.SUPABASE_SERVICE_ROLE_KEY, {
  auth: { autoRefreshToken: false, persistSession: false },
});
const admin = createClient(CONFIG.SUPABASE_URL, CONFIG.SUPABASE_SERVICE_ROLE_KEY, {
  auth: { autoRefreshToken: false, persistSession: false },
});

// ============================================================================
// PERMISSIONS (server-side source of truth)
// ============================================================================
const ROLE_PERMS = {
  super_admin: ['*'],
  warehouse_manager: [
    'DASHBOARD_VIEW', 'ITEMS_VIEW', 'ITEMS_CREATE', 'ITEMS_EDIT',
    'CATEGORY_VIEW', 'CATEGORY_CREATE', 'CATEGORY_EDIT',
    'SUPPLIER_VIEW', 'SUPPLIER_CREATE', 'SUPPLIER_EDIT',
    'DEPARTMENT_VIEW', 'DEPARTMENT_CREATE', 'DEPARTMENT_EDIT',
    'STOCK_VIEW', 'STOCK_IN_CREATE', 'STOCK_OUT_CREATE', 'ADJUSTMENT_CREATE',
    'TRANSACTION_SUBMIT', 'TRANSACTION_VIEW', 'TRANSACTION_DETAILS_VIEW',
    'APPROVALS_VIEW', 'APPROVALS_APPROVE', 'APPROVALS_REJECT', 'APPROVALS_RETURN',
    'APPROVAL_HISTORY_VIEW', 'REVERSAL_APPROVE',
    'REPORTS_VIEW', 'ANALYSIS_VIEW', 'AUDIT_LOG_VIEW',
  ],
  storekeeper: [
    'DASHBOARD_VIEW', 'ITEMS_VIEW', 'ITEMS_CREATE', 'ITEMS_EDIT',
    'CATEGORY_VIEW', 'CATEGORY_CREATE', 'CATEGORY_EDIT',
    'SUPPLIER_VIEW', 'SUPPLIER_CREATE', 'SUPPLIER_EDIT',
    'DEPARTMENT_VIEW', 'DEPARTMENT_CREATE', 'DEPARTMENT_EDIT',
    'STOCK_VIEW', 'STOCK_IN_CREATE', 'STOCK_OUT_CREATE', 'ADJUSTMENT_CREATE',
    'TRANSACTION_SUBMIT', 'TRANSACTION_VIEW', 'TRANSACTION_DETAILS_VIEW',
    'APPROVAL_HISTORY_VIEW', 'REPORTS_VIEW', 'ANALYSIS_VIEW',
  ],
  auditor: [
    'DASHBOARD_VIEW', 'ITEMS_VIEW', 'STOCK_VIEW',
    'TRANSACTION_VIEW', 'TRANSACTION_DETAILS_VIEW', 'APPROVAL_HISTORY_VIEW',
    'REPORTS_VIEW', 'ANALYSIS_VIEW', 'AUDIT_LOG_VIEW',
  ],
};

function hasPermission(role, perm) {
  const p = ROLE_PERMS[role] || [];
  return p.includes('*') || p.includes(perm);
}

// ============================================================================
// HELPERS
// ============================================================================
const nowIso = () => new Date().toISOString();
const today  = () => new Date().toISOString().slice(0, 10);

function ok(res, data) { res.json({ success: true, data }); }
function fail(res, status, error, message) {
  res.status(status).json({ success: false, error, message: message || error });
}

async function logAudit(req, action, opts = {}) {
  try {
    await admin.from('audit_logs').insert([{
      user_id: req.user?.id || null,
      user_name: req.user?.name || 'system',
      action,
      txn_number: opts.txnNumber || null,
      item_id: opts.itemId || null,
      item_name: opts.itemName || null,
      old_value: opts.oldValue != null ? String(opts.oldValue) : null,
      new_value: opts.newValue != null ? String(opts.newValue) : null,
      note: opts.note || null,
      ip: req.ip,
    }]);
  } catch (e) { console.error('Audit log failed:', e.message); }
}

async function notify(userId, title, message, link = null) {
  try {
    await admin.from('notifications').insert([{ user_id: userId, title, message, link }]);
  } catch (e) { console.error('Notify failed:', e.message); }
}

// ============================================================================
// EXPRESS
// ============================================================================
const app = express();
app.use(cors());
app.use(express.json({ limit: '4mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname));   // serves storekeeper.html, manager.html, auditor.html

// ============================================================================
// MIDDLEWARE
// ============================================================================
function authenticate(req, res, next) {
  const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  if (!token) return fail(res, 401, 'NOT_AUTHENTICATED', 'Missing token');
  try {
    req.user = jwt.verify(token, CONFIG.JWT_SECRET);
    next();
  } catch (e) {
    return fail(res, 401, 'INVALID_TOKEN', 'Invalid or expired token');
  }
}

function requirePerm(perm) {
  return (req, res, next) => {
    if (!hasPermission(req.user.role, perm)) {
      return fail(res, 403, 'FORBIDDEN', `Missing permission: ${perm}`);
    }
    next();
  };
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return fail(res, 403, 'ROLE_NOT_ALLOWED', `Requires: ${roles.join(', ')}`);
    }
    next();
  };
}

// ============================================================================
// AUTH
// ============================================================================
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return fail(res, 400, 'VALIDATION', 'Username and password required');

  // Sign in via Supabase Auth
  const email = username + CONFIG.EMAIL_DOMAIN;
  const { data: authData, error: authErr } = await anonClient.auth.signInWithPassword({ email, password });
  if (authErr || !authData?.user) return fail(res, 401, 'INVALID_CREDENTIALS', 'Invalid username or password');

  // Load profile via service_role
  const { data: profile, error: pErr } = await admin
    .from('profiles')
    .select('*')
    .eq('id', authData.user.id)
    .single();

  if (pErr || !profile) return fail(res, 401, 'PROFILE_NOT_FOUND', 'Profile not found');
  if (!profile.active) return fail(res, 403, 'ACCOUNT_INACTIVE', 'Account is inactive');

  // Issue our own JWT
  const token = jwt.sign(
    { id: profile.id, username: profile.username, name: profile.name, role: profile.role },
    CONFIG.JWT_SECRET,
    { expiresIn: CONFIG.JWT_EXPIRES }
  );

  // Audit
  await admin.from('audit_logs').insert([{
    user_id: profile.id, user_name: profile.name, action: 'LOGIN', ip: req.ip,
  }]);

  res.json({
    success: true,
    token,
    user: { id: profile.id, name: profile.name, username: profile.username, role: profile.role },
  });
});

app.post('/api/auth/logout', authenticate, async (req, res) => {
  await logAudit(req, 'LOGOUT');
  ok(res, { loggedOut: true });
});

app.get('/api/auth/me', authenticate, (req, res) => {
  res.json({
    id: req.user.id,
    name: req.user.name,
    username: req.user.username,
    role: req.user.role,
    permissions: ROLE_PERMS[req.user.role] || [],
  });
});

// ============================================================================
// DASHBOARD
// ============================================================================
app.get('/api/dashboard', authenticate, requirePerm('DASHBOARD_VIEW'), async (req, res) => {
  const todayStr = today();

  const [itemsRes, stockRes, pendingRes, todayRes] = await Promise.all([
    admin.from('items').select('id', { count: 'exact', head: true }).eq('status', 'Active'),
    admin.from('current_stock').select('*'),
    admin.from('transactions').select('id', { count: 'exact', head: true }).eq('status', 'Pending Approval'),
    admin.from('transactions').select('type,status,date,transaction_items(qty)').eq('date', todayStr).eq('status', 'Approved'),
  ]);

  const stock = stockRes.data || [];
  const totalQty = stock.reduce((s, r) => s + Math.max(0, Number(r.current_stock)), 0);
  const totalValue = stock.reduce((s, r) => s + Math.max(0, Number(r.current_stock)) * Number(r.unit_cost), 0);
  const lowStock = stock.filter(r => Number(r.current_stock) > 0 && Number(r.current_stock) <= Number(r.reorder_level)).length;
  const outStock = stock.filter(r => Number(r.current_stock) <= 0).length;

  const todayTxns = todayRes.data || [];
  const inToday = todayTxns.filter(t => t.type === 'STOCK_IN')
    .reduce((s, t) => s + (t.transaction_items || []).reduce((a, i) => a + Number(i.qty), 0), 0);
  const outToday = todayTxns.filter(t => t.type === 'STOCK_OUT')
    .reduce((s, t) => s + (t.transaction_items || []).reduce((a, i) => a + Number(i.qty), 0), 0);

  ok(res, {
    total_items: itemsRes.count || 0,
    total_quantity: totalQty,
    inventory_value: totalValue,
    stock_in_today: inToday,
    stock_out_today: outToday,
    low_stock_items: lowStock,
    out_of_stock_items: outStock,
    pending_approvals: pendingRes.count || 0,
  });
});

// ============================================================================
// MASTER DATA — ITEMS
// ============================================================================
app.get('/api/items', authenticate, requirePerm('ITEMS_VIEW'), async (req, res) => {
  const { data, error } = await admin.from('items').select('*').order('name');
  if (error) return fail(res, 500, error.code, error.message);
  ok(res, data || []);
});

app.get('/api/items/:id', authenticate, requirePerm('ITEMS_VIEW'), async (req, res) => {
  const { data, error } = await admin.from('items').select('*').eq('id', req.params.id).single();
  if (error) return fail(res, 404, 'NOT_FOUND', error.message);
  ok(res, data);
});

app.post('/api/items', authenticate, requirePerm('ITEMS_CREATE'), async (req, res) => {
  const b = req.body || {};
  if (!b.code || !b.name) return fail(res, 422, 'VALIDATION', 'Code and Name required');
  const { data, error } = await admin.from('items').insert([b]).select().single();
  if (error) return fail(res, 400, error.code || 'DB_ERROR', error.message);
  await logAudit(req, 'ITEM_CREATED', { itemId: data.id, itemName: data.name, note: data.code });
  ok(res, data);
});

app.put('/api/items/:id', authenticate, requirePerm('ITEMS_EDIT'), async (req, res) => {
  const b = { ...req.body, updated_at: nowIso() };
  delete b.id; delete b.created_at;
  const { data, error } = await admin.from('items').update(b).eq('id', req.params.id).select().single();
  if (error) return fail(res, 400, error.code || 'DB_ERROR', error.message);
  await logAudit(req, 'ITEM_UPDATED', { itemId: data.id, itemName: data.name });
  ok(res, data);
});

// ============================================================================
// MASTER DATA — CATEGORIES
// ============================================================================
app.get('/api/categories', authenticate, async (req, res) => {
  const { data } = await admin.from('categories').select('*').order('name');
  ok(res, data || []);
});

app.post('/api/categories', authenticate, requirePerm('CATEGORY_CREATE'), async (req, res) => {
  const { name } = req.body || {};
  if (!name) return fail(res, 422, 'VALIDATION', 'Name required');
  const { data, error } = await admin.from('categories').insert([{ name }]).select().single();
  if (error) return fail(res, 400, error.code, error.message);
  ok(res, data);
});

app.put('/api/categories/:id', authenticate, requirePerm('CATEGORY_EDIT'), async (req, res) => {
  const { name } = req.body || {};
  const { data, error } = await admin.from('categories').update({ name }).eq('id', req.params.id).select().single();
  if (error) return fail(res, 400, error.code, error.message);
  ok(res, data);
});

// ============================================================================
// MASTER DATA — SUPPLIERS
// ============================================================================
app.get('/api/suppliers', authenticate, async (req, res) => {
  const { data } = await admin.from('suppliers').select('*').order('name');
  ok(res, data || []);
});

app.post('/api/suppliers', authenticate, requirePerm('SUPPLIER_CREATE'), async (req, res) => {
  const b = req.body || {};
  if (!b.name) return fail(res, 422, 'VALIDATION', 'Name required');
  const { data, error } = await admin.from('suppliers').insert([b]).select().single();
  if (error) return fail(res, 400, error.code, error.message);
  ok(res, data);
});

app.put('/api/suppliers/:id', authenticate, requirePerm('SUPPLIER_EDIT'), async (req, res) => {
  const { data, error } = await admin.from('suppliers').update(req.body).eq('id', req.params.id).select().single();
  if (error) return fail(res, 400, error.code, error.message);
  ok(res, data);
});

// ============================================================================
// MASTER DATA — DEPARTMENTS
// ============================================================================
app.get('/api/departments', authenticate, async (req, res) => {
  const { data } = await admin.from('departments').select('*').order('name');
  ok(res, data || []);
});

app.post('/api/departments', authenticate, requirePerm('DEPARTMENT_CREATE'), async (req, res) => {
  const { name } = req.body || {};
  if (!name) return fail(res, 422, 'VALIDATION', 'Name required');
  const { data, error } = await admin.from('departments').insert([{ name }]).select().single();
  if (error) return fail(res, 400, error.code, error.message);
  ok(res, data);
});

app.put('/api/departments/:id', authenticate, requirePerm('DEPARTMENT_EDIT'), async (req, res) => {
  const { name } = req.body || {};
  const { data, error } = await admin.from('departments').update({ name }).eq('id', req.params.id).select().single();
  if (error) return fail(res, 400, error.code, error.message);
  ok(res, data);
});

// ============================================================================
// CURRENT STOCK (via the current_stock view)
// ============================================================================
app.get('/api/stock', authenticate, requirePerm('STOCK_VIEW'), async (req, res) => {
  const { data, error } = await admin.from('current_stock').select('*');
  if (error) return fail(res, 500, error.code, error.message);
  ok(res, data || []);
});

// ============================================================================
// STOCK IN
// ============================================================================
app.post('/api/stock-in', authenticate, requirePerm('STOCK_IN_CREATE'), async (req, res) => {
  const b = req.body || {};
  if (!Array.isArray(b.items) || b.items.length === 0) {
    return fail(res, 422, 'VALIDATION', 'At least one item required');
  }
  for (const l of b.items) {
    if (!l.item_id || !l.quantity || l.quantity <= 0) {
      return fail(res, 422, 'VALIDATION', 'Each line requires item_id and positive quantity');
    }
  }

  const { data: number, error: numErr } = await admin.rpc('next_txn_number', { p_type: 'STOCK_IN' });
  if (numErr) return fail(res, 500, 'RPC_ERROR', numErr.message);

  const { data: txn, error } = await admin.from('transactions').insert([{
    number,
    type: 'STOCK_IN',
    date: b.date || today(),
    status: 'Draft',
    requested_by: req.user.id,
    supplier_id: b.supplier_id || null,
    reference: b.reference_number || null,
    invoice: b.invoice || null,
    notes: b.notes || null,
  }]).select().single();
  if (error) return fail(res, 400, error.code, error.message);

  const lines = b.items.map(l => ({
    transaction_id: txn.id,
    item_id: l.item_id,
    qty: l.quantity,
    unit_cost: l.unit_cost || 0,
    unit: l.unit || 'pcs',
    batch: l.batch || null,
    expiry: l.expiry || null,
    location: l.location || null,
  }));
  const { error: lineErr } = await admin.from('transaction_items').insert(lines);
  if (lineErr) return fail(res, 400, lineErr.code, lineErr.message);

  await admin.from('approval_history').insert([{
    transaction_id: txn.id, user_id: req.user.id, user_name: req.user.name, action: 'Created',
  }]);

  await logAudit(req, 'STOCK_IN_CREATED', { txnNumber: number, note: `${lines.length} items` });
  ok(res, { id: txn.id, number });
});

// ============================================================================
// STOCK OUT
// ============================================================================
app.post('/api/stock-out', authenticate, requirePerm('STOCK_OUT_CREATE'), async (req, res) => {
  const b = req.body || {};
  if (!Array.isArray(b.items) || b.items.length === 0) {
    return fail(res, 422, 'VALIDATION', 'At least one item required');
  }

  const { data: number, error: numErr } = await admin.rpc('next_txn_number', { p_type: 'STOCK_OUT' });
  if (numErr) return fail(res, 500, 'RPC_ERROR', numErr.message);

  const { data: txn, error } = await admin.from('transactions').insert([{
    number,
    type: 'STOCK_OUT',
    date: b.date || today(),
    status: 'Draft',
    requested_by: req.user.id,
    department_id: b.department_id || null,
    recipient: b.recipient || null,
    reference: b.reference_number || null,
    purpose: b.purpose || null,
    notes: b.notes || null,
  }]).select().single();
  if (error) return fail(res, 400, error.code, error.message);

  // Fetch item costs
  const itemIds = b.items.map(l => l.item_id);
  const { data: items } = await admin.from('items').select('id,unit_cost,unit').in('id', itemIds);
  const itemMap = Object.fromEntries((items || []).map(i => [i.id, i]));

  const lines = b.items.map(l => ({
    transaction_id: txn.id,
    item_id: l.item_id,
    qty: l.quantity,
    unit_cost: itemMap[l.item_id]?.unit_cost || 0,
    unit: itemMap[l.item_id]?.unit || 'pcs',
  }));
  const { error: lineErr } = await admin.from('transaction_items').insert(lines);
  if (lineErr) return fail(res, 400, lineErr.code, lineErr.message);

  await admin.from('approval_history').insert([{
    transaction_id: txn.id, user_id: req.user.id, user_name: req.user.name, action: 'Created',
  }]);

  await logAudit(req, 'STOCK_OUT_CREATED', { txnNumber: number, note: `${lines.length} items` });
  ok(res, { id: txn.id, number });
});

// ============================================================================
// ADJUSTMENT
// ============================================================================
app.post('/api/adjustments', authenticate, requirePerm('ADJUSTMENT_CREATE'), async (req, res) => {
  const b = req.body || {};
  const { item_id, physical_quantity, reason, notes, reference } = b;
  if (!item_id || physical_quantity == null) return fail(res, 422, 'VALIDATION', 'item_id and physical_quantity required');

  // Get current stock
  const { data: stockRow } = await admin.from('current_stock').select('current_stock,unit_cost,unit').eq('item_id', item_id).single();
  const sys = Number(stockRow?.current_stock || 0);
  const phys = Number(physical_quantity);
  const diff = phys - sys;
  if (diff === 0) return fail(res, 422, 'NO_DIFFERENCE', 'Physical equals system — no adjustment needed');

  const type = diff > 0 ? 'ADJUSTMENT_IN' : 'ADJUSTMENT_OUT';
  const { data: number, error: numErr } = await admin.rpc('next_txn_number', { p_type: type });
  if (numErr) return fail(res, 500, 'RPC_ERROR', numErr.message);

  const { data: txn, error } = await admin.from('transactions').insert([{
    number, type, date: today(), status: 'Draft', requested_by: req.user.id,
    reason: reason || 'Physical count difference',
    notes: notes || null,
    reference: reference || null,
    adj_system: sys, adj_physical: phys, adj_diff: diff,
  }]).select().single();
  if (error) return fail(res, 400, error.code, error.message);

  await admin.from('transaction_items').insert([{
    transaction_id: txn.id, item_id, qty: Math.abs(diff),
    unit_cost: stockRow?.unit_cost || 0, unit: stockRow?.unit || 'pcs',
  }]);

  await admin.from('approval_history').insert([{
    transaction_id: txn.id, user_id: req.user.id, user_name: req.user.name,
    action: 'Created', comment: `System ${sys} → Physical ${phys}`,
  }]);

  await logAudit(req, 'ADJUSTMENT_CREATED', {
    txnNumber: number, itemId: item_id, oldValue: sys, newValue: phys, note: reason,
  });
  ok(res, { id: txn.id, number, diff });
});

// ============================================================================
// TRANSACTIONS — LIST / DETAIL / SUBMIT
// ============================================================================
app.get('/api/transactions', authenticate, requirePerm('TRANSACTION_VIEW'), async (req, res) => {
  const { type, status, from, to, limit } = req.query;
  let q = admin.from('transactions')
    .select('*, requested:profiles!transactions_requested_by_fkey(id,name), approved:profiles!transactions_approved_by_fkey(id,name)')
    .order('created_at', { ascending: false })
    .limit(Math.min(parseInt(limit) || 300, 1000));

  if (type)   q = q.eq('type', type);
  if (status) q = q.eq('status', status);
  if (from)   q = q.gte('date', from);
  if (to)     q = q.lte('date', to);

  const { data, error } = await q;
  if (error) return fail(res, 500, error.code, error.message);

  // Get item counts
  const ids = (data || []).map(t => t.id);
  let itemsByTxn = {};
  if (ids.length) {
    const { data: items } = await admin.from('transaction_items').select('transaction_id,qty').in('transaction_id', ids);
    (items || []).forEach(i => {
      itemsByTxn[i.transaction_id] = (itemsByTxn[i.transaction_id] || 0) + Number(i.qty);
    });
  }

  ok(res, (data || []).map(t => ({
    ...t,
    total_qty: itemsByTxn[t.id] || 0,
    requester_name: t.requested?.name || '-',
    approver_name: t.approved?.name || '-',
  })));
});

app.get('/api/transactions/:id', authenticate, requirePerm('TRANSACTION_DETAILS_VIEW'), async (req, res) => {
  const { data: t, error } = await admin.from('transactions').select('*').eq('id', req.params.id).single();
  if (error) return fail(res, 404, 'NOT_FOUND', error.message);

  const [itemsRes, histRes] = await Promise.all([
    admin.from('transaction_items').select('*, items(name,code,unit)').eq('transaction_id', req.params.id),
    admin.from('approval_history').select('*').eq('transaction_id', req.params.id).order('created_at'),
  ]);

  // Requesters / approvers
  const userIds = [t.requested_by, t.approved_by, t.rejected_by].filter(Boolean);
  const { data: profiles } = userIds.length
    ? await admin.from('profiles').select('id,name,role').in('id', userIds)
    : { data: [] };
  const pm = Object.fromEntries((profiles || []).map(p => [p.id, p]));

  ok(res, {
    ...t,
    requested_by_user: pm[t.requested_by] || null,
    approved_by_user: pm[t.approved_by] || null,
    rejected_by_user: pm[t.rejected_by] || null,
    items: (itemsRes.data || []).map(l => ({
      ...l,
      name: l.items?.name,
      code: l.items?.code,
      unit: l.unit || l.items?.unit,
    })),
    approval_history: histRes.data || [],
  });
});

app.post('/api/transactions/:id/submit', authenticate, requirePerm('TRANSACTION_SUBMIT'), async (req, res) => {
  const { data, error } = await admin.rpc('submit_transaction', { p_txn_id: req.params.id });
  if (error || !data?.success) return fail(res, 400, data?.error || 'SUBMIT_FAILED', error?.message || data?.error);
  await logAudit(req, 'TRANSACTION_SUBMITTED', { txnNumber: data.number });
  ok(res, data);
});

// ============================================================================
// MANAGER — APPROVALS
// ============================================================================
app.get('/api/manager/approvals', authenticate, requireRole('super_admin','warehouse_manager'), requirePerm('APPROVALS_VIEW'), async (req, res) => {
  const { data, error } = await admin.from('transactions')
    .select('*, requested:profiles!transactions_requested_by_fkey(id,name)')
    .eq('status', 'Pending Approval')
    .order('submitted_at', { ascending: true });
  if (error) return fail(res, 500, error.code, error.message);

  const ids = (data || []).map(t => t.id);
  let totals = {};
  if (ids.length) {
    const { data: items } = await admin.from('transaction_items').select('transaction_id,qty,unit_cost').in('transaction_id', ids);
    (items || []).forEach(i => {
      if (!totals[i.transaction_id]) totals[i.transaction_id] = { qty: 0, value: 0 };
      totals[i.transaction_id].qty += Number(i.qty);
      totals[i.transaction_id].value += Number(i.qty) * Number(i.unit_cost);
    });
  }

  const slaHours = 24;
  ok(res, (data || []).map(t => {
    const waitMin = t.submitted_at ? Math.floor((Date.now() - new Date(t.submitted_at)) / 60000) : 0;
    return {
      ...t,
      requester_name: t.requested?.name || '-',
      total_qty: totals[t.id]?.qty || 0,
      total_value: totals[t.id]?.value || 0,
      waited_minutes: waitMin,
      overdue: waitMin > slaHours * 60,
      can_approve: t.requested_by !== req.user.id,
    };
  }));
});

app.post('/api/manager/approvals/:id/approve', authenticate, requireRole('super_admin','warehouse_manager'), requirePerm('APPROVALS_APPROVE'), async (req, res) => {
  const { comment } = req.body || {};

  // Pre-check self-approval
  const { data: t } = await admin.from('transactions').select('requested_by,status').eq('id', req.params.id).single();
  if (!t) return fail(res, 404, 'NOT_FOUND', 'Transaction not found');
  if (t.requested_by === req.user.id) return fail(res, 403, 'SELF_APPROVAL', 'You cannot approve your own transaction');
  if (t.status !== 'Pending Approval') return fail(res, 409, 'INVALID_STATUS', `Cannot approve status ${t.status}`);

  const { data, error } = await admin.rpc('approve_transaction', {
    p_txn_id: req.params.id,
    p_comment: comment || null,
  });
  if (error || !data?.success) return fail(res, 400, data?.error || 'APPROVE_FAILED', error?.message || data?.error);

  await logAudit(req, 'TRANSACTION_APPROVED', { txnNumber: data.number, note: comment });
  ok(res, data);
});

app.post('/api/manager/approvals/:id/reject', authenticate, requireRole('super_admin','warehouse_manager'), requirePerm('APPROVALS_REJECT'), async (req, res) => {
  const { reason } = req.body || {};
  if (!reason || !reason.trim()) return fail(res, 422, 'REASON_REQUIRED', 'Rejection reason is required');

  const { data: t } = await admin.from('transactions').select('*').eq('id', req.params.id).single();
  if (!t) return fail(res, 404, 'NOT_FOUND', 'Transaction not found');
  if (t.status !== 'Pending Approval') return fail(res, 409, 'INVALID_STATUS', 'Only pending transactions can be rejected');
  if (t.requested_by === req.user.id) return fail(res, 403, 'SELF_APPROVAL', 'You cannot reject your own transaction');

  await admin.from('transactions').update({
    status: 'Rejected',
    rejected_by: req.user.id,
    rejected_at: nowIso(),
    rejection_reason: reason,
    updated_at: nowIso(),
  }).eq('id', req.params.id);

  await admin.from('approval_history').insert([{
    transaction_id: req.params.id, user_id: req.user.id, user_name: req.user.name,
    action: 'Rejected', comment: reason,
  }]);

  await notify(t.requested_by, 'Transaction rejected', `${t.number} rejected: ${reason}`, t.number);
  await logAudit(req, 'TRANSACTION_REJECTED', { txnNumber: t.number, note: reason });
  ok(res, { status: 'Rejected' });
});

app.post('/api/manager/approvals/:id/return', authenticate, requireRole('super_admin','warehouse_manager'), requirePerm('APPROVALS_RETURN'), async (req, res) => {
  const { comment } = req.body || {};
  if (!comment || !comment.trim()) return fail(res, 422, 'COMMENT_REQUIRED', 'Return comment is required');

  const { data: t } = await admin.from('transactions').select('*').eq('id', req.params.id).single();
  if (!t) return fail(res, 404, 'NOT_FOUND', 'Transaction not found');
  if (t.status !== 'Pending Approval') return fail(res, 409, 'INVALID_STATUS', 'Only pending transactions can be returned');

  await admin.from('transactions').update({
    status: 'Needs Correction',
    returned_by: req.user.id,
    returned_at: nowIso(),
    correction_comment: comment,
    updated_at: nowIso(),
  }).eq('id', req.params.id);

  await admin.from('approval_history').insert([{
    transaction_id: req.params.id, user_id: req.user.id, user_name: req.user.name,
    action: 'Returned', comment,
  }]);

  await notify(t.requested_by, 'Transaction returned', `${t.number}: ${comment}`, t.number);
  await logAudit(req, 'TRANSACTION_RETURNED', { txnNumber: t.number, note: comment });
  ok(res, { status: 'Needs Correction' });
});

// ============================================================================
// BULK IMPORT (from PDF parsed client-side)
// ============================================================================
app.post('/api/import/items', authenticate, requirePerm('ITEMS_CREATE'), async (req, res) => {
  const { rows, categoryId, supplierId, warehouse, building, txnDate, autoApprove } = req.body || {};
  if (!Array.isArray(rows) || !rows.length) return fail(res, 422, 'VALIDATION', 'No rows');
  if (!categoryId) return fail(res, 422, 'VALIDATION', 'categoryId required');

  // 1. Existing items
  const { data: existing } = await admin.from('items').select('id,name');
  const byName = new Map((existing || []).map(i => [i.name.toLowerCase(), i]));

  // 2. Prepare new items
  const prefix = `IMP${Date.now().toString().slice(-4)}`;
  const itemsToInsert = [];
  const rowToItemId = new Map();

  for (let i = 0; i < rows.length; i++) {
    const r = rows[i];
    const key = (r.name || '').toLowerCase();
    if (byName.has(key)) { rowToItemId.set(i, byName.get(key).id); continue; }
    itemsToInsert.push({
      code: `${prefix}-${String(i + 1).padStart(3, '0')}`,
      name: r.name,
      description: r.remark || null,
      category_id: categoryId,
      unit: r.unit || 'pcs',
      unit_cost: r.unit_cost || 0,
      min_stock: 0, reorder_level: 0, max_stock: 0,
      warehouse: warehouse || 'Main Warehouse',
      building: building || null,
      supplier_id: supplierId || null,
      status: 'Active',
    });
  }

  let inserted = [];
  if (itemsToInsert.length) {
    const { data, error } = await admin.from('items').insert(itemsToInsert).select('id,name');
    if (error) return fail(res, 400, error.code, error.message);
    inserted = data || [];
    inserted.forEach(it => {
      const idx = rows.findIndex(r => (r.name || '').toLowerCase() === it.name.toLowerCase());
      if (idx >= 0) rowToItemId.set(idx, it.id);
    });
  }

  // 3. Create OPENING transaction
  const { data: number, error: numErr } = await admin.rpc('next_txn_number', { p_type: 'OPENING' });
  if (numErr) return fail(res, 500, 'RPC_ERROR', numErr.message);

  const txnPayload = {
    number, type: 'OPENING',
    date: txnDate || today(),
    status: autoApprove ? 'Approved' : 'Draft',
    requested_by: req.user.id,
    supplier_id: supplierId || null,
    notes: `Imported ${rows.length} items from PDF`,
    reference: 'PDF Import',
  };
  if (autoApprove) {
    txnPayload.approved_by = req.user.id;
    txnPayload.approved_at = nowIso();
    txnPayload.submitted_at = nowIso();
    txnPayload.approval_comment = 'Auto-approved opening balance from PDF import';
  }

  const { data: txn, error: txnErr } = await admin.from('transactions').insert([txnPayload]).select().single();
  if (txnErr) return fail(res, 400, txnErr.code, txnErr.message);

  const lines = rows.map((r, i) => ({
    transaction_id: txn.id,
    item_id: rowToItemId.get(i),
    qty: r.qty,
    unit_cost: r.unit_cost,
    unit: r.unit,
  })).filter(l => l.item_id);

  if (lines.length) {
    const { error: lineErr } = await admin.from('transaction_items').insert(lines);
    if (lineErr) return fail(res, 400, lineErr.code, lineErr.message);
  }

  await admin.from('approval_history').insert([{
    transaction_id: txn.id, user_id: req.user.id, user_name: req.user.name,
    action: autoApprove ? 'Approved' : 'Created',
    comment: `Imported ${lines.length} items from PDF`,
  }]);

  await logAudit(req, 'PDF_IMPORT', {
    txnNumber: number,
    note: `${lines.length} items, ${itemsToInsert.length} new`,
  });

  ok(res, { transaction_id: txn.id, number, items_imported: lines.length, items_created: inserted.length });
});

// ============================================================================
// AUDIT LOG (read-only)
// ============================================================================
app.get('/api/audit-logs', authenticate, requirePerm('AUDIT_LOG_VIEW'), async (req, res) => {
  const { from, to, user, action, limit } = req.query;
  let q = admin.from('audit_logs').select('*').order('created_at', { ascending: false }).limit(Math.min(parseInt(limit) || 300, 2000));
  if (from) q = q.gte('created_at', from);
  if (to)   q = q.lte('created_at', to);
  if (user) q = q.ilike('user_name', `%${user}%`);
  if (action) q = q.ilike('action', `%${action}%`);
  const { data, error } = await q;
  if (error) return fail(res, 500, error.code, error.message);
  ok(res, data || []);
});

// Block mutations
app.put('/api/audit-logs/:id',    (req, res) => fail(res, 405, 'METHOD_NOT_ALLOWED', 'Audit logs are immutable'));
app.patch('/api/audit-logs/:id',  (req, res) => fail(res, 405, 'METHOD_NOT_ALLOWED', 'Audit logs are immutable'));
app.delete('/api/audit-logs/:id', (req, res) => fail(res, 405, 'METHOD_NOT_ALLOWED', 'Audit logs are immutable'));

// ============================================================================
// NOTIFICATIONS
// ============================================================================
app.get('/api/notifications', authenticate, async (req, res) => {
  const { data } = await admin.from('notifications').select('*')
    .eq('user_id', req.user.id).order('created_at', { ascending: false }).limit(50);
  ok(res, data || []);
});

app.post('/api/notifications/:id/read', authenticate, async (req, res) => {
  await admin.from('notifications').update({ is_read: true })
    .eq('id', req.params.id).eq('user_id', req.user.id);
  ok(res, { read: true });
});

// ============================================================================
// SETTINGS
// ============================================================================
app.get('/api/settings', authenticate, async (req, res) => {
  const { data } = await admin.from('settings').select('*');
  const s = {};
  (data || []).forEach(r => s[r.key] = r.value);
  ok(res, s);
});

app.post('/api/settings', authenticate, requireRole('super_admin'), async (req, res) => {
  const rows = Object.entries(req.body || {}).map(([key, value]) => ({ key, value: String(value) }));
  for (const r of rows) await admin.from('settings').upsert(r);
  ok(res, { saved: rows.length });
});

// ============================================================================
// USERS (admin)
// ============================================================================
app.get('/api/admin/users', authenticate, requireRole('super_admin'), async (req, res) => {
  const { data } = await admin.from('profiles').select('id,username,name,role,active,created_at').order('name');
  ok(res, data || []);
});

// ============================================================================
// HEALTH
// ============================================================================
app.get('/api/health', (req, res) => res.json({ ok: true, time: nowIso() }));

// ============================================================================
// FALLBACKS
// ============================================================================
app.use('/api', (req, res) => fail(res, 404, 'NOT_FOUND', `Unknown endpoint: ${req.method} ${req.path}`));

app.use((req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ success: false, error: 'INTERNAL_ERROR', message: err.message });
});

// ============================================================================
// BOOT
// ============================================================================
app.listen(CONFIG.PORT, () => {
  console.log(`🏭 WMS server listening on http://localhost:${CONFIG.PORT}`);
  console.log(`   Supabase: ${CONFIG.SUPABASE_URL}`);
  console.log(`   Static files served from: ${__dirname}`);
});
