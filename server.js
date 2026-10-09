/* ========================================================================
 * WAREHOUSE INVENTORY MANAGEMENT SYSTEM — BACKEND API
 * ------------------------------------------------------------------------
 * Node.js + Express + better-sqlite3 + JWT
 *
 * Architectural principles:
 *   1. Every protected endpoint checks:  Authentication → Role → Permission
 *   2. Inventory is transaction-based. Pending transactions do NOT affect
 *      official inventory. Only Approved transactions update balances.
 *   3. All approval + inventory updates happen inside ONE SQL transaction.
 *   4. No endpoint ever deletes a transaction. Use REVERSAL instead.
 *   5. The audit log is append-only. No UPDATE/DELETE is ever issued against it.
 *   6. The Auditor role is strictly READ-ONLY (see ROLE_PERMS matrix).
 *   7. No user can approve their own transaction (Rule 1).
 * ======================================================================== */

'use strict';

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');
const path = require('path');
const crypto = require('crypto');

// ----------------------------------------------------------------------
// CONFIG
// ----------------------------------------------------------------------
const CONFIG = {
  PORT: process.env.PORT || 3000,
  JWT_SECRET: process.env.JWT_SECRET || 'CHANGE-THIS-IN-PRODUCTION-9f2c1a',
  JWT_EXPIRES: '12h',
  DB_PATH: process.env.DB_PATH || path.join(__dirname, 'wms.db'),
  DEFAULT_CURRENCY: 'ETB',
  DEFAULT_SLA_HOURS: 24,
};

// ----------------------------------------------------------------------
// DATABASE
// ----------------------------------------------------------------------
const db = new Database(CONFIG.DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

function initSchema() {
  db.exec(`
    -- ============ AUTH ============
    CREATE TABLE IF NOT EXISTS users (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      username      TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      name          TEXT NOT NULL,
      role          TEXT NOT NULL,          -- super_admin | warehouse_manager | storekeeper | auditor
      active        INTEGER NOT NULL DEFAULT 1,
      created_at    TEXT NOT NULL DEFAULT (datetime('now'))
    );

    -- ============ MASTER DATA ============
    CREATE TABLE IF NOT EXISTS categories (
      id   INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT UNIQUE NOT NULL
    );

    CREATE TABLE IF NOT EXISTS suppliers (
      id      INTEGER PRIMARY KEY AUTOINCREMENT,
      name    TEXT NOT NULL,
      contact TEXT,
      email   TEXT,
      address TEXT
    );

    CREATE TABLE IF NOT EXISTS departments (
      id   INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT UNIQUE NOT NULL
    );

    CREATE TABLE IF NOT EXISTS items (
      id             INTEGER PRIMARY KEY AUTOINCREMENT,
      code           TEXT UNIQUE NOT NULL,
      sku            TEXT,
      barcode        TEXT UNIQUE,
      name           TEXT NOT NULL,
      description    TEXT,
      category_id    INTEGER REFERENCES categories(id),
      subcategory    TEXT,
      unit           TEXT NOT NULL DEFAULT 'pcs',
      min_stock      REAL NOT NULL DEFAULT 0,
      max_stock      REAL NOT NULL DEFAULT 0,
      reorder_level  REAL NOT NULL DEFAULT 0,
      unit_cost      REAL NOT NULL DEFAULT 0,
      warehouse      TEXT DEFAULT 'Main Warehouse',
      building       TEXT,
      rack           TEXT,
      shelf          TEXT,
      bin            TEXT,
      supplier_id    INTEGER REFERENCES suppliers(id),
      status         TEXT NOT NULL DEFAULT 'Active',
      created_at     TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at     TEXT NOT NULL DEFAULT (datetime('now'))
    );

    -- ============ TRANSACTIONS ============
    CREATE TABLE IF NOT EXISTS transactions (
      id              TEXT PRIMARY KEY,          -- e.g. IN-00001
      number          TEXT UNIQUE NOT NULL,
      type            TEXT NOT NULL,             -- STOCK_IN | STOCK_OUT | ADJUSTMENT_IN | ADJUSTMENT_OUT | OPENING
      date            TEXT NOT NULL,
      status          TEXT NOT NULL,             -- Draft | Pending Approval | Approved | Rejected | Needs Correction | Reversed | Reversal Pending
      requested_by    INTEGER NOT NULL REFERENCES users(id),
      requested_at    TEXT NOT NULL DEFAULT (datetime('now')),
      submitted_at    TEXT,
      approved_by     INTEGER REFERENCES users(id),
      approved_at     TEXT,
      rejected_by     INTEGER REFERENCES users(id),
      rejected_at     TEXT,
      returned_by     INTEGER REFERENCES users(id),
      returned_at     TEXT,
      reversed_by     INTEGER REFERENCES users(id),
      reversed_at     TEXT,
      approval_comment TEXT,
      rejection_reason TEXT,
      correction_comment TEXT,
      reference       TEXT,
      invoice         TEXT,
      notes           TEXT,
      purpose         TEXT,
      reason          TEXT,
      supplier_id     INTEGER REFERENCES suppliers(id),
      department_id   INTEGER REFERENCES departments(id),
      recipient       TEXT,
      adj_system      REAL,
      adj_physical    REAL,
      adj_diff        REAL,
      required_role   TEXT,
      approval_level  INTEGER DEFAULT 1,
      parent_txn_id   TEXT REFERENCES transactions(id),  -- for reversals
      created_at      TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS transaction_items (
      id             INTEGER PRIMARY KEY AUTOINCREMENT,
      transaction_id TEXT NOT NULL REFERENCES transactions(id),
      item_id        INTEGER NOT NULL REFERENCES items(id),
      qty            REAL NOT NULL,
      unit_cost      REAL NOT NULL DEFAULT 0,
      unit           TEXT,
      batch          TEXT,
      expiry         TEXT,
      location       TEXT
    );

    CREATE TABLE IF NOT EXISTS approval_history (
      id             INTEGER PRIMARY KEY AUTOINCREMENT,
      transaction_id TEXT NOT NULL REFERENCES transactions(id),
      user_id        INTEGER NOT NULL REFERENCES users(id),
      user_name      TEXT NOT NULL,
      action         TEXT NOT NULL,       -- Created | Submitted | Approved | Rejected | Returned | Resubmitted | Reversed
      comment        TEXT,
      created_at     TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS inventory_movements (
      id              INTEGER PRIMARY KEY AUTOINCREMENT,
      transaction_id  TEXT NOT NULL REFERENCES transactions(id),
      item_id         INTEGER NOT NULL REFERENCES items(id),
      movement_type   TEXT NOT NULL,       -- IN | OUT
      qty             REAL NOT NULL,
      unit_cost       REAL NOT NULL DEFAULT 0,
      balance_after   REAL NOT NULL,
      created_at      TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS inventory_balances (
      item_id      INTEGER PRIMARY KEY REFERENCES items(id),
      qty          REAL NOT NULL DEFAULT 0,
      updated_at   TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS stock_reservations (
      id             INTEGER PRIMARY KEY AUTOINCREMENT,
      transaction_id TEXT NOT NULL REFERENCES transactions(id),
      item_id        INTEGER NOT NULL REFERENCES items(id),
      qty            REAL NOT NULL,
      created_at     TEXT NOT NULL DEFAULT (datetime('now')),
      released_at    TEXT
    );

    CREATE TABLE IF NOT EXISTS reconciliation_records (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      item_id      INTEGER NOT NULL REFERENCES items(id),
      system_qty   REAL NOT NULL,
      physical_qty REAL NOT NULL,
      difference   REAL NOT NULL,
      counted_by   INTEGER NOT NULL REFERENCES users(id),
      notes        TEXT,
      created_at   TEXT NOT NULL DEFAULT (datetime('now'))
    );

    -- ============ AUDIT (append-only) ============
    CREATE TABLE IF NOT EXISTS audit_logs (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id    INTEGER,
      user_name  TEXT,
      action     TEXT NOT NULL,
      txn_number TEXT,
      item_id    INTEGER,
      item_name  TEXT,
      old_value  TEXT,
      new_value  TEXT,
      note       TEXT,
      ip         TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS notifications (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id    INTEGER NOT NULL REFERENCES users(id),
      title      TEXT NOT NULL,
      message    TEXT,
      link       TEXT,
      is_read    INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS settings (
      key   TEXT PRIMARY KEY,
      value TEXT
    );

    -- ============ INDEXES ============
    CREATE INDEX IF NOT EXISTS idx_txn_status     ON transactions(status);
    CREATE INDEX IF NOT EXISTS idx_txn_type       ON transactions(type);
    CREATE INDEX IF NOT EXISTS idx_txn_date       ON transactions(date);
    CREATE INDEX IF NOT EXISTS idx_txn_requested  ON transactions(requested_by);
    CREATE INDEX IF NOT EXISTS idx_txn_items_txn  ON transaction_items(transaction_id);
    CREATE INDEX IF NOT EXISTS idx_txn_items_item ON transaction_items(item_id);
    CREATE INDEX IF NOT EXISTS idx_movements_item ON inventory_movements(item_id);
    CREATE INDEX IF NOT EXISTS idx_audit_created  ON audit_logs(created_at);
  `);
}

// ----------------------------------------------------------------------
// PERMISSION MATRIX (server-side source of truth — frontend CANNOT override this)
// ----------------------------------------------------------------------
const ROLE_PERMS = {
  super_admin: ['*'],
  warehouse_manager: [
    'MANAGER_DASHBOARD_VIEW',
    'APPROVALS_VIEW', 'TRANSACTION_DETAILS_VIEW',
    'APPROVALS_APPROVE', 'APPROVALS_REJECT', 'APPROVALS_RETURN',
    'APPROVAL_HISTORY_VIEW', 'REVERSAL_APPROVE',
    'ITEMS_VIEW', 'STOCK_VIEW',
    'REPORTS_VIEW', 'ANALYSIS_VIEW',
  ],
  storekeeper: [
    'ITEMS_VIEW', 'ITEMS_CREATE', 'ITEMS_EDIT',
    'STOCK_VIEW', 'STOCK_IN_CREATE', 'STOCK_OUT_CREATE',
    'ADJUSTMENT_CREATE', 'TRANSACTION_SUBMIT',
    'TRANSACTION_VIEW_OWN', 'TRANSACTION_DETAILS_VIEW',
    'REPORTS_VIEW', 'ANALYSIS_VIEW',
  ],
  auditor: [
    'AUDITOR_DASHBOARD_VIEW',
    'ALL_TRANSACTIONS_VIEW', 'TRANSACTION_DETAILS_VIEW',
    'APPROVAL_HISTORY_VIEW', 'AUDIT_LOG_VIEW',
    'RECONCILIATION_VIEW', 'RECONCILIATION_CREATE',
    'EXCEPTIONS_VIEW',
    'ANALYSIS_VIEW', 'AUDIT_REPORTS_VIEW', 'AUDIT_EXPORT',
    'ITEMS_VIEW', 'STOCK_VIEW', 'REPORTS_VIEW',
  ],
};

function hasPermission(role, perm) {
  const p = ROLE_PERMS[role] || [];
  return p.includes('*') || p.includes(perm);
}

// ----------------------------------------------------------------------
// HELPERS
// ----------------------------------------------------------------------
const nowIso = () => new Date().toISOString().replace('T', ' ').slice(0, 19);
const today = () => new Date().toISOString().slice(0, 10);
const uid = () => crypto.randomBytes(8).toString('hex');

function nextTxnNumber(type) {
  const prefix = {
    STOCK_IN: 'IN', STOCK_OUT: 'OUT',
    ADJUSTMENT_IN: 'ADJ', ADJUSTMENT_OUT: 'ADJ',
    OPENING: 'OPEN', REVERSAL: 'REV',
  }[type] || 'TXN';
  const key = `seq.${prefix}`;
  const row = db.prepare(`SELECT value FROM settings WHERE key=?`).get(key);
  const n = row ? parseInt(row.value, 10) + 1 : 1;
  db.prepare(`INSERT INTO settings(key,value) VALUES(?,?)
              ON CONFLICT(key) DO UPDATE SET value=excluded.value`).run(key, String(n));
  return `${prefix}-${String(n).padStart(5, '0')}`;
}

function logAudit(req, action, opts = {}) {
  const user = req.user || {};
  db.prepare(`INSERT INTO audit_logs
    (user_id,user_name,action,txn_number,item_id,item_name,old_value,new_value,note,ip)
    VALUES (?,?,?,?,?,?,?,?,?,?)`)
    .run(user.id || null, user.name || 'system', action,
         opts.txnNumber || null, opts.itemId || null, opts.itemName || null,
         opts.oldValue != null ? String(opts.oldValue) : null,
         opts.newValue != null ? String(opts.newValue) : null,
         opts.note || null, req.ip || null);
}

function notify(userId, title, message, link = null) {
  db.prepare(`INSERT INTO notifications(user_id,title,message,link) VALUES (?,?,?,?)`)
    .run(userId, title, message, link);
}

function getBalance(itemId) {
  const r = db.prepare(`SELECT qty FROM inventory_balances WHERE item_id=?`).get(itemId);
  return r ? r.qty : 0;
}

function getPendingOutQty(itemId) {
  const r = db.prepare(`
    SELECT COALESCE(SUM(sr.qty),0) AS qty
    FROM stock_reservations sr
    JOIN transactions t ON t.id = sr.transaction_id
    WHERE sr.item_id=? AND sr.released_at IS NULL AND t.status='Pending Approval'
  `).get(itemId);
  return r.qty;
}

function getItemOr404(id) {
  return db.prepare(`SELECT * FROM items WHERE id=?`).get(id);
}

function sendError(res, status, error, message) {
  return res.status(status).json({ success: false, error, message });
}

// ----------------------------------------------------------------------
// EXPRESS APP
// ----------------------------------------------------------------------
const app = express();
app.use(cors());
app.use(express.json({ limit: '2mb' }));
app.use(express.static(path.join(__dirname, 'public'))); // serves manager.html, auditor.html, etc.
app.use(express.static(__dirname));                       // fallback if HTML sits next to server.js

// ----------------------------------------------------------------------
// AUTH MIDDLEWARE
// ----------------------------------------------------------------------
function authenticate(req, res, next) {
  const hdr = req.headers.authorization || '';
  const token = hdr.startsWith('Bearer ') ? hdr.slice(7) : null;
  if (!token) return sendError(res, 401, 'NOT_AUTHENTICATED', 'Missing token.');
  try {
    const payload = jwt.verify(token, CONFIG.JWT_SECRET);
    const user = db.prepare(`SELECT id, username, name, role, active FROM users WHERE id=?`).get(payload.sub);
    if (!user || !user.active) return sendError(res, 401, 'NOT_AUTHENTICATED', 'User inactive or deleted.');
    req.user = user;
    req.token = token;
    next();
  } catch (e) {
    return sendError(res, 401, 'INVALID_TOKEN', 'Invalid or expired token.');
  }
}

function requirePermission(perm) {
  return (req, res, next) => {
    if (!hasPermission(req.user.role, perm)) {
      return sendError(res, 403, 'FORBIDDEN', `Missing permission: ${perm}`);
    }
    next();
  };
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return sendError(res, 403, 'ROLE_NOT_ALLOWED', `Requires one of: ${roles.join(', ')}`);
    }
    next();
  };
}

// ======================================================================
// AUTH ROUTES
// ======================================================================
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return sendError(res, 400, 'VALIDATION', 'Username and password required.');

  const user = db.prepare(`SELECT * FROM users WHERE username=?`).get(username);
  if (!user) return sendError(res, 401, 'INVALID_CREDENTIALS', 'Invalid username or password.');
  if (!user.active) return sendError(res, 403, 'ACCOUNT_INACTIVE', 'Account is inactive.');
  if (!bcrypt.compareSync(password, user.password_hash)) {
    return sendError(res, 401, 'INVALID_CREDENTIALS', 'Invalid username or password.');
  }

  const token = jwt.sign(
    { sub: user.id, role: user.role, username: user.username },
    CONFIG.JWT_SECRET,
    { expiresIn: CONFIG.JWT_EXPIRES }
  );

  db.prepare(`INSERT INTO audit_logs(user_id,user_name,action,note,ip)
              VALUES (?,?,?,?,?)`)
    .run(user.id, user.name, 'LOGIN', 'Login success', req.ip);

  res.json({
    success: true,
    token,
    user: { id: user.id, name: user.name, username: user.username, role: user.role },
  });
});

app.post('/api/auth/logout', authenticate, (req, res) => {
  logAudit(req, 'LOGOUT');
  res.json({ success: true });
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

// ======================================================================
// MASTER DATA (categories, suppliers, departments, items)
// ======================================================================
app.get('/api/categories', authenticate, requirePermission('ITEMS_VIEW'), (req, res) => {
  res.json({ success: true, data: db.prepare(`SELECT * FROM categories ORDER BY name`).all() });
});

app.post('/api/categories', authenticate, requireRole('super_admin'), (req, res) => {
  const { name } = req.body || {};
  if (!name) return sendError(res, 422, 'VALIDATION', 'Name required.');
  const info = db.prepare(`INSERT INTO categories(name) VALUES (?)`).run(name);
  logAudit(req, 'CATEGORY_CREATED', { note: name });
  res.status(201).json({ success: true, data: { id: info.lastInsertRowid, name } });
});

app.get('/api/suppliers', authenticate, requirePermission('ITEMS_VIEW'), (req, res) => {
  res.json({ success: true, data: db.prepare(`SELECT * FROM suppliers ORDER BY name`).all() });
});

app.post('/api/suppliers', authenticate, requireRole('super_admin'), (req, res) => {
  const { name, contact, email, address } = req.body || {};
  if (!name) return sendError(res, 422, 'VALIDATION', 'Name required.');
  const info = db.prepare(`INSERT INTO suppliers(name,contact,email,address) VALUES (?,?,?,?)`)
    .run(name, contact || null, email || null, address || null);
  logAudit(req, 'SUPPLIER_CREATED', { note: name });
  res.status(201).json({ success: true, data: { id: info.lastInsertRowid } });
});

app.get('/api/departments', authenticate, requirePermission('ITEMS_VIEW'), (req, res) => {
  res.json({ success: true, data: db.prepare(`SELECT * FROM departments ORDER BY name`).all() });
});

app.post('/api/departments', authenticate, requireRole('super_admin'), (req, res) => {
  const { name } = req.body || {};
  if (!name) return sendError(res, 422, 'VALIDATION', 'Name required.');
  const info = db.prepare(`INSERT INTO departments(name) VALUES (?)`).run(name);
  logAudit(req, 'DEPARTMENT_CREATED', { note: name });
  res.status(201).json({ success: true, data: { id: info.lastInsertRowid } });
});

// ---- ITEMS ----
app.get('/api/items', authenticate, requirePermission('ITEMS_VIEW'), (req, res) => {
  const { search, category, status, location, low_stock, out_of_stock } = req.query;
  let sql = `
    SELECT i.*, c.name AS category_name, s.name AS supplier_name,
           COALESCE(ib.qty,0) AS current_stock
    FROM items i
    LEFT JOIN categories c ON c.id = i.category_id
    LEFT JOIN suppliers s ON s.id = i.supplier_id
    LEFT JOIN inventory_balances ib ON ib.item_id = i.id
    WHERE 1=1
  `;
  const args = [];
  if (search) {
    sql += ` AND (i.name LIKE ? OR i.code LIKE ? OR i.barcode LIKE ? OR i.sku LIKE ?)`;
    const q = `%${search}%`;
    args.push(q, q, q, q);
  }
  if (category) { sql += ` AND i.category_id=?`; args.push(+category); }
  if (status)   { sql += ` AND i.status=?`; args.push(status); }
  if (location) { sql += ` AND (i.warehouse LIKE ? OR i.rack LIKE ? OR i.bin LIKE ?)`; const q = `%${location}%`; args.push(q, q, q); }
  if (low_stock === '1')      sql += ` AND COALESCE(ib.qty,0) <= i.reorder_level AND COALESCE(ib.qty,0) > 0`;
  if (out_of_stock === '1')   sql += ` AND COALESCE(ib.qty,0) <= 0`;

  sql += ` ORDER BY i.name`;
  const rows = db.prepare(sql).all(...args);
  res.json({ success: true, data: rows });
});

app.get('/api/items/:id', authenticate, requirePermission('ITEMS_VIEW'), (req, res) => {
  const item = getItemOr404(+req.params.id);
  if (!item) return sendError(res, 404, 'ITEM_NOT_FOUND', 'Item does not exist.');
  item.current_stock = getBalance(item.id);
  item.pending_out = getPendingOutQty(item.id);
  item.available_stock = item.current_stock - item.pending_out;
  res.json({ success: true, data: item });
});

app.post('/api/items', authenticate, requirePermission('ITEMS_CREATE'), (req, res) => {
  const b = req.body || {};
  if (!b.code || !b.name) return sendError(res, 422, 'VALIDATION', 'Code and Name required.');
  if (db.prepare(`SELECT 1 FROM items WHERE code=?`).get(b.code)) {
    return sendError(res, 409, 'DUPLICATE_CODE', 'Item code already exists.');
  }
  const info = db.prepare(`
    INSERT INTO items(code,sku,barcode,name,description,category_id,subcategory,unit,
      min_stock,max_stock,reorder_level,unit_cost,warehouse,building,rack,shelf,bin,
      supplier_id,status)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
  `).run(
    b.code, b.sku || null, b.barcode || null, b.name, b.description || null,
    b.category_id || null, b.subcategory || null, b.unit || 'pcs',
    b.min_stock || 0, b.max_stock || 0, b.reorder_level || 0, b.unit_cost || 0,
    b.warehouse || 'Main Warehouse', b.building || null, b.rack || null,
    b.shelf || null, b.bin || null, b.supplier_id || null, b.status || 'Active'
  );
  db.prepare(`INSERT INTO inventory_balances(item_id,qty) VALUES (?,0)`).run(info.lastInsertRowid);
  logAudit(req, 'ITEM_CREATED', { itemId: info.lastInsertRowid, itemName: b.name, note: `Code ${b.code}` });
  res.status(201).json({ success: true, data: { id: info.lastInsertRowid } });
});

app.put('/api/items/:id', authenticate, requirePermission('ITEMS_EDIT'), (req, res) => {
  const id = +req.params.id;
  const item = getItemOr404(id);
  if (!item) return sendError(res, 404, 'ITEM_NOT_FOUND', 'Item does not exist.');
  const b = req.body || {};
  // NOTE: unit_cost is intentionally editable ONLY through Stock IN approvals
  db.prepare(`
    UPDATE items SET
      name=?, sku=?, barcode=?, description=?, category_id=?, subcategory=?, unit=?,
      min_stock=?, max_stock=?, reorder_level=?, warehouse=?, building=?, rack=?,
      shelf=?, bin=?, supplier_id=?, status=?, updated_at=datetime('now')
    WHERE id=?
  `).run(
    b.name ?? item.name, b.sku ?? item.sku, b.barcode ?? item.barcode,
    b.description ?? item.description, b.category_id ?? item.category_id,
    b.subcategory ?? item.subcategory, b.unit ?? item.unit,
    b.min_stock ?? item.min_stock, b.max_stock ?? item.max_stock,
    b.reorder_level ?? item.reorder_level,
    b.warehouse ?? item.warehouse, b.building ?? item.building,
    b.rack ?? item.rack, b.shelf ?? item.shelf, b.bin ?? item.bin,
    b.supplier_id ?? item.supplier_id, b.status ?? item.status, id
  );
  logAudit(req, 'ITEM_UPDATED', { itemId: id, itemName: item.name });
  res.json({ success: true });
});

// ======================================================================
// STOCK IN
// ======================================================================
app.post('/api/stock-in', authenticate, requirePermission('STOCK_IN_CREATE'), (req, res) => {
  const b = req.body || {};
  if (!Array.isArray(b.items) || b.items.length === 0) {
    return sendError(res, 422, 'VALIDATION', 'At least one item required.');
  }
  for (const l of b.items) {
    if (!l.item_id || !l.quantity || l.quantity <= 0) {
      return sendError(res, 422, 'VALIDATION', 'Each line requires item_id and positive quantity.');
    }
    if (!getItemOr404(l.item_id)) return sendError(res, 404, 'ITEM_NOT_FOUND', `Item ${l.item_id} not found.`);
  }

  const txn = db.transaction(() => {
    const number = nextTxnNumber('STOCK_IN');
    const id = uid();
    db.prepare(`
      INSERT INTO transactions(id,number,type,date,status,requested_by,
        reference,invoice,notes,supplier_id,created_at,updated_at)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
    `).run(id, number, 'STOCK_IN', b.date || today(), 'Draft',
           req.user.id, b.reference_number || null, b.invoice || null,
           b.notes || null, b.supplier_id || null, nowIso(), nowIso());

    const insertLine = db.prepare(`
      INSERT INTO transaction_items(transaction_id,item_id,qty,unit_cost,unit,batch,expiry,location)
      VALUES (?,?,?,?,?,?,?,?)
    `);
    for (const l of b.items) {
      const item = getItemOr404(l.item_id);
      insertLine.run(id, l.item_id, l.quantity, l.unit_cost ?? item.unit_cost,
                     item.unit, l.batch || null, l.expiry || null, l.location || null);
    }
    db.prepare(`INSERT INTO approval_history(transaction_id,user_id,user_name,action,comment)
                VALUES (?,?,?,?,?)`)
      .run(id, req.user.id, req.user.name, 'Created', null);
    return { id, number };
  })();

  logAudit(req, 'STOCK_IN_CREATED', { txnNumber: txn.number, note: `${b.items.length} item(s)` });
  res.status(201).json({ success: true, data: txn });
});

app.get('/api/stock-in/:id', authenticate, requirePermission('TRANSACTION_DETAILS_VIEW'), (req, res) => {
  const t = db.prepare(`SELECT * FROM transactions WHERE id=? AND type='STOCK_IN'`).get(req.params.id);
  if (!t) return sendError(res, 404, 'NOT_FOUND', 'Transaction not found.');
  res.json({ success: true, data: buildTransactionDetail(t) });
});

app.post('/api/stock-in/:id/submit', authenticate, requirePermission('TRANSACTION_SUBMIT'), (req, res) => {
  try {
    const t = submitTransaction(req, req.params.id, 'STOCK_IN');
    res.json({ success: true, data: t });
  } catch (e) {
    sendError(res, e.status || 400, e.code || 'ERROR', e.message);
  }
});

// ======================================================================
// STOCK OUT
// ======================================================================
app.post('/api/stock-out', authenticate, requirePermission('STOCK_OUT_CREATE'), (req, res) => {
  const b = req.body || {};
  if (!Array.isArray(b.items) || b.items.length === 0) {
    return sendError(res, 422, 'VALIDATION', 'At least one item required.');
  }
  for (const l of b.items) {
    if (!l.item_id || !l.quantity || l.quantity <= 0) {
      return sendError(res, 422, 'VALIDATION', 'Each line requires item_id and positive quantity.');
    }
    if (!getItemOr404(l.item_id)) return sendError(res, 404, 'ITEM_NOT_FOUND', `Item ${l.item_id} not found.`);
  }

  const txn = db.transaction(() => {
    const number = nextTxnNumber('STOCK_OUT');
    const id = uid();
    db.prepare(`
      INSERT INTO transactions(id,number,type,date,status,requested_by,
        reference,purpose,notes,department_id,recipient,created_at,updated_at)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
    `).run(id, number, 'STOCK_OUT', b.date || today(), 'Draft',
           req.user.id, b.reference_number || null, b.purpose || null,
           b.notes || null, b.department_id || null, b.recipient || null,
           nowIso(), nowIso());

    const insertLine = db.prepare(`
      INSERT INTO transaction_items(transaction_id,item_id,qty,unit_cost,unit)
      VALUES (?,?,?,?,?)
    `);
    for (const l of b.items) {
      const item = getItemOr404(l.item_id);
      insertLine.run(id, l.item_id, l.quantity, item.unit_cost, item.unit);
    }
    db.prepare(`INSERT INTO approval_history(transaction_id,user_id,user_name,action)
                VALUES (?,?,?,?)`)
      .run(id, req.user.id, req.user.name, 'Created');
    return { id, number };
  })();

  logAudit(req, 'STOCK_OUT_CREATED', { txnNumber: txn.number, note: `${b.items.length} item(s)` });
  res.status(201).json({ success: true, data: txn });
});

app.post('/api/stock-out/:id/submit', authenticate, requirePermission('TRANSACTION_SUBMIT'), (req, res) => {
  try {
    const t = submitTransaction(req, req.params.id, 'STOCK_OUT');
    res.json({ success: true, data: t });
  } catch (e) {
    sendError(res, e.status || 400, e.code || 'ERROR', e.message);
  }
});

// ======================================================================
// ADJUSTMENT
// ======================================================================
app.post('/api/adjustments', authenticate, requirePermission('ADJUSTMENT_CREATE'), (req, res) => {
  const b = req.body || {};
  const { item_id, physical_quantity, reason, notes, reference } = b;
  if (!item_id || physical_quantity == null) {
    return sendError(res, 422, 'VALIDATION', 'item_id and physical_quantity are required.');
  }
  const item = getItemOr404(item_id);
  if (!item) return sendError(res, 404, 'ITEM_NOT_FOUND', 'Item not found.');

  const systemQty = getBalance(item_id);
  const diff = Number(physical_quantity) - systemQty;
  if (diff === 0) return sendError(res, 422, 'NO_DIFFERENCE', 'Physical equals system — no adjustment needed.');

  const type = diff > 0 ? 'ADJUSTMENT_IN' : 'ADJUSTMENT_OUT';

  const txn = db.transaction(() => {
    const number = nextTxnNumber(type);
    const id = uid();
    db.prepare(`
      INSERT INTO transactions(id,number,type,date,status,requested_by,
        reason,notes,reference,adj_system,adj_physical,adj_diff,created_at,updated_at)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    `).run(id, number, type, today(), 'Draft', req.user.id,
           reason || 'Physical count difference', notes || null, reference || null,
           systemQty, Number(physical_quantity), diff, nowIso(), nowIso());

    db.prepare(`
      INSERT INTO transaction_items(transaction_id,item_id,qty,unit_cost,unit)
      VALUES (?,?,?,?,?)
    `).run(id, item_id, Math.abs(diff), item.unit_cost, item.unit);

    db.prepare(`INSERT INTO approval_history(transaction_id,user_id,user_name,action,comment)
                VALUES (?,?,?,?,?)`)
      .run(id, req.user.id, req.user.name, 'Created', `System ${systemQty} → Physical ${physical_quantity}`);

    return { id, number, diff };
  })();

  logAudit(req, 'ADJUSTMENT_CREATED', {
    txnNumber: txn.number, itemId: item_id, itemName: item.name,
    oldValue: systemQty, newValue: physical_quantity, note: reason
  });
  res.status(201).json({ success: true, data: txn });
});

// ======================================================================
// GENERIC SUBMIT (used by Stock IN / Stock OUT / Adjustment)
// ======================================================================
function submitTransaction(req, txnId, expectedType) {
  const t = db.prepare(`SELECT * FROM transactions WHERE id=?`).get(txnId);
  if (!t) { const e = new Error('Transaction not found.'); e.status = 404; e.code = 'NOT_FOUND'; throw e; }
  if (expectedType && t.type !== expectedType && !(expectedType === 'ADJUSTMENT' && t.type.startsWith('ADJUSTMENT'))) {
    const e = new Error('Wrong transaction type for this endpoint.'); e.status = 400; e.code = 'WRONG_TYPE'; throw e;
  }
  if (!['Draft', 'Needs Correction'].includes(t.status)) {
    const e = new Error(`Cannot submit in status ${t.status}.`); e.status = 409; e.code = 'INVALID_STATUS'; throw e;
  }
  if (t.requested_by !== req.user.id && !hasPermission(req.user.role, 'TRANSACTION_SUBMIT')) {
    const e = new Error('Not permitted.'); e.status = 403; e.code = 'FORBIDDEN'; throw e;
  }

  const items = db.prepare(`SELECT * FROM transaction_items WHERE transaction_id=?`).all(txnId);
  if (items.length === 0) { const e = new Error('No items.'); e.status = 422; e.code = 'VALIDATION'; throw e; }

  // Compute approval requirement
  const totalQty = items.reduce((s, l) => s + l.qty, 0);
  const totalValue = items.reduce((s, l) => s + l.qty * (l.unit_cost || 0), 0);

  // For Stock OUT: verify available stock at submit time (reserve)
  if (t.type === 'STOCK_OUT') {
    for (const l of items) {
      const avail = getBalance(l.item_id) - getPendingOutQty(l.item_id);
      if (l.qty > avail && !getAllowNegative()) {
        const item = getItemOr404(l.item_id);
        const e = new Error(`Insufficient available stock for ${item.name}: available ${avail}, requested ${l.qty}`);
        e.status = 409; e.code = 'INSUFFICIENT_AVAILABLE_STOCK'; throw e;
      }
    }
  }

  const requiredRole = getRequiredApprovalRole(
    t.type === 'STOCK_IN' ? 'STOCK_IN'
    : t.type === 'STOCK_OUT' ? 'STOCK_OUT'
    : 'ADJUSTMENT',
    totalQty, totalValue
  );

  const result = db.transaction(() => {
    // Create reservations for Stock OUT
    if (t.type === 'STOCK_OUT') {
      const insRes = db.prepare(`INSERT INTO stock_reservations(transaction_id,item_id,qty) VALUES (?,?,?)`);
      for (const l of items) insRes.run(txnId, l.item_id, l.qty);
    }

    if (!requiredRole) {
      // Auto-approve: apply inventory immediately
      db.prepare(`UPDATE transactions SET status='Approved', submitted_at=?, approved_by=?, approved_at=?, updated_at=?
                  WHERE id=?`)
        .run(nowIso(), req.user.id, nowIso(), nowIso(), txnId);
      applyInventory(t, items, req);
      db.prepare(`INSERT INTO approval_history(transaction_id,user_id,user_name,action,comment)
                  VALUES (?,?,?,?,?)`).run(txnId, req.user.id, req.user.name, 'Auto-Approved', 'No approval required');
      // Release reservations (stock already deducted)
      db.prepare(`UPDATE stock_reservations SET released_at=? WHERE transaction_id=?`).run(nowIso(), txnId);
    } else {
      db.prepare(`UPDATE transactions SET status='Pending Approval', submitted_at=?, required_role=?, approval_level=1, updated_at=?
                  WHERE id=?`)
        .run(nowIso(), requiredRole, nowIso(), txnId);
      db.prepare(`INSERT INTO approval_history(transaction_id,user_id,user_name,action,comment)
                  VALUES (?,?,?,?,?)`).run(txnId, req.user.id, req.user.name, 'Submitted', 'Ready for approval');

      // Notify approvers
      const approvers = db.prepare(`SELECT id FROM users WHERE role=? AND active=1 AND id<>?`).all(requiredRole, req.user.id);
      for (const a of approvers) {
        notify(a.id, 'New transaction awaiting approval', `${t.number} — ${t.type.replace('_', ' ')}`, t.number);
      }
    }
    return t;
  })();

  logAudit(req, t.type + '_SUBMITTED', { txnNumber: t.number, note: `Auto-approve: ${!requiredRole}` });
  return db.prepare(`SELECT * FROM transactions WHERE id=?`).get(txnId);
}

function getAllowNegative() {
  const r = db.prepare(`SELECT value FROM settings WHERE key='allow_negative_stock'`).get();
  return r && r.value === '1';
}

function getRequiredApprovalRole(kind, qty, value) {
  // Simple rules: read from settings (with defaults matching the spec)
  const defaults = {
    STOCK_IN:   { enabled: 1, qty: 0,   value: 0,     role: 'warehouse_manager' },
    STOCK_OUT:  { enabled: 1, qty: 100, value: 50000, role: 'warehouse_manager' },
    ADJUSTMENT: { enabled: 1, qty: 10,  value: 0,     role: 'warehouse_manager' },
  };
  const d = defaults[kind];
  if (!d || !d.enabled) return null;
  if (kind === 'STOCK_OUT') {
    if (qty >= d.qty || value >= d.value) return d.role;
    return d.role; // spec says all Stock OUT require approval
  }
  if (kind === 'ADJUSTMENT') {
    return qty >= d.qty ? d.role : d.role; // all adjustments require approval
  }
  return d.role;
}

/**
 * Apply an APPROVED transaction to the inventory_balances table.
 * Must be called inside a DB transaction.
 */
function applyInventory(txn, items, req) {
  const upsert = db.prepare(`
    INSERT INTO inventory_balances(item_id,qty,updated_at) VALUES (?,?,?)
    ON CONFLICT(item_id) DO UPDATE SET qty = qty + excluded.qty, updated_at = excluded.updated_at
  `);
  const insertMovement = db.prepare(`
    INSERT INTO inventory_movements(transaction_id,item_id,movement_type,qty,unit_cost,balance_after)
    VALUES (?,?,?,?,?,?)
  `);
  const getBal = db.prepare(`SELECT COALESCE(qty,0) AS qty FROM inventory_balances WHERE item_id=?`);

  for (const l of items) {
    const sign = ['STOCK_IN', 'OPENING', 'ADJUSTMENT_IN'].includes(txn.type) ? +1 : -1;
    const moveQty = l.qty * sign;

    upsert.run(l.item_id, moveQty, nowIso());

    const after = getBal.get(l.item_id).qty;
    insertMovement.run(txn.id, l.item_id, sign > 0 ? 'IN' : 'OUT', Math.abs(l.qty), l.unit_cost, after);

    logAudit(req, `INVENTORY_CHANGE`, {
      txnNumber: txn.number, itemId: l.item_id,
      itemName: (getItemOr404(l.item_id) || {}).name,
      oldValue: after - moveQty, newValue: after,
    });

    // Update weighted average cost on IN
    if (sign > 0) {
      const item = getItemOr404(l.item_id);
      const priorQty = after - l.qty;
      const priorVal = Math.max(0, priorQty) * item.unit_cost;
      const newVal = priorVal + l.qty * (l.unit_cost || item.unit_cost);
      const newQty = after;
      if (newQty > 0) {
        db.prepare(`UPDATE items SET unit_cost=?, updated_at=? WHERE id=?`)
          .run(+(newVal / newQty).toFixed(4), nowIso(), l.item_id);
      }
    }
  }
}

// ======================================================================
// TRANSACTION DETAIL BUILDER (used by manager & auditor)
// ======================================================================
function buildTransactionDetail(t) {
  const items = db.prepare(`
    SELECT ti.*, i.name AS item_name, i.code AS item_code,
           i.warehouse, i.rack, i.shelf, i.bin
    FROM transaction_items ti
    JOIN items i ON i.id = ti.item_id
    WHERE ti.transaction_id=?
  `).all(t.id);

  const history = db.prepare(`
    SELECT * FROM approval_history WHERE transaction_id=? ORDER BY created_at ASC
  `).all(t.id);

  const reqUser = db.prepare(`SELECT id,name,role FROM users WHERE id=?`).get(t.requested_by);
  const apprUser = t.approved_by ? db.prepare(`SELECT id,name,role FROM users WHERE id=?`).get(t.approved_by) : null;
  const rejUser = t.rejected_by ? db.prepare(`SELECT id,name,role FROM users WHERE id=?`).get(t.rejected_by) : null;
  const sup = t.supplier_id ? db.prepare(`SELECT name FROM suppliers WHERE id=?`).get(t.supplier_id) : null;
  const dept = t.department_id ? db.prepare(`SELECT name FROM departments WHERE id=?`).get(t.department_id) : null;

  const enriched = items.map(l => {
    const current = getBalance(l.item_id);
    let stockAfter = current;
    if (t.status !== 'Approved') {
      // Predict
      if (['STOCK_IN', 'OPENING', 'ADJUSTMENT_IN'].includes(t.type)) stockAfter = current + l.qty;
      else if (['STOCK_OUT', 'ADJUSTMENT_OUT'].includes(t.type)) stockAfter = current - l.qty;
    }
    return {
      item_id: l.item_id, name: l.item_name, code: l.item_code,
      qty: l.qty, unit: l.unit, unit_cost: l.unit_cost,
      total: l.qty * l.unit_cost,
      location: `${l.warehouse || ''} · ${l.rack || ''}/${l.shelf || ''}/${l.bin || ''}`.trim(),
      current_stock: current,
      pending_out: getPendingOutQty(l.item_id),
      available_stock: current - getPendingOutQty(l.item_id),
      stock_after: t.type.startsWith('ADJUSTMENT') ? (t.adj_physical ?? stockAfter) : stockAfter,
      adj_system: t.adj_system, adj_physical: t.adj_physical, adj_diff: t.adj_diff,
    };
  });

  return {
    id: t.id, number: t.number, type: t.type, date: t.date, status: t.status,
    reference: t.reference, invoice: t.invoice, notes: t.notes,
    purpose: t.purpose, reason: t.reason, recipient: t.recipient,
    supplier: sup ? sup.name : null,
    department: dept ? dept.name : null,
    requested_by: reqUser,
    approver: apprUser ? { ...apprUser, date: t.approved_at, comment: t.approval_comment } : null,
    rejector: rejUser ? { ...rejUser, date: t.rejected_at, reason: t.rejection_reason } : null,
    created_at: t.created_at, submitted_at: t.submitted_at, approved_at: t.approved_at,
    items: enriched,
    approval_history: history,
    total_qty: enriched.reduce((s, i) => s + i.qty, 0),
    total_value: enriched.reduce((s, i) => s + i.total, 0),
  };
}

// ======================================================================
// MANAGER APPROVAL ENDPOINTS
// ======================================================================
app.get('/api/manager/approvals', authenticate, requireRole('super_admin', 'warehouse_manager'), requirePermission('APPROVALS_VIEW'), (req, res) => {
  const { type, from, to, requester, status } = req.query;
  let sql = `
    SELECT t.*, u.name AS requester_name,
           (SELECT COALESCE(SUM(qty),0) FROM transaction_items WHERE transaction_id=t.id) AS total_qty,
           (SELECT COALESCE(SUM(qty*unit_cost),0) FROM transaction_items WHERE transaction_id=t.id) AS total_value,
           (SELECT COUNT(*) FROM transaction_items WHERE transaction_id=t.id) AS item_count
    FROM transactions t
    JOIN users u ON u.id = t.requested_by
    WHERE t.status='Pending Approval'
  `;
  const args = [];
  if (type)      { sql += ` AND t.type=?`; args.push(type); }
  if (from)      { sql += ` AND t.date>=?`; args.push(from); }
  if (to)        { sql += ` AND t.date<=?`; args.push(to); }
  if (requester) { sql += ` AND u.name LIKE ?`; args.push(`%${requester}%`); }
  if (status)    { sql += ` AND t.status=?`; args.push(status); }
  sql += ` ORDER BY t.submitted_at ASC`;
  const rows = db.prepare(sql).all(...args);
  const slaHrs = parseInt(db.prepare(`SELECT value FROM settings WHERE key='sla_hours'`).get()?.value || '24');
  const data = rows.map(r => {
    const waitedMin = r.submitted_at ? Math.floor((Date.now() - new Date(r.submitted_at)) / 60000) : 0;
    return { ...r, waited_minutes: waitedMin, overdue: waitedMin > slaHrs * 60, can_approve: r.requested_by !== req.user.id };
  });
  res.json({ success: true, data });
});

app.get('/api/manager/approvals/:id', authenticate, requireRole('super_admin', 'warehouse_manager'), requirePermission('TRANSACTION_DETAILS_VIEW'), (req, res) => {
  const t = db.prepare(`SELECT * FROM transactions WHERE id=?`).get(req.params.id);
  if (!t) return sendError(res, 404, 'NOT_FOUND', 'Transaction not found.');
  const detail = buildTransactionDetail(t);
  detail.is_own = t.requested_by === req.user.id;
  detail.can_approve = t.status === 'Pending Approval' && !detail.is_own;
  res.json({ success: true, data: detail });
});

app.post('/api/manager/approvals/:id/approve', authenticate, requireRole('super_admin', 'warehouse_manager'), requirePermission('APPROVALS_APPROVE'), (req, res) => {
  const { comment } = req.body || {};
  try {
    const result = approveTransaction(req, req.params.id, comment);
    res.json({ success: true, data: result });
  } catch (e) {
    sendError(res, e.status || 400, e.code || 'ERROR', e.message);
  }
});

app.post('/api/manager/approvals/:id/reject', authenticate, requireRole('super_admin', 'warehouse_manager'), requirePermission('APPROVALS_REJECT'), (req, res) => {
  const { reason } = req.body || {};
  if (!reason || !reason.trim()) return sendError(res, 422, 'REASON_REQUIRED', 'Rejection reason is required.');
  const t = db.prepare(`SELECT * FROM transactions WHERE id=?`).get(req.params.id);
  if (!t) return sendError(res, 404, 'NOT_FOUND', 'Transaction not found.');
  if (t.status !== 'Pending Approval') return sendError(res, 409, 'INVALID_STATUS', 'Only pending transactions can be rejected.');
  if (t.requested_by === req.user.id) return sendError(res, 403, 'SELF_APPROVAL', 'You cannot reject your own transaction.');

  db.transaction(() => {
    db.prepare(`UPDATE transactions SET status='Rejected', rejected_by=?, rejected_at=?, rejection_reason=?, updated_at=? WHERE id=?`)
      .run(req.user.id, nowIso(), reason, nowIso(), t.id);
    db.prepare(`UPDATE stock_reservations SET released_at=? WHERE transaction_id=?`).run(nowIso(), t.id);
    db.prepare(`INSERT INTO approval_history(transaction_id,user_id,user_name,action,comment) VALUES (?,?,?,?,?)`)
      .run(t.id, req.user.id, req.user.name, 'Rejected', reason);
    notify(t.requested_by, 'Transaction rejected', `${t.number} rejected: ${reason}`, t.number);
  })();

  logAudit(req, t.type + '_REJECTED', { txnNumber: t.number, note: reason });
  res.json({ success: true });
});

app.post('/api/manager/approvals/:id/return', authenticate, requireRole('super_admin', 'warehouse_manager'), requirePermission('APPROVALS_RETURN'), (req, res) => {
  const { comment } = req.body || {};
  if (!comment || !comment.trim()) return sendError(res, 422, 'COMMENT_REQUIRED', 'Return comment is required.');
  const t = db.prepare(`SELECT * FROM transactions WHERE id=?`).get(req.params.id);
  if (!t) return sendError(res, 404, 'NOT_FOUND', 'Transaction not found.');
  if (t.status !== 'Pending Approval') return sendError(res, 409, 'INVALID_STATUS', 'Only pending transactions can be returned.');

  db.transaction(() => {
    db.prepare(`UPDATE transactions SET status='Needs Correction', returned_by=?, returned_at=?, correction_comment=?, updated_at=? WHERE id=?`)
      .run(req.user.id, nowIso(), comment, nowIso(), t.id);
    db.prepare(`UPDATE stock_reservations SET released_at=? WHERE transaction_id=?`).run(nowIso(), t.id);
    db.prepare(`INSERT INTO approval_history(transaction_id,user_id,user_name,action,comment) VALUES (?,?,?,?,?)`)
      .run(t.id, req.user.id, req.user.name, 'Returned', comment);
    notify(t.requested_by, 'Transaction returned for correction', `${t.number}: ${comment}`, t.number);
  })();

  logAudit(req, 'TRANSACTION_RETURNED', { txnNumber: t.number, note: comment });
  res.json({ success: true });
});

function approveTransaction(req, txnId, comment) {
  return db.transaction(() => {
    const t = db.prepare(`SELECT * FROM transactions WHERE id=?`).get(txnId);
    if (!t) { const e = new Error('Transaction not found.'); e.status = 404; e.code = 'NOT_FOUND'; throw e; }

    // Rule 1: no self approval
    if (t.requested_by === req.user.id) { const e = new Error('You cannot approve your own transaction.'); e.status = 403; e.code = 'SELF_APPROVAL'; throw e; }
    // Rule 2: cannot approve twice
    if (t.status !== 'Pending Approval') { const e = new Error(`Cannot approve in status ${t.status}.`); e.status = 409; e.code = 'INVALID_STATUS'; throw e; }

    const items = db.prepare(`SELECT * FROM transaction_items WHERE transaction_id=?`).all(t.id);

    // Rule 10: re-check stock for Stock OUT (concurrency protection)
    if (t.type === 'STOCK_OUT') {
      for (const l of items) {
        const bal = getBalance(l.item_id);
        const reserved = getPendingOutQty(l.item_id);
        const availableForThis = bal - (reserved - l.qty); // minus other pending
        if (l.qty > availableForThis && !getAllowNegative()) {
          const item = getItemOr404(l.item_id);
          const e = new Error(`Concurrency check failed for ${item.name}: available ${availableForThis}, requested ${l.qty}`);
          e.status = 409; e.code = 'INSUFFICIENT_STOCK'; throw e;
        }
      }
    }

    // Apply inventory (inside the same SQL transaction — atomic)
    applyInventory(t, items, req);

    // Update transaction record
    db.prepare(`UPDATE transactions SET status='Approved', approved_by=?, approved_at=?, approval_comment=?, updated_at=? WHERE id=?`)
      .run(req.user.id, nowIso(), comment || null, nowIso(), t.id);

    // Release reservations
    db.prepare(`UPDATE stock_reservations SET released_at=? WHERE transaction_id=?`).run(nowIso(), t.id);

    // History
    db.prepare(`INSERT INTO approval_history(transaction_id,user_id,user_name,action,comment) VALUES (?,?,?,?,?)`)
      .run(t.id, req.user.id, req.user.name, 'Approved', comment || null);

    // Notify requester
    notify(t.requested_by, 'Transaction approved', `${t.number} approved by ${req.user.name}.`, t.number);

    logAudit(req, t.type + '_APPROVED', { txnNumber: t.number, note: comment || '' });

    return { id: t.id, number: t.number, status: 'Approved' };
  })();
}

app.get('/api/transactions/:id/approval-history', authenticate, requirePermission('APPROVAL_HISTORY_VIEW'), (req, res) => {
  const rows = db.prepare(`SELECT * FROM approval_history WHERE transaction_id=? ORDER BY created_at ASC`).all(req.params.id);
  res.json({ success: true, data: rows });
});

// ======================================================================
// REVERSAL (approved → REVERSAL_PENDING → reversed)
// ======================================================================
app.post('/api/transactions/:id/reversal-request', authenticate, requirePermission('TRANSACTION_SUBMIT'), (req, res) => {
  const { reason } = req.body || {};
  if (!reason) return sendError(res, 422, 'VALIDATION', 'Reversal reason required.');
  const t = db.prepare(`SELECT * FROM transactions WHERE id=?`).get(req.params.id);
  if (!t) return sendError(res, 404, 'NOT_FOUND', 'Transaction not found.');
  if (t.status !== 'Approved') return sendError(res, 409, 'INVALID_STATUS', 'Only approved transactions can be reversed.');
  if (db.prepare(`SELECT 1 FROM transactions WHERE parent_txn_id=?`).get(t.id)) {
    return sendError(res, 409, 'ALREADY_REVERSED', 'This transaction was already reversed.');
  }

  db.transaction(() => {
    db.prepare(`UPDATE transactions SET status='Reversal Pending', updated_at=? WHERE id=?`).run(nowIso(), t.id);
    db.prepare(`INSERT INTO approval_history(transaction_id,user_id,user_name,action,comment) VALUES (?,?,?,?,?)`)
      .run(t.id, req.user.id, req.user.name, 'Reversal Requested', reason);
  })();
  logAudit(req, 'REVERSAL_REQUESTED', { txnNumber: t.number, note: reason });
  res.json({ success: true });
});

app.post('/api/manager/reversals/:id/approve', authenticate, requireRole('super_admin', 'warehouse_manager'), requirePermission('REVERSAL_APPROVE'), (req, res) => {
  const { comment } = req.body || {};
  const t = db.prepare(`SELECT * FROM transactions WHERE id=?`).get(req.params.id);
  if (!t) return sendError(res, 404, 'NOT_FOUND', 'Transaction not found.');
  if (t.status !== 'Reversal Pending') return sendError(res, 409, 'INVALID_STATUS', 'Not in Reversal Pending state.');

  const items = db.prepare(`SELECT * FROM transaction_items WHERE transaction_id=?`).all(t.id);
  const reversedType = ['STOCK_IN', 'OPENING', 'ADJUSTMENT_IN'].includes(t.type) ? 'STOCK_OUT'
                     : 'STOCK_IN'; // reverse in opposite direction

  db.transaction(() => {
    // Create the opposite transaction
    const revNumber = nextTxnNumber('REVERSAL');
    const revId = uid();
    db.prepare(`
      INSERT INTO transactions(id,number,type,date,status,requested_by,
        parent_txn_id,notes,reference,created_at,updated_at,approved_by,approved_at,approval_comment,submitted_at)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    `).run(revId, revNumber, reversedType, today(), 'Approved', req.user.id,
           t.id, `Reversal of ${t.number}`, t.reference || null,
           nowIso(), nowIso(), req.user.id, nowIso(), comment || 'Reversal approved', nowIso());

    const insLine = db.prepare(`INSERT INTO transaction_items(transaction_id,item_id,qty,unit_cost,unit) VALUES (?,?,?,?,?)`);
    for (const l of items) insLine.run(revId, l.item_id, l.qty, l.unit_cost, l.unit);

    // Apply reversal inventory
    const revTxn = db.prepare(`SELECT * FROM transactions WHERE id=?`).get(revId);
    const revItems = db.prepare(`SELECT * FROM transaction_items WHERE transaction_id=?`).all(revId);
    applyInventory(revTxn, revItems, req);

    // Mark original
    db.prepare(`UPDATE transactions SET status='Reversed', reversed_by=?, reversed_at=?, updated_at=? WHERE id=?`)
      .run(req.user.id, nowIso(), nowIso(), t.id);
    db.prepare(`INSERT INTO approval_history(transaction_id,user_id,user_name,action,comment) VALUES (?,?,?,?,?)`)
      .run(t.id, req.user.id, req.user.name, 'Reversed', comment || 'Reversal approved');
    notify(t.requested_by, 'Transaction reversed', `${t.number} reversed. Reversal ref: ${revNumber}`, revNumber);
  })();

  logAudit(req, 'TRANSACTION_REVERSED', { txnNumber: t.number, note: comment || '' });
  res.json({ success: true });
});

// ======================================================================
// MANAGER APPROVAL HISTORY
// ======================================================================
app.get('/api/manager/approval-history', authenticate, requireRole('super_admin', 'warehouse_manager'), requirePermission('APPROVAL_HISTORY_VIEW'), (req, res) => {
  const { from, to, type, decision, requester } = req.query;
  let sql = `
    SELECT ah.*, t.number AS txn_number, t.type AS txn_type,
           ru.name AS requester_name, u.role AS manager_role
    FROM approval_history ah
    JOIN transactions t ON t.id = ah.transaction_id
    JOIN users u ON u.id = ah.user_id
    JOIN users ru ON ru.id = t.requested_by
    WHERE u.role IN ('super_admin','warehouse_manager')
      AND ah.action IN ('Approved','Rejected','Returned','Reversed')
  `;
  const args = [];
  if (from) sql += ` AND date(ah.created_at)>=?`; args.push(from);
  if (to)   sql += ` AND date(ah.created_at)<=?`; args.push(to);
  if (type) sql += ` AND t.type=?`; args.push(type);
  if (decision) sql += ` AND ah.action=?`; args.push(decision);
  if (requester) { sql += ` AND ru.name LIKE ?`; args.push(`%${requester}%`); }
  sql += ` ORDER BY ah.created_at DESC LIMIT 500`;
  res.json({ success: true, data: db.prepare(sql).all(...args) });
});

// ======================================================================
// CURRENT STOCK
// ======================================================================
app.get('/api/inventory', authenticate, requirePermission('STOCK_VIEW'), (req, res) => {
  const rows = db.prepare(`
    SELECT i.id AS item_id, i.code, i.name AS item_name, i.unit, i.min_stock, i.reorder_level,
           i.unit_cost,
           COALESCE(ib.qty,0) AS current_stock,
           COALESCE((SELECT SUM(sr.qty) FROM stock_reservations sr
                     JOIN transactions t ON t.id = sr.transaction_id
                     WHERE sr.item_id=i.id AND sr.released_at IS NULL AND t.status='Pending Approval'),0) AS pending_out
    FROM items i
    LEFT JOIN inventory_balances ib ON ib.item_id = i.id
    WHERE i.status='Active'
    ORDER BY i.name
  `).all();
  const data = rows.map(r => ({
    ...r,
    available_stock: r.current_stock - r.pending_out,
    value: r.current_stock * r.unit_cost,
    status: r.current_stock <= 0 ? 'OUT_OF_STOCK'
          : r.current_stock <= r.min_stock ? 'CRITICAL'
          : r.current_stock <= r.reorder_level ? 'LOW_STOCK'
          : 'NORMAL',
  }));
  res.json({ success: true, data });
});

// ======================================================================
// DASHBOARD
// ======================================================================
app.get('/api/dashboard', authenticate, (req, res) => {
  const todayStr = today();
  const totalItems = db.prepare(`SELECT COUNT(*) c FROM items WHERE status='Active'`).get().c;
  const totalQty = db.prepare(`SELECT COALESCE(SUM(qty),0) q FROM inventory_balances`).get().q;
  const invValue = db.prepare(`
    SELECT COALESCE(SUM(ib.qty * i.unit_cost),0) v
    FROM inventory_balances ib JOIN items i ON i.id=ib.item_id
  `).get().v;
  const inToday = db.prepare(`
    SELECT COALESCE(SUM(ti.qty),0) q
    FROM transactions t JOIN transaction_items ti ON ti.transaction_id=t.id
    WHERE t.type='STOCK_IN' AND t.status='Approved' AND t.date=?
  `).get(todayStr).q;
  const outToday = db.prepare(`
    SELECT COALESCE(SUM(ti.qty),0) q
    FROM transactions t JOIN transaction_items ti ON ti.transaction_id=t.id
    WHERE t.type='STOCK_OUT' AND t.status='Approved' AND t.date=?
  `).get(todayStr).q;
  const lowStock = db.prepare(`
    SELECT COUNT(*) c FROM items i LEFT JOIN inventory_balances ib ON ib.item_id=i.id
    WHERE COALESCE(ib.qty,0) > 0 AND COALESCE(ib.qty,0) <= i.reorder_level
  `).get().c;
  const outStock = db.prepare(`
    SELECT COUNT(*) c FROM items i LEFT JOIN inventory_balances ib ON ib.item_id=i.id
    WHERE COALESCE(ib.qty,0) <= 0
  `).get().c;
  const pending = db.prepare(`SELECT COUNT(*) c FROM transactions WHERE status='Pending Approval'`).get().c;

  res.json({
    success: true,
    data: {
      total_items: totalItems,
      total_quantity: totalQty,
      inventory_value: invValue,
      stock_in_today: inToday,
      stock_out_today: outToday,
      low_stock_items: lowStock,
      out_of_stock_items: outStock,
      pending_approvals: pending,
    },
  });
});

// ======================================================================
// AUDITOR API — READ-ONLY
// ======================================================================
app.get('/api/auditor/dashboard', authenticate, requireRole('super_admin', 'auditor'), requirePermission('AUDITOR_DASHBOARD_VIEW'), (req, res) => {
  const byType = {};
  for (const r of db.prepare(`SELECT type, COUNT(*) c FROM transactions GROUP BY type`).all()) byType[r.type] = r.c;
  const byStatus = {};
  for (const r of db.prepare(`SELECT status, COUNT(*) c FROM transactions GROUP BY status`).all()) byStatus[r.status] = r.c;
  const discrepancies = db.prepare(`SELECT COUNT(*) c FROM reconciliation_records WHERE ABS(difference) > 0`).get().c;
  res.json({ success: true, data: { by_type: byType, by_status: byStatus, discrepancies } });
});

app.get('/api/auditor/transactions', authenticate, requireRole('super_admin', 'auditor'), requirePermission('ALL_TRANSACTIONS_VIEW'), (req, res) => {
  const { from, to, type, status, requester, approver, department } = req.query;
  let sql = `
    SELECT t.*, u.name AS requester_name, a.name AS approver_name,
           (SELECT COALESCE(SUM(qty),0) FROM transaction_items WHERE transaction_id=t.id) total_qty,
           (SELECT COALESCE(SUM(qty*unit_cost),0) FROM transaction_items WHERE transaction_id=t.id) total_value,
           (SELECT COUNT(*) FROM transaction_items WHERE transaction_id=t.id) item_count
    FROM transactions t
    LEFT JOIN users u ON u.id = t.requested_by
    LEFT JOIN users a ON a.id = t.approved_by
    WHERE 1=1
  `;
  const args = [];
  if (from) sql += ` AND t.date>=?`, args.push(from);
  if (to)   sql += ` AND t.date<=?`, args.push(to);
  if (type) sql += ` AND t.type=?`, args.push(type);
  if (status) sql += ` AND t.status=?`, args.push(status);
  if (requester) { sql += ` AND u.name LIKE ?`; args.push(`%${requester}%`); }
  if (approver) { sql += ` AND a.name LIKE ?`; args.push(`%${approver}%`); }
  if (department) { sql += ` AND t.department_id=?`; args.push(+department); }
  sql += ` ORDER BY t.date DESC, t.created_at DESC LIMIT 1000`;
  res.json({ success: true, data: db.prepare(sql).all(...args) });
});

app.get('/api/auditor/transactions/:id', authenticate, requireRole('super_admin', 'auditor'), requirePermission('TRANSACTION_DETAILS_VIEW'), (req, res) => {
  const t = db.prepare(`SELECT * FROM transactions WHERE id=?`).get(req.params.id);
  if (!t) return sendError(res, 404, 'NOT_FOUND', 'Transaction not found.');
  res.json({ success: true, data: buildTransactionDetail(t) });
});

app.get('/api/auditor/audit-log', authenticate, requireRole('super_admin', 'auditor'), requirePermission('AUDIT_LOG_VIEW'), (req, res) => {
  const { from, to, user, action, transaction } = req.query;
  let sql = `SELECT * FROM audit_logs WHERE 1=1`;
  const args = [];
  if (from) sql += ` AND date(created_at)>=?`, args.push(from);
  if (to)   sql += ` AND date(created_at)<=?`, args.push(to);
  if (user) { sql += ` AND user_name LIKE ?`; args.push(`%${user}%`); }
  if (action) { sql += ` AND action LIKE ?`; args.push(`%${action}%`); }
  if (transaction) { sql += ` AND txn_number LIKE ?`; args.push(`%${transaction}%`); }
  sql += ` ORDER BY created_at DESC LIMIT 2000`;
  res.json({ success: true, data: db.prepare(sql).all(...args) });
});

app.get('/api/auditor/reconciliation', authenticate, requireRole('super_admin', 'auditor'), requirePermission('RECONCILIATION_VIEW'), (req, res) => {
  const rows = db.prepare(`
    SELECT i.id AS item_id, i.code, i.name AS item_name, i.unit,
           COALESCE(ib.qty,0) AS system_qty,
           (SELECT physical_qty FROM reconciliation_records rr WHERE rr.item_id=i.id ORDER BY created_at DESC LIMIT 1) AS last_physical,
           (SELECT created_at  FROM reconciliation_records rr WHERE rr.item_id=i.id ORDER BY created_at DESC LIMIT 1) AS last_counted_at
    FROM items i LEFT JOIN inventory_balances ib ON ib.item_id=i.id
    WHERE i.status='Active'
  `).all();
  const data = rows.map(r => {
    const physical = r.last_physical != null ? r.last_physical : r.system_qty;
    const diff = physical - r.system_qty;
    const status = diff === 0 ? 'MATCH'
      : Math.abs(diff) >= 10 || (r.system_qty > 0 && Math.abs(diff) / r.system_qty > 0.05) ? 'CRITICAL DIFFERENCE'
      : 'DIFFERENCE';
    return { ...r, physical_qty: physical, difference: diff, status };
  });
  res.json({ success: true, data });
});

app.post('/api/auditor/reconciliation', authenticate, requireRole('super_admin', 'auditor'), requirePermission('RECONCILIATION_CREATE'), (req, res) => {
  const { item_id, physical_qty, notes } = req.body || {};
  if (!item_id || physical_qty == null) return sendError(res, 422, 'VALIDATION', 'item_id and physical_qty required.');
  const item = getItemOr404(item_id);
  if (!item) return sendError(res, 404, 'ITEM_NOT_FOUND', 'Item not found.');
  const sys = getBalance(item_id);
  const diff = Number(physical_qty) - sys;
  db.prepare(`INSERT INTO reconciliation_records(item_id,system_qty,physical_qty,difference,counted_by,notes)
              VALUES (?,?,?,?,?,?)`)
    .run(item_id, sys, Number(physical_qty), diff, req.user.id, notes || null);
  logAudit(req, 'RECONCILIATION_CREATED', {
    itemId: item_id, itemName: item.name,
    oldValue: sys, newValue: physical_qty,
    note: `Diff ${diff}. Auditor count.`
  });
  res.status(201).json({ success: true, data: { item_id, system_qty: sys, physical_qty, difference: diff } });
});

app.get('/api/auditor/exceptions', authenticate, requireRole('super_admin', 'auditor'), requirePermission('EXCEPTIONS_VIEW'), (req, res) => {
  const exceptions = [];

  // 1. Self approval
  const selfApprove = db.prepare(`
    SELECT id, number FROM transactions
    WHERE approved_by IS NOT NULL AND approved_by = requested_by
  `).all();
  for (const t of selfApprove) {
    exceptions.push({ severity: 'critical', title: 'Self-Approval', txn: t.number, detail: `Transaction ${t.number} was approved by the same user who created it.` });
  }

  // 2. Large adjustment ≥ 100
  const largeAdj = db.prepare(`
    SELECT t.id, t.number, SUM(ti.qty) q FROM transactions t
    JOIN transaction_items ti ON ti.transaction_id=t.id
    WHERE t.type LIKE 'ADJUSTMENT%' GROUP BY t.id HAVING q >= 100
  `).all();
  for (const t of largeAdj) {
    exceptions.push({ severity: 'warn', title: 'Large Adjustment', txn: t.number, detail: `Adjustment of ${t.q} units exceeds 100-unit threshold.` });
  }

  // 3. Repeated rejections
  const repeated = db.prepare(`
    SELECT requested_by, COUNT(*) c, u.name FROM transactions t JOIN users u ON u.id=t.requested_by
    WHERE t.status='Rejected' GROUP BY requested_by HAVING c >= 2
  `).all();
  for (const r of repeated) {
    exceptions.push({ severity: 'warn', title: 'Repeated Rejections', detail: `${r.name} has ${r.c} rejected transactions.` });
  }

  // 4. Approval delays
  const slaHours = parseInt(db.prepare(`SELECT value FROM settings WHERE key='sla_hours'`).get()?.value || '24');
  const overdue = db.prepare(`
    SELECT number, submitted_at FROM transactions
    WHERE status='Pending Approval' AND julianday('now') - julianday(submitted_at) > ?
  `).all(slaHours / 24);
  for (const r of overdue) {
    exceptions.push({ severity: 'warn', title: 'Approval Delay', txn: r.number, detail: `Pending since ${r.submitted_at}, exceeding SLA of ${slaHours}h.` });
  }

  // 5. Stock discrepancies from reconciliations
  const disc = db.prepare(`
    SELECT rr.*, i.name FROM reconciliation_records rr JOIN items i ON i.id=rr.item_id
    WHERE ABS(rr.difference) >= 10
  `).all();
  for (const r of disc) {
    exceptions.push({ severity: 'warn', title: 'Stock Discrepancy', detail: `${r.name}: system ${r.system_qty} vs physical ${r.physical_qty} (diff ${r.difference}).` });
  }

  // 6. Excessive reversals
  const revCount = db.prepare(`SELECT COUNT(*) c FROM transactions WHERE status='Reversed'`).get().c;
  if (revCount >= 3) {
    exceptions.push({ severity: 'warn', title: 'Excessive Reversals', detail: `${revCount} transactions reversed — review control environment.` });
  }

  res.json({ success: true, data: exceptions });
});

// ======================================================================
// GENERAL REPORTS (read-only, exposed to all authenticated users)
// ======================================================================
app.get('/api/reports/current-stock', authenticate, requirePermission('REPORTS_VIEW'), (req, res) => {
  const rows = db.prepare(`
    SELECT i.code, i.name, i.unit, i.unit_cost, i.min_stock,
           COALESCE(ib.qty,0) AS qty,
           (COALESCE(ib.qty,0) * i.unit_cost) AS value,
           c.name AS category, i.warehouse, i.rack, i.shelf, i.bin
    FROM items i
    LEFT JOIN inventory_balances ib ON ib.item_id=i.id
    LEFT JOIN categories c ON c.id = i.category_id
    ORDER BY i.name
  `).all();
  res.json({ success: true, data: rows });
});

app.get('/api/reports/inventory-value', authenticate, requirePermission('REPORTS_VIEW'), (req, res) => {
  const rows = db.prepare(`
    SELECT c.name AS category, SUM(ib.qty * i.unit_cost) AS value
    FROM items i
    LEFT JOIN categories c ON c.id = i.category_id
    LEFT JOIN inventory_balances ib ON ib.item_id=i.id
    GROUP BY c.id
  `).all();
  res.json({ success: true, data: rows });
});

// ======================================================================
// AUDIT LOG ENDPOINTS — read-only on /api/audit-logs. No PUT/PATCH/DELETE
// ======================================================================
app.get('/api/audit-logs', authenticate, (req, res) => {
  if (!['super_admin', 'auditor', 'warehouse_manager'].includes(req.user.role)) {
    return sendError(res, 403, 'FORBIDDEN', 'Not permitted to view audit logs.');
  }
  const { from, to, user, action } = req.query;
  let sql = `SELECT * FROM audit_logs WHERE 1=1`;
  const args = [];
  if (from) sql += ` AND date(created_at)>=?`, args.push(from);
  if (to)   sql += ` AND date(created_at)<=?`, args.push(to);
  if (user) { sql += ` AND user_name LIKE ?`; args.push(`%${user}%`); }
  if (action) { sql += ` AND action LIKE ?`; args.push(`%${action}%`); }
  sql += ` ORDER BY created_at DESC LIMIT 2000`;
  res.json({ success: true, data: db.prepare(sql).all(...args) });
});

// Explicitly block mutation methods on audit logs
app.put('/api/audit-logs/:id', (req, res) => sendError(res, 405, 'METHOD_NOT_ALLOWED', 'Audit logs cannot be modified.'));
app.patch('/api/audit-logs/:id', (req, res) => sendError(res, 405, 'METHOD_NOT_ALLOWED', 'Audit logs cannot be modified.'));
app.delete('/api/audit-logs/:id', (req, res) => sendError(res, 405, 'METHOD_NOT_ALLOWED', 'Audit logs cannot be modified.'));
app.delete('/api/audit-logs', (req, res) => sendError(res, 405, 'METHOD_NOT_ALLOWED', 'Audit logs cannot be modified.'));

// ======================================================================
// NOTIFICATIONS
// ======================================================================
app.get('/api/notifications', authenticate, (req, res) => {
  const rows = db.prepare(`SELECT * FROM notifications WHERE user_id=? ORDER BY created_at DESC LIMIT 50`).all(req.user.id);
  res.json({ success: true, data: rows });
});
app.post('/api/notifications/:id/read', authenticate, (req, res) => {
  db.prepare(`UPDATE notifications SET is_read=1 WHERE id=? AND user_id=?`).run(req.params.id, req.user.id);
  res.json({ success: true });
});

// ======================================================================
// ADMIN — user management
// ======================================================================
app.get('/api/admin/users', authenticate, requireRole('super_admin'), (req, res) => {
  const rows = db.prepare(`SELECT id,username,name,role,active,created_at FROM users ORDER BY name`).all();
  res.json({ success: true, data: rows });
});

app.post('/api/admin/users', authenticate, requireRole('super_admin'), (req, res) => {
  const { username, password, name, role } = req.body || {};
  if (!username || !password || !name || !role) return sendError(res, 422, 'VALIDATION', 'All fields required.');
  if (!['super_admin', 'warehouse_manager', 'storekeeper', 'auditor'].includes(role)) {
    return sendError(res, 422, 'VALIDATION', 'Invalid role.');
  }
  if (db.prepare(`SELECT 1 FROM users WHERE username=?`).get(username)) return sendError(res, 409, 'DUPLICATE', 'Username exists.');
  const hash = bcrypt.hashSync(password, 10);
  const info = db.prepare(`INSERT INTO users(username,password_hash,name,role,active) VALUES (?,?,?,?,1)`)
    .run(username, hash, name, role);
  logAudit(req, 'USER_CREATED', { note: `${username} (${role})` });
  res.status(201).json({ success: true, data: { id: info.lastInsertRowid } });
});

// ======================================================================
// SEEDING — first-run setup
// ======================================================================
function seedIfEmpty() {
  const userCount = db.prepare(`SELECT COUNT(*) c FROM users`).get().c;
  if (userCount > 0) return;

  console.log('🌱 Seeding initial data...');

  db.transaction(() => {
    const hash = pw => bcrypt.hashSync(pw, 10);
    const insertUser = db.prepare(`INSERT INTO users(username,password_hash,name,role,active) VALUES (?,?,?,?,1)`);
    insertUser.run('admin',   hash('admin'),   'System Admin',   'super_admin');
    insertUser.run('manager', hash('manager'), 'Abebe Manager',  'warehouse_manager');
    insertUser.run('store',   hash('store'),   'John Storekeeper', 'storekeeper');
    insertUser.run('auditor', hash('auditor'), 'Sara Auditor',   'auditor');

    const cat = db.prepare(`INSERT INTO categories(name) VALUES (?)`);
    const c1 = cat.run('Bearings').lastInsertRowid;
    const c2 = cat.run('Belts').lastInsertRowid;
    const c3 = cat.run('Fasteners').lastInsertRowid;
    const c4 = cat.run('Consumables').lastInsertRowid;

    const sup = db.prepare(`INSERT INTO suppliers(name,contact,email,address) VALUES (?,?,?,?)`);
    const s1 = sup.run('Addis Bearing Supply', '+251-911-111111', 'sales@abs.et', 'Addis Ababa').lastInsertRowid;
    const s2 = sup.run('Ethio Industrial Parts', '+251-911-222222', 'info@eip.et', 'Adama').lastInsertRowid;
    const s3 = sup.run('Fastener House PLC', '+251-911-333333', 'fh@example.et', 'Addis Ababa').lastInsertRowid;
    const s4 = sup.run('WeldPro Ethiopia', '+251-911-444444', 'sales@weldpro.et', 'Hawassa').lastInsertRowid;

    const dept = db.prepare(`INSERT INTO departments(name) VALUES (?)`);
    dept.run('Maintenance');
    dept.run('Production');
    dept.run('Workshop');
    dept.run('Project Alpha');
    dept.run('Project Beta');
    dept.run('Branch - Adama');

    const insertItem = db.prepare(`
      INSERT INTO items(code,sku,barcode,name,description,category_id,subcategory,unit,
        min_stock,max_stock,reorder_level,unit_cost,warehouse,building,rack,shelf,bin,
        supplier_id,status)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    `);
    const insertBal = db.prepare(`INSERT INTO inventory_balances(item_id,qty) VALUES (?,0)`);
    const makeItem = (data) => {
      const id = insertItem.run(
        data.code, data.sku, data.barcode, data.name, data.desc,
        data.catId, data.sub, data.unit, data.min, data.max, data.reorder, data.cost,
        'Main Warehouse', data.building, data.rack, data.shelf, data.bin,
        data.supId, 'Active'
      ).lastInsertRowid;
      insertBal.run(id);
      return id;
    };

    const i1 = makeItem({ code:'BRG-6205', sku:'SKU-6205', barcode:'1000000001', name:'Bearing 6205', desc:'Deep groove ball bearing', catId:c1, sub:'Ball Bearings', unit:'pcs', min:20, max:500, reorder:50, cost:500, building:'A', rack:'R-03', shelf:'S-02', bin:'B-05', supId:s1 });
    const i2 = makeItem({ code:'BRG-6206', sku:'SKU-6206', barcode:'1000000002', name:'Bearing 6206', desc:'Deep groove ball bearing', catId:c1, sub:'Ball Bearings', unit:'pcs', min:20, max:400, reorder:40, cost:650, building:'A', rack:'R-03', shelf:'S-02', bin:'B-06', supId:s1 });
    const i3 = makeItem({ code:'BLT-B52',  sku:'SKU-B52',  barcode:'1000000003', name:'V-Belt B-52',  desc:'V-belt type B', catId:c2, sub:'V-Belts', unit:'pcs', min:10, max:200, reorder:25, cost:180, building:'A', rack:'R-05', shelf:'S-01', bin:'B-02', supId:s2 });
    const i4 = makeItem({ code:'BLT-M10',  sku:'SKU-M10',  barcode:'1000000004', name:'Bolt M10',     desc:'Hex bolt M10x50', catId:c3, sub:'Bolts', unit:'pcs', min:100, max:5000, reorder:300, cost:8, building:'B', rack:'R-01', shelf:'S-03', bin:'B-01', supId:s3 });
    const i5 = makeItem({ code:'WLD-ELC',  sku:'SKU-WLD',  barcode:'1000000005', name:'Welding Electrode', desc:'Welding electrode 3.2mm', catId:c4, sub:'Welding', unit:'kg', min:50, max:1000, reorder:100, cost:220, building:'B', rack:'R-02', shelf:'S-01', bin:'B-04', supId:s4 });

    // Opening balance via admin
    const admin = db.prepare(`SELECT id FROM users WHERE username='admin'`).get();

    // Insert an approved OPENING transaction
    const openId = uid();
    db.prepare(`INSERT INTO transactions(id,number,type,date,status,requested_by,approved_by,approved_at,submitted_at,notes)
                VALUES (?,?,?,?,?,?,?,?,?,?)`)
      .run(openId, 'OPEN-00001', 'OPENING', today(), 'Approved', admin.id, admin.id, nowIso(), nowIso(), 'Initial balances');
    const openingItems = [
      { item: i1, qty: 1000 },
      { item: i2, qty: 500 },
      { item: i3, qty: 300 },
      { item: i4, qty: 5000 },
      { item: i5, qty: 800 },
    ];
    const insOpenLine = db.prepare(`INSERT INTO transaction_items(transaction_id,item_id,qty,unit_cost,unit) VALUES (?,?,?,?,?)`);
    const upsertBal = db.prepare(`
      INSERT INTO inventory_balances(item_id,qty) VALUES (?,?)
      ON CONFLICT(item_id) DO UPDATE SET qty = qty + excluded.qty
    `);
    const insMove = db.prepare(`INSERT INTO inventory_movements(transaction_id,item_id,movement_type,qty,unit_cost,balance_after) VALUES (?,?,?,?,?,?)`);
    for (const o of openingItems) {
      const item = db.prepare(`SELECT * FROM items WHERE id=?`).get(o.item);
      insOpenLine.run(openId, o.item, o.qty, item.unit_cost, item.unit);
      upsertBal.run(o.item, o.qty);
      insMove.run(openId, o.item, 'IN', o.qty, item.unit_cost, o.qty);
    }
    db.prepare(`INSERT INTO approval_history(transaction_id,user_id,user_name,action,comment) VALUES (?,?,?,?,?)`)
      .run(openId, admin.id, 'System Admin', 'Approved', 'Opening balances');

    // Settings
    const setSetting = db.prepare(`INSERT OR REPLACE INTO settings(key,value) VALUES (?,?)`);
    setSetting.run('company', 'Ethiopian Warehouse Co.');
    setSetting.run('address', 'Addis Ababa, Ethiopia');
    setSetting.run('phone', '+251-11-XXX-XXXX');
    setSetting.run('currency', 'ETB');
    setSetting.run('sla_hours', String(CONFIG.DEFAULT_SLA_HOURS));
    setSetting.run('allow_negative_stock', '0');

    // Pre-seed seq keys
    setSetting.run('seq.IN', '0');
    setSetting.run('seq.OUT', '0');
    setSetting.run('seq.ADJ', '0');
    setSetting.run('seq.OPEN', '1');
    setSetting.run('seq.REV', '0');
  })();

  console.log('✅ Seed complete. Demo accounts:');
  console.log('   admin/admin · manager/manager · store/store · auditor/auditor');
}

// ======================================================================
// BOOT
// ======================================================================
initSchema();
seedIfEmpty();

// Simple health check
app.get('/api/health', (req, res) => res.json({ ok: true, time: nowIso() }));

// Global 404
app.use('/api', (req, res) => sendError(res, 404, 'NOT_FOUND', `Unknown endpoint: ${req.method} ${req.path}`));

// Error handler
app.use((err, req, res, next) => {
  console.error('Unhandled:', err);
  res.status(500).json({ success: false, error: 'INTERNAL_ERROR', message: 'Server error.' });
});

app.listen(CONFIG.PORT, () => {
  console.log(`\n🏭 Warehouse IMS backend listening on http://localhost:${CONFIG.PORT}`);
  console.log(`   DB: ${CONFIG.DB_PATH}\n`);
});
