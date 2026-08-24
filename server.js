// ============================================================
// SERVER.JS - Inventory System with Supabase
// ============================================================

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const { createClient } = require('@supabase/supabase-js');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 5000;

// ============================================================
// SUPABASE CLIENT
// ============================================================
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_KEY;

if (!supabaseUrl || !supabaseKey) {
    console.error('❌ Missing SUPABASE_URL or SUPABASE_KEY in .env');
    process.exit(1);
}

const supabase = createClient(supabaseUrl, supabaseKey);

// ============================================================
// SEED DEFAULT ADMIN USER
// ============================================================
async function seedAdmin() {
    try {
        const { data: users, error } = await supabase
            .from('users')
            .select('id')
            .eq('username', 'admin')
            .limit(1);

        if (error) {
            console.error('⚠️ Error checking admin user:', error.message);
            return;
        }

        if (!users || users.length === 0) {
            console.log('🔑 Creating default admin user...');
            const hashedPassword = await bcrypt.hash('admin123', 10);
            const { error: insertError } = await supabase
                .from('users')
                .insert({
                    username: 'admin',
                    password: hashedPassword,
                    full_name: 'Administrator',
                    role: 'admin'
                });
            if (insertError) {
                console.error('❌ Error creating admin:', insertError.message);
            } else {
                console.log('✅ Admin user created (username: admin, password: admin123)');
            }
        } else {
            console.log('✅ Admin user already exists.');
        }
    } catch (err) {
        console.error('❌ Seed error:', err.message);
    }
}

// Run seed
seedAdmin();

// ============================================================
// MIDDLEWARE
// ============================================================
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, '.')));

// ============================================================
// JWT CONFIG
// ============================================================
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-key-change-me';

// ============================================================
// AUTHENTICATION MIDDLEWARE
// ============================================================
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Authentication required' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        return res.status(403).json({ error: 'Invalid or expired token' });
    }
}

function requireAdmin(req, res, next) {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Admin access required' });
    }
    next();
}

// ============================================================
// HELPER: Run Supabase Query with Error Handling
// ============================================================
async function supabaseQuery(table, operation, params = {}) {
    try {
        let query = supabase.from(table);

        if (operation === 'select') {
            const { select = '*', filter = {}, order = {}, range = {} } = params;
            let q = query.select(select);

            for (const [key, value] of Object.entries(filter)) {
                if (Array.isArray(value)) {
                    q = q.in(key, value);
                } else if (typeof value === 'object' && value.operator) {
                    q = q.filter(key, value.operator, value.value);
                } else {
                    q = q.eq(key, value);
                }
            }

            if (order.column) {
                q = q.order(order.column, { ascending: order.ascending !== false });
            }

            if (range.start !== undefined && range.end !== undefined) {
                q = q.range(range.start, range.end);
            }

            const { data, error } = await q;
            if (error) throw error;
            return { data, error: null };
        }

        if (operation === 'insert') {
            const { data, error } = await query.insert(params.data).select();
            if (error) throw error;
            return { data, error: null };
        }

        if (operation === 'update') {
            const { data, error } = await query
                .update(params.data)
                .eq(params.matchField || 'id', params.matchValue)
                .select();
            if (error) throw error;
            return { data, error: null };
        }

        if (operation === 'delete') {
            const { data, error } = await query
                .delete()
                .eq(params.matchField || 'id', params.matchValue)
                .select();
            if (error) throw error;
            return { data, error: null };
        }

        throw new Error(`Unsupported operation: ${operation}`);
    } catch (error) {
        return { data: null, error: error.message };
    }
}

// ============================================================
// AUTHENTICATION ROUTES
// ============================================================
app.post('/api/auth/login', [
    body('username').notEmpty().withMessage('Username required'),
    body('password').notEmpty().withMessage('Password required')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { username, password } = req.body;

    try {
        const { data: users, error } = await supabase
            .from('users')
            .select('*')
            .eq('username', username);

        if (error) throw new Error(error.message);
        if (!users || users.length === 0) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const user = users[0];
        const valid = await bcrypt.compare(password, user.password);
        if (!valid) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const token = jwt.sign(
            { id: user.id, username: user.username, role: user.role },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({
            token,
            user: {
                id: user.id,
                username: user.username,
                fullName: user.full_name,
                role: user.role
            }
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/auth/register', [
    body('username').notEmpty().withMessage('Username required'),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 chars'),
    body('fullName').optional()
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { username, password, fullName, role } = req.body;

    try {
        const { data: existing } = await supabase
            .from('users')
            .select('id')
            .eq('username', username);

        if (existing && existing.length > 0) {
            return res.status(400).json({ error: 'Username already exists' });
        }

        const hashed = await bcrypt.hash(password, 10);
        const { data, error } = await supabase
            .from('users')
            .insert({
                username,
                password: hashed,
                full_name: fullName || username,
                role: role || 'staff'
            })
            .select();

        if (error) throw new Error(error.message);

        res.status(201).json({
            message: 'User created successfully',
            user: data[0]
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ============================================================
// ITEM ROUTES
// ============================================================
app.get('/api/items', authenticateToken, async (req, res) => {
    const {
        search,
        category,
        status,
        sort = 'id',
        order = 'ASC',
        page = 1,
        limit = 20
    } = req.query;

    try {
        let query = supabase.from('items').select('*', { count: 'exact' });

        if (search) {
            query = query.or(`name.ilike.%${search}%,id::text.ilike.%${search}%`);
        }
        if (category && category !== 'all') {
            query = query.eq('category', category);
        }
        if (status && status !== 'all') {
            query = query.eq('status', status);
        }

        const orderField = sort === 'total_price' ? 'total_price' : sort;
        const ascending = order.toUpperCase() !== 'DESC';
        query = query.order(orderField, { ascending });

        const pageNum = parseInt(page);
        const limitNum = parseInt(limit);
        const start = (pageNum - 1) * limitNum;
        const end = start + limitNum - 1;

        query = query.range(start, end);

        const { data, error, count } = await query;

        if (error) throw new Error(error.message);

        data.forEach(item => {
            item.total_price = item.quantity * item.unit_price;
        });

        res.json({
            items: data,
            pagination: {
                page: pageNum,
                limit: limitNum,
                total: count || 0,
                pages: Math.ceil((count || 0) / limitNum)
            }
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/items/:id', authenticateToken, async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('items')
            .select('*')
            .eq('id', req.params.id);

        if (error) throw new Error(error.message);
        if (!data || data.length === 0) {
            return res.status(404).json({ error: 'Item not found' });
        }

        const item = data[0];
        item.total_price = item.quantity * item.unit_price;
        res.json(item);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/items', authenticateToken, [
    body('name').notEmpty().withMessage('Item name required'),
    body('unit').notEmpty().withMessage('Unit required'),
    body('quantity').isFloat({ min: 0 }).withMessage('Quantity must be >= 0'),
    body('unitPrice').isFloat({ min: 0 }).withMessage('Unit price must be >= 0')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const {
        name, unit, quantity = 0, unitPrice = 0,
        category = 'raw_material', itemType = 'durable',
        status = 'active', description = '',
        minStockLevel = 5, maxStockLevel = 100, location = ''
    } = req.body;

    try {
        const totalPrice = quantity * unitPrice;
        const { data, error } = await supabase
            .from('items')
            .insert({
                name, unit, quantity, unit_price: unitPrice,
                total_price: totalPrice,
                category, item_type: itemType,
                status, description,
                min_stock_level: minStockLevel,
                max_stock_level: maxStockLevel,
                location
            })
            .select();

        if (error) throw new Error(error.message);

        const newItem = data[0];

        if (quantity > 0) {
            await supabase
                .from('transactions')
                .insert({
                    item_id: newItem.id,
                    item_name: newItem.name,
                    type: 'IN',
                    quantity: quantity,
                    unit: newItem.unit,
                    unit_price: newItem.unit_price,
                    total_price: quantity * newItem.unit_price,
                    description: 'Initial stock entry',
                    performed_by: req.user.username
                });
        }

        newItem.total_price = newItem.quantity * newItem.unit_price;
        res.status(201).json(newItem);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.put('/api/items/:id', authenticateToken, [
    body('name').notEmpty().withMessage('Item name required'),
    body('unit').notEmpty().withMessage('Unit required'),
    body('quantity').isFloat({ min: 0 }).withMessage('Quantity must be >= 0'),
    body('unitPrice').isFloat({ min: 0 }).withMessage('Unit price must be >= 0')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const id = req.params.id;
    const {
        name, unit, quantity, unitPrice,
        category, itemType, status, description,
        minStockLevel, maxStockLevel, location
    } = req.body;

    try {
        const { data: currentData, error: fetchError } = await supabase
            .from('items')
            .select('*')
            .eq('id', id);

        if (fetchError) throw new Error(fetchError.message);
        if (!currentData || currentData.length === 0) {
            return res.status(404).json({ error: 'Item not found' });
        }

        const currentItem = currentData[0];
        const totalPrice = quantity * unitPrice;
        const now = new Date().toISOString();

        const { data, error } = await supabase
            .from('items')
            .update({
                name, unit, quantity, unit_price: unitPrice,
                total_price: totalPrice,
                category, item_type: itemType,
                status, description,
                min_stock_level: minStockLevel || 5,
                max_stock_level: maxStockLevel || 100,
                location: location || '',
                updated_at: now
            })
            .eq('id', id)
            .select();

        if (error) throw new Error(error.message);

        const qtyDiff = quantity - currentItem.quantity;
        if (qtyDiff !== 0) {
            const type = qtyDiff > 0 ? 'IN' : 'OUT';
            await supabase
                .from('transactions')
                .insert({
                    item_id: id,
                    item_name: name,
                    type: type,
                    quantity: Math.abs(qtyDiff),
                    unit: unit,
                    unit_price: unitPrice,
                    total_price: Math.abs(qtyDiff) * unitPrice,
                    description: `Stock adjustment: ${type} ${Math.abs(qtyDiff)} units`,
                    performed_by: req.user.username
                });
        }

        const updatedItem = data[0];
        updatedItem.total_price = updatedItem.quantity * updatedItem.unit_price;
        res.json(updatedItem);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/items/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        await supabase
            .from('transactions')
            .delete()
            .eq('item_id', req.params.id);

        const { data, error } = await supabase
            .from('items')
            .delete()
            .eq('id', req.params.id)
            .select();

        if (error) throw new Error(error.message);
        if (!data || data.length === 0) {
            return res.status(404).json({ error: 'Item not found' });
        }

        res.json({ message: 'Item deleted successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ============================================================
// TRANSACTION ROUTES
// ============================================================
app.get('/api/transactions', authenticateToken, async (req, res) => {
    const { type, itemId, startDate, endDate, page = 1, limit = 50 } = req.query;

    try {
        let query = supabase.from('transactions').select('*', { count: 'exact' });

        if (type && type !== 'all') {
            query = query.eq('type', type.toUpperCase());
        }
        if (itemId) {
            query = query.eq('item_id', parseInt(itemId));
        }
        if (startDate) {
            query = query.gte('created_at', startDate);
        }
        if (endDate) {
            query = query.lte('created_at', endDate + ' 23:59:59');
        }

        query = query.order('created_at', { ascending: false });

        const pageNum = parseInt(page);
        const limitNum = parseInt(limit);
        const start = (pageNum - 1) * limitNum;
        const end = start + limitNum - 1;

        query = query.range(start, end);

        const { data, error, count } = await query;
        if (error) throw new Error(error.message);

        res.json({
            transactions: data,
            pagination: {
                page: pageNum,
                limit: limitNum,
                total: count || 0,
                pages: Math.ceil((count || 0) / limitNum)
            }
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/transactions', authenticateToken, [
    body('itemId').isInt().withMessage('Valid item ID required'),
    body('type').isIn(['IN', 'OUT']).withMessage('Type must be IN or OUT'),
    body('quantity').isFloat({ min: 0.001 }).withMessage('Quantity must be > 0')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { itemId, type, quantity, description, reference } = req.body;

    try {
        const { data: itemData, error: itemError } = await supabase
            .from('items')
            .select('*')
            .eq('id', itemId);

        if (itemError) throw new Error(itemError.message);
        if (!itemData || itemData.length === 0) {
            return res.status(404).json({ error: 'Item not found' });
        }

        const item = itemData[0];

        if (type === 'OUT' && item.quantity < quantity) {
            return res.status(400).json({
                error: `Insufficient stock. Available: ${item.quantity} ${item.unit}`
            });
        }

        const totalPrice = quantity * item.unit_price;

        const { data: txnData, error: txnError } = await supabase
            .from('transactions')
            .insert({
                item_id: itemId,
                item_name: item.name,
                type: type,
                quantity: quantity,
                unit: item.unit,
                unit_price: item.unit_price,
                total_price: totalPrice,
                description: description || '',
                reference: reference || '',
                performed_by: req.user.username
            })
            .select();

        if (txnError) throw new Error(txnError.message);

        const newQuantity = type === 'IN' ? item.quantity + quantity : item.quantity - quantity;
        const newTotalPrice = newQuantity * item.unit_price;

        await supabase
            .from('items')
            .update({
                quantity: newQuantity,
                total_price: newTotalPrice,
                updated_at: new Date().toISOString()
            })
            .eq('id', itemId);

        res.status(201).json(txnData[0]);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/items/:id/transactions', authenticateToken, async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('transactions')
            .select('*')
            .eq('item_id', req.params.id)
            .order('created_at', { ascending: false });

        if (error) throw new Error(error.message);
        res.json(data);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ============================================================
// CATEGORY ROUTES
// ============================================================
app.get('/api/categories', authenticateToken, async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('categories')
            .select('*')
            .order('name');

        if (error) throw new Error(error.message);
        res.json(data);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/categories', authenticateToken, requireAdmin, [
    body('name').notEmpty().withMessage('Category name required')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { name, description } = req.body;

    try {
        const { data, error } = await supabase
            .from('categories')
            .insert({ name, description: description || '' })
            .select();

        if (error) throw new Error(error.message);
        res.status(201).json(data[0]);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ============================================================
// DASHBOARD STATS
// ============================================================
app.get('/api/dashboard/stats', authenticateToken, async (req, res) => {
    try {
        const { count: totalItems, error: countError } = await supabase
            .from('items')
            .select('*', { count: 'exact', head: true });

        if (countError) throw new Error(countError.message);

        const { data: valueData, error: valueError } = await supabase
            .from('items')
            .select('total_price');

        if (valueError) throw new Error(valueError.message);
        const totalValue = valueData.reduce((sum, row) => sum + (row.total_price || 0), 0);

        const { count: lowStockCount, error: lowError } = await supabase
            .from('items')
            .select('*', { count: 'exact', head: true })
            .lte('quantity', 'min_stock_level')
            .gt('quantity', 0);

        if (lowError) throw new Error(lowError.message);

        const { data: allItems } = await supabase
            .from('items')
            .select('category');

        const categoryBreakdown = {};
        (allItems || []).forEach(item => {
            categoryBreakdown[item.category] = (categoryBreakdown[item.category] || 0) + 1;
        });

        const { data: allItemsStatus } = await supabase
            .from('items')
            .select('status');

        const statusBreakdown = {};
        (allItemsStatus || []).forEach(item => {
            const status = item.status || 'active';
            statusBreakdown[status] = (statusBreakdown[status] || 0) + 1;
        });

        const { data: recentTxns, error: txnError } = await supabase
            .from('transactions')
            .select('*')
            .order('created_at', { ascending: false })
            .limit(10);

        if (txnError) throw new Error(txnError.message);

        const { data: monthlyData, error: monthlyError } = await supabase
            .from('transactions')
            .select('created_at, type, quantity');

        if (monthlyError) throw new Error(monthlyError.message);

        const monthlySummary = {};
        (monthlyData || []).forEach(txn => {
            const month = new Date(txn.created_at).toISOString().slice(0, 7);
            if (!monthlySummary[month]) monthlySummary[month] = { stock_in: 0, stock_out: 0 };
            if (txn.type === 'IN') monthlySummary[month].stock_in += txn.quantity;
            else if (txn.type === 'OUT') monthlySummary[month].stock_out += txn.quantity;
        });

        const monthlySummaryArray = Object.entries(monthlySummary)
            .map(([month, data]) => ({ month, ...data }))
            .sort((a, b) => b.month.localeCompare(a.month))
            .slice(0, 12);

        res.json({
            totalItems: totalItems || 0,
            totalValue: totalValue || 0,
            lowStockItems: lowStockCount || 0,
            categoryBreakdown: Object.entries(categoryBreakdown).map(([category, count]) => ({ category, count })),
            statusBreakdown: Object.entries(statusBreakdown).map(([status, count]) => ({ status, count })),
            recentTransactions: recentTxns || [],
            monthlySummary: monthlySummaryArray
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ============================================================
// SUPPLIER ROUTES
// ============================================================
app.get('/api/suppliers', authenticateToken, async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('suppliers')
            .select('*')
            .order('name');

        if (error) throw new Error(error.message);
        res.json(data);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/suppliers', authenticateToken, requireAdmin, [
    body('name').notEmpty().withMessage('Supplier name required')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { name, contactPerson, phone, email, address, taxId } = req.body;

    try {
        const { data, error } = await supabase
            .from('suppliers')
            .insert({
                name,
                contact_person: contactPerson || '',
                phone: phone || '',
                email: email || '',
                address: address || '',
                tax_id: taxId || ''
            })
            .select();

        if (error) throw new Error(error.message);
        res.status(201).json(data[0]);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ============================================================
// REPORT ROUTES
// ============================================================
app.get('/api/reports/top-items', authenticateToken, async (req, res) => {
    const limit = parseInt(req.query.limit) || 10;
    try {
        const { data, error } = await supabase
            .from('items')
            .select('id, name, unit, quantity, unit_price, total_price, category')
            .gt('quantity', 0)
            .order('total_price', { ascending: false })
            .limit(limit);

        if (error) throw new Error(error.message);
        res.json(data);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/reports/monthly-summary', authenticateToken, async (req, res) => {
    const year = req.query.year || new Date().getFullYear();
    try {
        const { data, error } = await supabase
            .from('transactions')
            .select('created_at, type, quantity')
            .gte('created_at', `${year}-01-01`)
            .lte('created_at', `${year}-12-31`);

        if (error) throw new Error(error.message);

        const summary = {};
        (data || []).forEach(txn => {
            const month = new Date(txn.created_at).toISOString().slice(5, 7);
            if (!summary[month]) summary[month] = { stock_in: 0, stock_out: 0 };
            if (txn.type === 'IN') summary[month].stock_in += txn.quantity;
            else if (txn.type === 'OUT') summary[month].stock_out += txn.quantity;
        });

        const result = Object.entries(summary)
            .map(([month, data]) => ({ month, ...data }))
            .sort((a, b) => a.month.localeCompare(b.month));

        res.json(result);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/reports/low-stock', authenticateToken, async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('items')
            .select('id, name, unit, quantity, min_stock_level, category')
            .lte('quantity', 'min_stock_level')
            .gt('quantity', 0)
            .order('quantity', { ascending: true });

        if (error) throw new Error(error.message);
        res.json(data);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ============================================================
// USER MANAGEMENT (Admin only)
// ============================================================
app.get('/api/users', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('users')
            .select('id, username, full_name, role, created_at');

        if (error) throw new Error(error.message);
        res.json(data);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ============================================================
// SERVE FRONTEND - CORRECTED ROUTE
// ============================================================
app.get('/', (req, res) => {
    const indexPath = path.join(__dirname, 'index.html');
    if (fs.existsSync(indexPath)) {
        res.sendFile(indexPath);
    } else {
        res.status(404).json({ error: 'Frontend not found. Place index.html.' });
    }
});

// ============================================================
// START SERVER
// ============================================================
app.listen(PORT, () => {
    console.log(`\n========================================`);
    console.log(`🚀 Inventory System Server Running`);
    console.log(`========================================`);
    console.log(`📡 Server: http://localhost:${PORT}`);
    console.log(`📊 API: http://localhost:${PORT}/api`);
    console.log(`🗄️  Database: Supabase (PostgreSQL)`);
    console.log(`🔑 Default Admin: admin / admin123`);
    console.log(`========================================\n`);
});
