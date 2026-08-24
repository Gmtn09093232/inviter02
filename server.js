// ============================================================
// SERVER.JS - Inventory System with Supabase (No Auth)
// Works with Express 5 – uses {*path} for wildcard routes
// ============================================================

require('dotenv').config();
const express = require('express');
const cors = require('cors');
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
// MIDDLEWARE
// ============================================================
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, '.')));

// ============================================================
// DUMMY USER FOR TRANSACTIONS
// ============================================================
const SYSTEM_USER = { username: 'admin', id: 1 };

// ============================================================
// HEALTH CHECK
// ============================================================
app.get('/api/health', (req, res) => {
    res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// ============================================================
// HELPER FUNCTIONS
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
// ALL ROUTES – AUTHENTICATION REMOVED
// ============================================================

// ---- Items ----
app.get('/api/items', async (req, res) => {
    const { search, category, status, sort = 'id', order = 'ASC', page = 1, limit = 20 } = req.query;
    try {
        let query = supabase.from('items').select('*', { count: 'exact' });
        if (search) query = query.or(`name.ilike.%${search}%,id::text.ilike.%${search}%`);
        if (category && category !== 'all') query = query.eq('category', category);
        if (status && status !== 'all') query = query.eq('status', status);
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
        data.forEach(item => { item.total_price = item.quantity * item.unit_price; });
        res.json({
            items: data,
            pagination: { page: pageNum, limit: limitNum, total: count || 0, pages: Math.ceil((count || 0) / limitNum) }
        });
    } catch (error) {
        console.error('❌ /api/items error:', error.message);
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/items/:id', async (req, res) => {
    try {
        const { data, error } = await supabase.from('items').select('*').eq('id', req.params.id);
        if (error) throw new Error(error.message);
        if (!data || data.length === 0) return res.status(404).json({ error: 'Item not found' });
        const item = data[0];
        item.total_price = item.quantity * item.unit_price;
        res.json(item);
    } catch (error) {
        console.error('❌ /api/items/:id error:', error.message);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/items', [
    body('name').notEmpty().withMessage('Item name required'),
    body('unit').notEmpty().withMessage('Unit required'),
    body('quantity').isFloat({ min: 0 }).withMessage('Quantity must be >= 0'),
    body('unitPrice').isFloat({ min: 0 }).withMessage('Unit price must be >= 0')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { name, unit, quantity = 0, unitPrice = 0, category = 'raw_material', itemType = 'durable',
        status = 'active', description = '', minStockLevel = 5, maxStockLevel = 100, location = '' } = req.body;

    try {
        const totalPrice = quantity * unitPrice;
        const { data, error } = await supabase
            .from('items')
            .insert({ name, unit, quantity, unit_price: unitPrice, total_price: totalPrice,
                category, item_type: itemType, status, description,
                min_stock_level: minStockLevel, max_stock_level: maxStockLevel, location })
            .select();
        if (error) throw new Error(error.message);
        const newItem = data[0];
        if (quantity > 0) {
            await supabase.from('transactions').insert({
                item_id: newItem.id,
                item_name: newItem.name,
                type: 'IN',
                quantity: quantity,
                unit: newItem.unit,
                unit_price: newItem.unit_price,
                total_price: quantity * newItem.unit_price,
                description: 'Initial stock entry',
                performed_by: SYSTEM_USER.username
            });
        }
        newItem.total_price = newItem.quantity * newItem.unit_price;
        res.status(201).json(newItem);
    } catch (error) {
        console.error('❌ POST /api/items error:', error.message);
        res.status(500).json({ error: error.message });
    }
});

app.put('/api/items/:id', [
    body('name').notEmpty().withMessage('Item name required'),
    body('unit').notEmpty().withMessage('Unit required'),
    body('quantity').isFloat({ min: 0 }).withMessage('Quantity must be >= 0'),
    body('unitPrice').isFloat({ min: 0 }).withMessage('Unit price must be >= 0')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const id = req.params.id;
    const { name, unit, quantity, unitPrice, category, itemType, status, description,
        minStockLevel, maxStockLevel, location } = req.body;

    try {
        const { data: currentData, error: fetchError } = await supabase
            .from('items').select('*').eq('id', id);
        if (fetchError) throw new Error(fetchError.message);
        if (!currentData || currentData.length === 0) return res.status(404).json({ error: 'Item not found' });

        const currentItem = currentData[0];
        const totalPrice = quantity * unitPrice;
        const now = new Date().toISOString();

        const { data, error } = await supabase
            .from('items')
            .update({ name, unit, quantity, unit_price: unitPrice, total_price: totalPrice,
                category, item_type: itemType, status, description,
                min_stock_level: minStockLevel || 5, max_stock_level: maxStockLevel || 100,
                location: location || '', updated_at: now })
            .eq('id', id)
            .select();
        if (error) throw new Error(error.message);

        const qtyDiff = quantity - currentItem.quantity;
        if (qtyDiff !== 0) {
            const type = qtyDiff > 0 ? 'IN' : 'OUT';
            await supabase.from('transactions').insert({
                item_id: id,
                item_name: name,
                type: type,
                quantity: Math.abs(qtyDiff),
                unit: unit,
                unit_price: unitPrice,
                total_price: Math.abs(qtyDiff) * unitPrice,
                description: `Stock adjustment: ${type} ${Math.abs(qtyDiff)} units`,
                performed_by: SYSTEM_USER.username
            });
        }

        const updatedItem = data[0];
        updatedItem.total_price = updatedItem.quantity * updatedItem.unit_price;
        res.json(updatedItem);
    } catch (error) {
        console.error('❌ PUT /api/items/:id error:', error.message);
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/items/:id', async (req, res) => {
    try {
        await supabase.from('transactions').delete().eq('item_id', req.params.id);
        const { data, error } = await supabase.from('items').delete().eq('id', req.params.id).select();
        if (error) throw new Error(error.message);
        if (!data || data.length === 0) return res.status(404).json({ error: 'Item not found' });
        res.json({ message: 'Item deleted successfully' });
    } catch (error) {
        console.error('❌ DELETE /api/items/:id error:', error.message);
        res.status(500).json({ error: error.message });
    }
});

// ---- Transactions ----
app.get('/api/transactions', async (req, res) => {
    const { type, itemId, startDate, endDate, page = 1, limit = 50 } = req.query;
    try {
        let query = supabase.from('transactions').select('*', { count: 'exact' });
        if (type && type !== 'all') query = query.eq('type', type.toUpperCase());
        if (itemId) query = query.eq('item_id', parseInt(itemId));
        if (startDate) query = query.gte('created_at', startDate);
        if (endDate) query = query.lte('created_at', endDate + ' 23:59:59');
        query = query.order('created_at', { ascending: false });
        const pageNum = parseInt(page);
        const limitNum = parseInt(limit);
        const start = (pageNum - 1) * limitNum;
        const end = start + limitNum - 1;
        query = query.range(start, end);
        const { data, error, count } = await query;
        if (error) throw new Error(error.message);
        res.json({ transactions: data, pagination: { page: pageNum, limit: limitNum, total: count || 0, pages: Math.ceil((count || 0) / limitNum) } });
    } catch (error) {
        console.error('❌ /api/transactions error:', error.message);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/transactions', [
    body('itemId').isInt().withMessage('Valid item ID required'),
    body('type').isIn(['IN', 'OUT']).withMessage('Type must be IN or OUT'),
    body('quantity').isFloat({ min: 0.001 }).withMessage('Quantity must be > 0')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { itemId, type, quantity, description, reference } = req.body;
    try {
        const { data: itemData, error: itemError } = await supabase
            .from('items').select('*').eq('id', itemId);
        if (itemError) throw new Error(itemError.message);
        if (!itemData || itemData.length === 0) return res.status(404).json({ error: 'Item not found' });

        const item = itemData[0];
        if (type === 'OUT' && item.quantity < quantity) {
            return res.status(400).json({ error: `Insufficient stock. Available: ${item.quantity} ${item.unit}` });
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
                performed_by: SYSTEM_USER.username
            })
            .select();
        if (txnError) throw new Error(txnError.message);

        const newQuantity = type === 'IN' ? item.quantity + quantity : item.quantity - quantity;
        const newTotalPrice = newQuantity * item.unit_price;
        await supabase.from('items').update({ quantity: newQuantity, total_price: newTotalPrice, updated_at: new Date().toISOString() }).eq('id', itemId);

        res.status(201).json(txnData[0]);
    } catch (error) {
        console.error('❌ POST /api/transactions error:', error.message);
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/items/:id/transactions', async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('transactions')
            .select('*')
            .eq('item_id', req.params.id)
            .order('created_at', { ascending: false });
        if (error) throw new Error(error.message);
        res.json(data);
    } catch (error) {
        console.error('❌ /api/items/:id/transactions error:', error.message);
        res.status(500).json({ error: error.message });
    }
});

// ---- Categories ----
app.get('/api/categories', async (req, res) => {
    try {
        const { data, error } = await supabase.from('categories').select('*').order('name');
        if (error) throw new Error(error.message);
        res.json(data);
    } catch (error) {
        console.error('❌ /api/categories error:', error.message);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/categories', [
    body('name').notEmpty().withMessage('Category name required')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
    const { name, description } = req.body;
    try {
        const { data, error } = await supabase.from('categories').insert({ name, description: description || '' }).select();
        if (error) throw new Error(error.message);
        res.status(201).json(data[0]);
    } catch (error) {
        console.error('❌ POST /api/categories error:', error.message);
        res.status(500).json({ error: error.message });
    }
});

// ---- Dashboard Stats ----
app.get('/api/dashboard/stats', async (req, res) => {
    try {
        const { count: totalItems, error: countError } = await supabase
            .from('items').select('*', { count: 'exact', head: true });
        if (countError) throw new Error(countError.message);

        const { data: valueData, error: valueError } = await supabase
            .from('items').select('total_price');
        if (valueError) throw new Error(valueError.message);
        const totalValue = valueData.reduce((sum, row) => sum + (row.total_price || 0), 0);

        const { count: lowStockCount, error: lowError } = await supabase
            .from('items').select('*', { count: 'exact', head: true })
            .lte('quantity', 'min_stock_level').gt('quantity', 0);
        if (lowError) throw new Error(lowError.message);

        const { data: allItems } = await supabase.from('items').select('category');
        const categoryBreakdown = {};
        (allItems || []).forEach(item => {
            categoryBreakdown[item.category] = (categoryBreakdown[item.category] || 0) + 1;
        });

        const { data: allItemsStatus } = await supabase.from('items').select('status');
        const statusBreakdown = {};
        (allItemsStatus || []).forEach(item => {
            const status = item.status || 'active';
            statusBreakdown[status] = (statusBreakdown[status] || 0) + 1;
        });

        const { data: recentTxns, error: txnError } = await supabase
            .from('transactions').select('*').order('created_at', { ascending: false }).limit(10);
        if (txnError) throw new Error(txnError.message);

        const { data: monthlyData, error: monthlyError } = await supabase
            .from('transactions').select('created_at, type, quantity');
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
        console.error('❌ /api/dashboard/stats error:', error.message);
        res.status(500).json({ error: error.message });
    }
});

// ---- Suppliers ----
app.get('/api/suppliers', async (req, res) => {
    try {
        const { data, error } = await supabase.from('suppliers').select('*').order('name');
        if (error) throw new Error(error.message);
        res.json(data);
    } catch (error) {
        console.error('❌ /api/suppliers error:', error.message);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/suppliers', [
    body('name').notEmpty().withMessage('Supplier name required')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
    const { name, contactPerson, phone, email, address, taxId } = req.body;
    try {
        const { data, error } = await supabase.from('suppliers').insert({
            name,
            contact_person: contactPerson || '',
            phone: phone || '',
            email: email || '',
            address: address || '',
            tax_id: taxId || ''
        }).select();
        if (error) throw new Error(error.message);
        res.status(201).json(data[0]);
    } catch (error) {
        console.error('❌ POST /api/suppliers error:', error.message);
        res.status(500).json({ error: error.message });
    }
});

// ---- Reports ----
app.get('/api/reports/top-items', async (req, res) => {
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
        console.error('❌ /api/reports/top-items error:', error.message);
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/reports/monthly-summary', async (req, res) => {
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
        console.error('❌ /api/reports/monthly-summary error:', error.message);
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/reports/low-stock', async (req, res) => {
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
        console.error('❌ /api/reports/low-stock error:', error.message);
        res.status(500).json({ error: error.message });
    }
});

// ============================================================
// CATCH-ALL for API routes – FIXED for Express 5
// ============================================================
// Use named wildcard {*path} to avoid path-to-regexp error
app.use('/api/{*path}', (req, res) => {
    res.status(404).json({ error: `API endpoint not found: ${req.originalUrl}` });
});

// ---- Serve Frontend ----
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
    console.log(`🚀 Inventory System Server Running (No Auth)`);
    console.log(`========================================`);
    console.log(`📡 Server: http://localhost:${PORT}`);
    console.log(`📊 API: http://localhost:${PORT}/api`);
    console.log(`🏥 Health: http://localhost:${PORT}/api/health`);
    console.log(`🗄️  Database: Supabase (PostgreSQL)`);
    console.log(`👤 Default User: admin (auto-assigned)`);
    console.log(`========================================\n`);
});
