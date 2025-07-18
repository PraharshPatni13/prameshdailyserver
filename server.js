const dotenv = require('dotenv');
const path = require('path');
// const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
dotenv.config({ path: path.resolve(__dirname, '.env') });

const express = require('express');
const useragent = require('express-useragent');
const os = require('os');
const nodemailer = require('nodemailer');
const http = require('http');
const compression = require('compression');
const socketIO = require('socket.io');
const mysql = require('mysql2/promise');
const cors = require("cors");
const rateLimit = require('express-rate-limit');

const app = express();
const server = http.createServer(app);
const io = socketIO(server, {
    cors: {
        origin: 'https://prameshdailyserver.onrender.com',
        methods: ['GET', 'POST'],
    }
});

const dropdownRoutes = require("./routes/dropdownRoutes")

let db;

// === ✅ MySQL Database Connection ===
mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT || 3306,
}).then((connection) => {
    db = connection;
    console.log('✅ Connected to MySQL database');
}).catch((err) => {
    console.error(' Database connection failed:', err.stack);
});

// === 🔌 Socket.IO Setup ===
io.on('connection', (socket) => {
    console.log('Client connected:', socket.id);

    socket.on('new_data', (data) => {
        console.log('Received new_data:', data);
        io.emit('update_data', data);
    });

    socket.on('disconnect', () => {
        console.log('Client disconnected:', socket.id);
    });
});

// for mailing to the user 
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL, // your sender email
        pass: process.env.EMAIL_PASS    // Gmail app password (not your Gmail login)
    }
});

function sendLoginAttemptEmail(toEmail, deviceName) {
    const mailOptions = {
        from: '"Pramesh Security Team" <your_email@gmail.com>',
        to: toEmail,
        subject: '🔒 Security Alert: Unauthorized Login Attempt Detected',
        text: `Hello,\n\nWe detected a login attempt to your Pramesh account from device: ${deviceName}.\n\nIf this wasn't you, we strongly recommend changing your password immediately and contacting our support team.\n\n– Pramesh Security Team`,
        html: `
            <div style="font-family: Arial, sans-serif; padding: 20px; color: #333;">
                <h2 style="color: #E63946;">🔒 Unauthorized Login Attempt</h2>
                <p>Dear user,</p>
                <p>We detected an attempt to access your <strong>Pramesh Data Entry System</strong> account from the following device:</p>
                <p style="font-size: 16px; color: #0D1B2A;"><strong>Device Name:</strong> ${deviceName}</p>
                
                <p>If this attempt was <strong>not</strong> made by you, please take immediate action:</p>
                <ul>
                    <li>Change your account password.</li>
                    <li>Enable two-step verification if not already enabled.</li>
                    <li>Contact our support team at <a href="mailto:support@pramesh.com">support@pramesh.com</a></li>
                </ul>

                <p style="margin-top: 30px;">Stay safe,</p>
                <p style="font-weight: bold;">– Pramesh Security Team</p>

                <hr style="margin: 30px 0;">
                <small style="color: #6C757D;">This is an automated message. If you did not initiate this request, please ignore this email or contact support.</small>
            </div>
        `
    };

    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.error("Email failed:", error);
        } else {
            console.log("✅ Security alert email sent:", info.response);
        }
    });
}

app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ limit: '50mb', extended: true }));


// === 🌐 Express Middleware ===
app.use(express.json());
// app.use(express.json({ limit: '100mb' }));
app.use(compression({
    threshold: 0,
    filter: (req, res) => {
        if (req.headers['x-no-compression']) {
            return false;
        }
        return compression.filter(req, res);
    }
}));

app.use(cors());
app.use(useragent.express());
// === 📋 Route Logger Middleware ===
app.use((req, res, next) => {
    let color;

    switch (req.method) {
        case 'GET':
            color = '\x1b[32m'; // Green
            break;
        case 'POST':
        case 'PUT':
            color = '\x1b[33m'; // Yellow
            break;
        case 'DELETE':
            color = '\x1b[31m'; // Red
            break;
        default:
            color = '\x1b[0m';  // Reset (default)
    }

    console.log(`${color}${req.method} ${req.url}\x1b[0m`); // Reset color at end
    next();
});


app.use('/api', dropdownRoutes);
const queryLimiter = rateLimit({
    windowMs: 60 * 1000, // 1 minute
    max: 10, // limit to 10 queries per minute per IP
    message: 'Too many queries, slow down.',
});

app.use('/api/run-query', queryLimiter);

const allowedTables = ['KYC', 'Transaction', 'STP_Switch', 'Non_Financial', 'NSE_Pramesh', 'FFL_Transaction', 'FFL_STP_Switch', 'FFL_Non_Financial', 'NSE_FFL', 'FD', 'Realvalue'];

app.post('/api/logDownload', async (req, res) => {
    const { user_email, table_name, file_type } = req.body;
    const ip_address = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    const user_agent = req.headers['user-agent'];

    if (!user_email || !table_name || !file_type) {
        return res.status(400).json({ error: "Missing fields" });
    }

    try {
        await db.query(
            'INSERT INTO download_logs (user_email, table_name, file_type, ip_address, user_agent) VALUES (?, ?, ?, ?, ?)',
            [user_email, table_name, file_type, ip_address, user_agent]
        );
        res.json({ message: "Download logged successfully" });
    } catch (err) {
        console.error("❌ Failed to log download:", err);
        res.status(500).json({ error: "Logging failed" });
    }
});


// for importing excel file 
app.use(express.json()); // ✅ Needed to parse JSON body

const excelDateToMySQLDate = (value) => {
    if (typeof value === 'number') {
        const excelEpoch = new Date(Date.UTC(1899, 11, 30));
        const mysqlDate = new Date(excelEpoch.getTime() + value * 86400 * 1000);
        return mysqlDate.toISOString().split('T')[0]; // 'YYYY-MM-DD'
    }

    if (/^\d{4}-\d{2}-\d{2}$/.test(value)) return value;

    const match = value.match(/^(\d{2})[-\/](\d{2})[-\/](\d{4})$/);
    if (match) {
        const [, dd, mm, yyyy] = match;
        const parsedDate = new Date(`${yyyy}-${mm}-${dd}`);
        if (isNaN(parsedDate)) {
            console.warn(`⚠️ Invalid date after parsing: ${value}`);
            return null;
        }
        return parsedDate.toISOString().split('T')[0];
    }

    return null;
};

const cleanAmount = (val) => {
    if (typeof val === 'string') {
        const cleaned = parseFloat(val.replace(/,/g, ''));
        return isNaN(cleaned) ? null : cleaned;
    }
    if (typeof val === 'number') return val;
    return null;
};

app.post('/api/importExcel', async (req, res) => {
    const { tableName, rows, created_by } = req.body;

    if (!tableName || !rows || !Array.isArray(rows)) {
        return res.status(400).json({ message: "Invalid request body" });
    }

    const allowedTables = [
        'KYC', 'Transaction', 'FD', 'STP_Switch', 'Non_Financial',
        'NSE_Pramesh', 'FFL_Transaction', 'FFL_STP_Switch',
        'FFL_Non_Financial', 'NSE_FFL', 'Realvalue'
    ];

    if (!allowedTables.includes(tableName)) {
        return res.status(400).json({ message: "Invalid table name" });
    }

    try {
        const [columnsResult] = await db.execute(`SHOW COLUMNS FROM \`${tableName}\``);
        const validColumns = columnsResult.map(col => col.Field);

        let successCount = 0;
        let skipped = [];

        for (const [index, row] of rows.entries()) {
            const data = { ...row, created_by };

            const mappedData = {};

            for (const key in data) {
                const originalKey = key === 'Cheqe_No' ? 'Cheque_No' : key;
                const matchedColumn = validColumns.find(col => col.toLowerCase() === originalKey.toLowerCase());

                if (matchedColumn) {
                    let value = data[key];

                    // Normalize date fields (ends with _Date or Start_Date, End_Date, etc.)
                    if (matchedColumn.toLowerCase().includes('date')) {
                        if (!value || value === '' || value === 'Showing') {
                            value = null;
                        } else {
                            value = excelDateToMySQLDate(value);
                        }
                    }

                    // Clean amount-like fields
                    if (['amount', 'rejected_amount'].includes(matchedColumn.toLowerCase())) {
                        value = cleanAmount(value);
                    }

                    mappedData[matchedColumn] = value;
                }
            }

            try {
                const columns = Object.keys(mappedData).map(col => `\`${col.trim()}\``).join(', ');
                const values = Object.values(mappedData);
                const placeholders = values.map(() => '?').join(', ');

                const query = `INSERT INTO \`${tableName}\` (${columns}) VALUES (${placeholders})`;
                await db.execute(query, values);
                successCount++;
            } catch (rowError) {
                console.warn(`⛔ Skipped row ${index + 1}:`, rowError.message, JSON.stringify(data, null, 2));
                skipped.push({ index: index + 1, reason: rowError.message });
            }
        }

        res.status(200).json({
            message: `✅ ${successCount} rows inserted successfully.`,
            skipped
        });

    } catch (error) {
        console.error("❌ MySQL Error:", error);
        res.status(500).json({ message: "Internal server error", error: error.message });
    }
});


const validateUserFromSession = (req, res, next) => {
    const email = req.headers['x-user-email'];
    const name = req.headers['x-user-name'];

    if (!email || !name) {
        return res.status(401).json({ error: 'User not identified. Please log in again.' });
    }

    req.user = { email, name };
    next();
};

app.post('/api/run-query', validateUserFromSession, async (req, res) => {
    let { query } = req.body;

    if (!query || typeof query !== 'string') {
        return res.status(400).json({ error: 'Query is required' });
    }

    const originalQuery = query;
    // const lowerQuery = query.trim().toLowerCase();

    //  Only allow SELECT queries
    if (!/^\s*select\b/i.test(query)) {
        return res.status(403).json({ error: 'Only SELECT queries are allowed.' });
    }

    //  Prevent SQL injection via semicolon, comments, DDL/DML
    if (/--|\/\*|\*\/|;/i.test(query)) {
        return res.status(403).json({ error: 'SQL comments or multiple statements are not allowed.' });
    }

    if (/(drop|insert|delete|update|alter|create)\b/i.test(query)) {
        return res.status(403).json({ error: 'Unsafe SQL operations are blocked.' });
    }

    // ✅ Extract table and validate access
    const match = query.match(/from\s+([^\s;]+)/i);
    const tableName = match ? match[1].replace(/[`"]/g, '') : null;

    if (!tableName || !allowedTables.map(t => t.toLowerCase()).includes(tableName.toLowerCase())) {
        return res.status(403).json({ error: `Access to table "${tableName}" is not allowed.` });
    }

    // ✅ Automatically add is_deleted = 0 filter
    if (/select\s+\*\s+from\s+/i.test(query)) {
        const isAlreadyFiltered = /\bis_deleted\s*=\s*\d\b/i.test(query);
        const match = query.match(/select \* from\s+([^\s;]+)/i);

        if (match && !isAlreadyFiltered) {
            const tableName = match[1];
            const rest = query.replace(/select \* from\s+[^\s;]+/i, '');

            if (/where\s+/i.test(rest)) {
                query = `SELECT * FROM ${tableName} ${rest.replace(/where/i, 'WHERE')} AND is_deleted = 0`;
            } else {
                query = `SELECT * FROM ${tableName} WHERE is_deleted = 0${rest}`;
            }
        }
    }

    // ✅ Apply a limit if not already present
    if (!/limit\s+\d+/i.test(query)) {
        query += ' LIMIT 100';
    }

    try {
        // ✅ Log the executed query with user info
        await db.query(
            'INSERT INTO query_logs (query_text, user_email, endpoint) VALUES (?, ?, ?)',
            [originalQuery, req.user.email, '/api/run-query']
        );

        // ✅ Run the query securely with a timeout
        const [rows] = await db.query({ sql: query, timeout: 5000 });

        res.json({ rows });
    } catch (err) {
        console.error('Query execution error:', err);
        res.status(500).json({ error: 'Invalid query or internal server error' });
    }
});


// user login and logout route 

app.post('/login', async (req, res) => {

    // var plainPassword = "123456"
    // const saltRounds = 10; 
    // const hashedPassword = await bcrypt.hash(plainPassword, saltRounds);
    // console.log("//////////", hashedPassword);


    const { email, password } = req.body;

    const sqlInjectionPattern = /('|--|;|\/\*|\*\/)/i;
    if (
        typeof email !== 'string' ||
        typeof password !== 'string' ||
        sqlInjectionPattern.test(email) ||
        sqlInjectionPattern.test(password)
    ) {
        return res.status(400).json({ error: 'Invalid input format.' });
    }

    try {
        // 1. Fetch user
        const [users] = await db.query('SELECT * FROM users WHERE user_email = ?', [email]);
        if (users.length === 0) {
            return res.status(400).json({ error: 'User not found' });
        }

        const user = users[0];

        // 2. Validate password
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // 3. Check is_logged_in and send email if already logged in
        if (user.is_logged_in) {
            const deviceName = os.hostname();
            sendLoginAttemptEmail(user.user_email, deviceName); // 👈 send unauthorized login alert
            return res.status(403).json({ error: 'User is already logged in on another device' });
        }

        // 4. Mark as logged in
        await db.query('UPDATE users SET is_logged_in = 1, login_time = NOW(), logout_time = NULL, session_duration = NULL WHERE user_email = ?', [email]);


        // 5. Return success
        res.json({
            email: user.user_email,
            name: user.user_name
        });

    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/logout', express.json(), async (req, res) => {
    const { email } = req.body;
    console.log("🔒 Logging out user:", email);

    if (!email) {
        return res.status(400).json({ error: 'Email required for logout' });
    }

    try {
        // 1. Get the user's login time
        const [result] = await db.query('SELECT login_time FROM users WHERE user_email = ?', [email]);

        const loginTime = result[0]?.login_time;
        if (!loginTime) {
            return res.status(400).json({ error: 'Login time not found for this user' });
        }

        // 2. Update logout time and session duration
        await db.query(`
            UPDATE users
            SET 
                is_logged_in = 0,
                logout_time = NOW(),
                session_duration = TIMEDIFF(NOW(), login_time)
            WHERE user_email = ?
        `, [email]);

        res.json({ message: '✅ User logged out successfully with session duration stored.' });
    } catch (err) {
        console.error('❌ Logout error:', err);
        res.status(500).json({ error: 'Logout failed' });
    }
});



// === 📥 API: Get Table Data ===

app.get('/api/getTableData/:submodule', (req, res) => {
    if (!db) {
        return res.status(503).json({ error: 'Database not connected' });
    }

    const { submodule } = req.params;
    const allowedTables = ['KYC', 'Transaction', 'FD', 'STP_Switch', 'Non_Financial', 'NSE_Pramesh', 'FFL_Transaction', 'FFL_STP_Switch', 'FFL_Non_Financial', 'NSE_FFL', 'Realvalue'];

    if (!allowedTables.includes(submodule)) {
        return res.status(400).json({ error: 'Invalid table name' });
    }

    db.query(`SELECT * FROM \`${submodule}\` WHERE is_deleted = 0`)
        .then(([rows]) => {
            const formatted = rows.map(row => {
                const formattedRow = {};
                for (const key in row) {
                    if (row[key] instanceof Date) {
                        const localDate = new Date(row[key]);
                        formattedRow[key] = localDate.toLocaleDateString('en-CA');
                    } else {
                        formattedRow[key] = row[key];
                    }
                }
                return formattedRow;
            });

            res.status(200).json(formatted);
        })
        .catch((error) => {
            console.error(`Error fetching data from ${submodule}:`, error);
            res.status(500).json({ error: `Failed to fetch data from ${submodule}` });
        });
});

// === 📤 API: Save Table Data ===

// For New Row Entries 

app.post('/api/insertTableData', async (req, res) => {
    const { tableName, entries } = req.body;

    const allowedTables = [
        'KYC', 'Transaction', 'FD', 'STP_Switch', 'Non_Financial', 'Realvalue',
        'NSE_Pramesh', 'FFL_Transaction', 'FFL_STP_Switch', 'FFL_Non_Financial', 'NSE_FFL'
    ];

    if (!allowedTables.includes(tableName)) {
        return res.status(400).json({ error: 'Invalid table name' });
    }

    function normalizeDate(input) {
        if (!input) return input;
        if (typeof input === 'string') {
            const match = input.match(/^(\d{2})[-\/](\d{2})[-\/](\d{4})$/);
            if (match) {
                const [_, dd, mm, yyyy] = match;
                return `${yyyy}-${mm}-${dd}`;
            }
        }
        if (!isNaN(input) && Number(input) > 30000 && Number(input) < 60000) {
            const excelEpoch = new Date(Date.UTC(1899, 11, 30));
            const actualDate = new Date(excelEpoch.getTime() + (input * 86400000));
            return actualDate.toISOString().slice(0, 10);
        }
        return input;
    }

    try {
        let insertCount = 0;
        const insertedRows = [];

        for (const row of entries) {
            if ('id' in row) delete row.id;
            if ('created_at' in row) delete row.created_at;
            if ('updated_at' in row) delete row.updated_at;

            if (!('created_by' in row) || !row.created_by) {
                row.created_by = 'Unknown';
            }

            for (const key in row) {
                if (key.toLowerCase().includes('date') && row[key]) {
                    row[key] = normalizeDate(row[key]);
                }
            }

            const onlyDatesFilled = Object.entries(row).every(([key, val]) => {
                if (key === 'Received_Date' || key === 'Proceed_Date') return true;
                if (['Amount', 'Re_Amount', 'Total_Amount', 'Installment', 'No_of_Installment', 'Rejected_Amount'].includes(key)) {
                    return val === '0' || val === 0;
                }
                return !val || val === '' || val === null;
            });

            if (onlyDatesFilled) {
                console.log(`⛔ Skipped insert for blank row with only date fields.`);
                continue;
            }

            // Add timestamps manually
            row.created_at = new Date();
            row.updated_at = new Date();

            const fields = Object.keys(row);
            const values = fields.map(f => {
                const val = row[f];
                if (typeof val === 'string' && val.trim() === '') {
                    if (f.toLowerCase().includes("date")) return null;
                }
                return val;
            });

            const escapedFields = fields.map(f => `\`${f}\``).join(', ');
            const placeholders = fields.map(() => '?').join(', ');
            const sql = `INSERT INTO \`${tableName}\` (${escapedFields}) VALUES (${placeholders})`;

            const [result] = await db.query(sql, values);
            insertCount++;
            insertedRows.push({ ...row, id: result.insertId });
        }

        io.emit('rowInserted', { tableName, rows: insertedRows });

        res.json({ success: true, inserted: insertCount });
    } catch (err) {
        console.error("Insert Error:", err);
        res.status(500).json({ success: false, message: "Insert failed" });
    }
});


// For Existing Row but Modified Entries 

app.put('/api/updateTableData', async (req, res) => {
    const { tableName, entries } = req.body;

    const allowedTables = [
        'KYC', 'Transaction', 'FD', 'STP_Switch', 'Non_Financial', 'Realvalue',
        'NSE_Pramesh', 'FFL_Transaction', 'FFL_STP_Switch', 'FFL_Non_Financial', 'NSE_FFL'
    ];

    if (!allowedTables.includes(tableName)) {
        return res.status(400).json({ error: 'Invalid table name' });
    }

    const numericFields = [
        'Amount', 'Total_Amount', 'Installment', 'No_of_Installment', 'Re_Amount', 'Rejected_Amount', 'NAV'
    ];

    try {
        const updatedRows = [];

        for (const row of entries) {
            const id = row.id;
            if (!id) continue;

            numericFields.forEach(field => {
                if (row[field] === '') {
                    row[field] = 0;
                }
            });

            if (!('modified_by' in row) || !row.modified_by) {
                row.modified_by = 'Unknown';
            }

            // Manually update timestamp
            row.updated_at = new Date();

            const fields = Object.keys(row).filter(f => f !== 'id');
            const updates = fields.map(f => `\`${f}\` = ?`).join(', ');
            const values = fields.map(f => row[f]);
            values.push(id);

            const sql = `UPDATE \`${tableName}\` SET ${updates} WHERE id = ?`;
            await db.query(sql, values);
            updatedRows.push(row);
        }

        io.emit('rowUpdated', { tableName, rows: updatedRows });

        res.json({ success: true, updated: updatedRows.length });
    } catch (err) {
        console.error("Update Error:", err);
        res.status(500).json({ success: false, message: "Update failed" });
    }
});




// for deleting the row 
app.delete('/api/deleteRows', async (req, res) => {
    const { tableName, ids, deleted_by } = req.body;

    if (!tableName || !Array.isArray(ids) || ids.length === 0) {
        return res.status(400).json({ message: "Invalid request" });
    }

    try {
        const placeholders = ids.map(() => '?').join(',');
        const query = `
            UPDATE \`${tableName}\`
            SET is_deleted = 1, deleted_by = ?, deleted_date = NOW()
            WHERE id IN (${placeholders})
        `;
        const params = [deleted_by, ...ids];

        const [result] = await db.query(query, params);

        io.emit('rowDeleted', { tableName, ids });
        res.json({ message: "Rows marked as deleted", affectedRows: result.affectedRows });
    } catch (err) {
        console.error("Delete error:", err);
        res.status(500).json({ message: "Failed to mark rows as deleted" });
    }
});


// for deleting all selected rows 

app.delete('/api/deleteSelectedRows', async (req, res) => {
    const { tableName, ids, deleted_by } = req.body;

    if (!tableName || !Array.isArray(ids) || ids.length === 0) {
        return res.status(400).json({ message: "Invalid table name or IDs" });
    }

    try {
        const placeholders = ids.map(() => '?').join(',');
        const query = `
            UPDATE \`${tableName}\`
            SET is_deleted = 1, deleted_by = ?, deleted_date = NOW()
            WHERE id IN (${placeholders})
        `;
        const params = [deleted_by, ...ids];

        const [result] = await db.query(query, params);

        io.emit('rowDeleted', { tableName, ids });
        res.json({ message: "Rows marked as deleted", affectedRows: result.affectedRows });
    } catch (err) {
        console.error("SQL update error:", err);
        res.status(500).json({ message: "Server error while marking rows as deleted." });
    }
});


// to get all logged Queries

app.get('/api/query-logs', async (req, res) => {
    try {
        const [logs] = await db.query(
            'SELECT user_email, endpoint, query_text, request_time FROM Query_Logs ORDER BY request_time DESC LIMIT 100'
        );
        res.json({ logs });
    } catch (err) {
        console.error('Error fetching query logs:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});



// GET /api/columns
app.post('/api/run-query', async (req, res) => {
    let { query } = req.body;

    if (!query || typeof query !== 'string') {
        return res.status(400).json({ error: 'Query is required' });
    }

    const lowerQuery = query.trim().toLowerCase();

    // ❌ Restrict access to the 'users' table (case insensitive, spaces handled)
    if (/\bfrom\s+users\b/.test(lowerQuery) || /\bjoin\s+users\b/.test(lowerQuery)) {
        return res.status(403).json({ error: 'Access to the "users" table is restricted.' });
    }

    // ❌ Allow only SELECT queries
    if (!lowerQuery.startsWith('select')) {
        return res.status(403).json({ error: 'Only SELECT queries are allowed.' });
    }

    // ✅ Automatically filter for "is_deleted = 0" in SELECT * queries
    if (lowerQuery.startsWith('select * from')) {
        const match = query.match(/select \* from\s+([^\s;]+)(.*)/i);
        if (match) {
            const tableName = match[1];
            const rest = match[2] || '';

            if (/where\s/i.test(rest)) {
                // WHERE already exists → add AND is_deleted = 0
                query = `SELECT * FROM ${tableName} ${rest.replace(/where/i, 'WHERE')} AND is_deleted = 0`;
            } else {
                // No WHERE clause
                query = `SELECT * FROM ${tableName} WHERE is_deleted = 0${rest}`;
            }
        }
    }

    try {
        const [rows] = await db.query(query);
        res.json({ rows });
    } catch (err) {
        console.error('Query execution error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});




const emailToRMMap = {
    'vishalvaidya@gmail.com': 'Vishal Vaidya',
    'arpitaparmar@gmail.com': 'Arpita Parmar',
    // Add more mappings as needed
};

const unrestricted_adminEmails = ['admin@gmail.com', 'praharshpatni@gmail.com', 'divya@gmail.com'];

app.post('/api/chart-data', async (req, res) => {
    const { fromDate, duration } = req.body;
    const userEmail = req.headers['email'];

    if (!userEmail) {
        return res.status(400).json({ error: 'Missing user email' });
    }

    const from = new Date(fromDate);
    const to = new Date(from);
    to.setMonth(to.getMonth() + parseInt(duration));

    if (isNaN(from.getTime()) || isNaN(to.getTime())) {
        return res.status(400).json({ error: 'Invalid date range' });
    }

    try {
        const fromStr = from.toISOString().split('T')[0];
        const toStr = to.toISOString().split('T')[0];

        let whereClause = `Received_Date BETWEEN ? AND ? AND is_deleted = 0`;
        const params = [fromStr, toStr];

        if (!unrestricted_adminEmails.includes(userEmail)) {
            const rmName = emailToRMMap[userEmail];

            if (!rmName) {
                return res.status(403).json({ error: 'Access denied: RM not recognized' });
            }

            whereClause += ` AND RM = ?`;
            params.push(rmName);
        }

        const queries = {
            newSIP: `SELECT SUM(Amount) as total FROM transaction WHERE Transaction_Type = 'SIP' AND SIP_Type = 'New' AND ${whereClause}`,
            reSIP: `SELECT SUM(Amount) as total FROM transaction WHERE Transaction_Type = 'Re_SIP' AND SIP_Type = 'Existing' AND ${whereClause}`,
            lumpsum: `SELECT SUM(Amount) as total FROM transaction WHERE Transaction_Type = 'Lumpsum' AND ${whereClause}`,
            additional: `SELECT SUM(Amount) as total FROM transaction WHERE Transaction_Type = 'Additional' AND ${whereClause}`,
            redemption: `SELECT SUM(Amount) as total FROM transaction WHERE Transaction_Type = 'Redemption' AND ${whereClause}`
        };

        const [sipNew] = await db.query(queries.newSIP, params);
        const [reSIP] = await db.query(queries.reSIP, params);
        const [lumpsum] = await db.query(queries.lumpsum, params);
        const [additional] = await db.query(queries.additional, params);
        const [redemption] = await db.query(queries.redemption, params);

        const amounts = {
            newSIP: Number(sipNew[0].total || 0),
            reSIP: Number(reSIP[0].total || 0),
            lumpsum: Number(lumpsum[0].total || 0),
            additional: Number(additional[0].total || 0),
            redemption: Number(redemption[0].total || 0)
        };

        const totalInvestments = amounts.newSIP + amounts.reSIP + amounts.lumpsum + amounts.additional;
        const netAmount = totalInvestments - amounts.redemption;

        const chart = {
            labels: ['New SIP', 'Re-SIP', 'Lumpsum', 'Additional', 'Redemption'],
            datasets: [{
                label: `Investment Distribution (${fromStr} to ${toStr})`,
                data: [
                    amounts.newSIP,
                    amounts.reSIP,
                    amounts.lumpsum,
                    amounts.additional,
                    amounts.redemption
                ],
                backgroundColor: ['#3f51b5', '#ff9800', '#4caf50', '#f44336', '#9c27b0']
            }]
        };

        res.json({ chart, amounts: { ...amounts, netAmount } });
    } catch (err) {
        console.error('Chart error:', err);
        res.status(500).json({ error: 'Failed to fetch chart data' });
    }
});


// Get the earliest received date for SIP or Lumpsum
app.get('/api/chart-start-date', async (req, res) => {
    // console.log("✅ /api/chart-start-date HIT");

    try {
        const [rows] = await db.query(`
            SELECT MIN(Received_Date) as startDate
            FROM transaction
            WHERE is_deleted = 0
        `);

        const startDate = rows[0]?.startDate;

        if (!startDate) {
            return res.status(404).json({ error: 'No transactions found' });
        }
        // console.log("start date", startDate)

        res.json({ startDate });
    } catch (err) {
        console.error('Start date fetch error:', err);
        res.status(500).json({ error: 'Failed to fetch start date' });
    }
});


app.get('/api/chart-overview', async (req, res) => {
    try {
        const userEmail = req.headers['email']; // Assumes email is passed in headers from frontend

        if (!userEmail) {
            return res.status(400).json({ error: 'Missing user email' });
        }

        let queryCondition = "is_deleted = 0";

        if (!unrestricted_adminEmails.includes(userEmail)) {
            const rmName = emailToRMMap[userEmail];

            if (!rmName) {
                return res.status(403).json({ error: 'Access denied: RM not recognized' });
            }

            queryCondition += ` AND RM = '${rmName}'`;
        }

        const [sipNew] = await db.query(`
            SELECT SUM(Amount) as total FROM transaction 
            WHERE Transaction_Type = 'SIP' AND SIP_Type = 'New' AND ${queryCondition}
        `);
        const [reSIP] = await db.query(`
            SELECT SUM(Amount) as total FROM transaction 
            WHERE Transaction_Type = 'Re_SIP' AND SIP_Type = 'Existing' AND ${queryCondition}
        `);
        const [lumpsum] = await db.query(`
            SELECT SUM(Amount) as total FROM transaction 
            WHERE Transaction_Type = 'Lumpsum' AND ${queryCondition}
        `);
        const [additional] = await db.query(`
            SELECT SUM(Amount) as total FROM transaction 
            WHERE Transaction_Type = 'Additional' AND ${queryCondition}
        `);
        const [redemption] = await db.query(`
            SELECT SUM(Amount) as total FROM transaction 
            WHERE Transaction_Type = 'Redemption' AND ${queryCondition}
        `);

        const amounts = {
            newSIP: Number(sipNew[0].total || 0),
            reSIP: Number(reSIP[0].total || 0),
            lumpsum: Number(lumpsum[0].total || 0),
            additional: Number(additional[0].total || 0),
            redemption: Number(redemption[0].total || 0)
        };

        // console.log(amounts.reSIP);
        const totalInvestments = amounts.newSIP + amounts.reSIP + amounts.lumpsum + amounts.additional;
        const netAmount = totalInvestments - amounts.redemption;

        const chart = {
            labels: ['New SIP', 'Re-SIP', 'Lumpsum', 'Additional', 'Redemption'],
            datasets: [{
                label: 'Investment Overview (All Time)',
                data: [
                    amounts.newSIP,
                    amounts.reSIP,
                    amounts.lumpsum,
                    amounts.additional,
                    amounts.redemption
                ],
                backgroundColor: ['#3f51b5', '#ff9800', '#4caf50', '#f44336', '#9c27b0']
            }]
        };

        res.json({ chart, amounts: { ...amounts, netAmount } });
    } catch (err) {
        console.error("Overview chart error:", err);
        res.status(500).json({ error: "Failed to generate overview chart" });
    }
});

// UPDATED /api/client-stats TO INCLUDE RAW DATA

app.post('/api/client-stats', async (req, res) => {
    const { month } = req.body;

    try {
        const startDate = new Date(`${month}-01`);
        const endDate = new Date();

        const [rows] = await db.query(
            `SELECT Client_Type, COUNT(*) as count
             FROM transaction
             WHERE Received_Date BETWEEN ? AND ? AND is_deleted = 0 AND Client_Type != ''
             GROUP BY Client_Type`,
            [startDate, endDate]
        );

        const chart = {
            labels: rows.map(r => r.Client_Type),
            datasets: [
                {
                    label: 'Clients',
                    data: rows.map(r => r.count),
                    backgroundColor: rows.map((_, i) => ['#4caf50', '#f44336', '#2196f3', '#ff9800'][i % 4])
                }
            ]
        };

        res.json({ chart, rawData: rows });
    } catch (err) {
        console.error('Client stats error:', err);
        res.status(500).json({ error: 'Failed to fetch client stats' });
    }
});



app.post('/api/client-stats', async (req, res) => {
    const { month } = req.body;

    if (!month) return res.status(400).json({ error: "Month is required" });

    try {
        const startDate = new Date(`${month}-01`);
        const endDate = new Date();

        const [rows] = await db.query(
            `SELECT Client_Type, COUNT(*) as count
             FROM transaction
             WHERE Received_Date BETWEEN ? AND ? AND is_deleted = 0
             GROUP BY Client_Type`,
            [startDate, endDate]
        );

        const chart = {
            labels: rows.map(r => r.Client_Type),
            datasets: [{
                label: 'Clients',
                data: rows.map(r => r.count),
                backgroundColor: rows.map((_, i) => ['#4caf50', '#f44336', '#2196f3', '#ff9800'][i % 4])
            }]
        };

        res.json({ chart, rawData: rows }); // 🔧 include rawData
    } catch (err) {
        console.error('Client stats error:', err);
        res.status(500).json({ error: 'Failed to fetch client stats' });
    }
});



// for counting commision route 
app.get('/api/distinct-approach-by', async (req, res) => {
    try {
        const [prameshRows] = await db.query(
            `SELECT DISTINCT LOWER(TRIM(Approach_By)) AS name 
             FROM transaction 
             WHERE is_deleted = 0 AND Approach_By IS NOT NULL`
        );

        const [fflRows] = await db.query(
            `SELECT DISTINCT LOWER(TRIM(Approach_By)) AS name 
             FROM ffl_transaction 
             WHERE is_deleted = 0 AND Approach_By IS NOT NULL`
        );

        const uniquePramesh = [...new Set(prameshRows.map(r => r.name))];
        const uniqueFfl = [...new Set(fflRows.map(r => r.name))];

        // console.log("Distinct values from server (normalized):", uniquePramesh);

        res.json({
            pramesh: uniquePramesh,
            ffl: uniqueFfl,
        });

    } catch (err) {
        console.error('Error fetching distinct names:', err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});



app.post('/api/calculate-commission', async (req, res) => {
    const { approach_by, fromDate, duration, table, transactionType } = req.body;
    // console.log("Transaction type", transactionType)

    if (!approach_by || !fromDate || !duration || !table) {
        return res.status(400).json({ error: 'Missing fields' });
    }

    try {
        const from = new Date(fromDate);
        const to = new Date(from);
        to.setMonth(to.getMonth() + parseInt(duration));

        const fromStr = from.toISOString().split('T')[0];
        const toStr = to.toISOString().split('T')[0];

        const [rows] = await db.query(
            `SELECT 
        RM, 
        DATE_FORMAT(Received_Date, '%d-%m-%Y') as Date, 
        Client_Name, 
        Transaction_Type, 
        Scheme, 
        Amount
     FROM ?? 
     WHERE is_deleted = 0 
     AND Approach_By = ? 
     AND Received_Date BETWEEN ? AND ? 
     AND Transaction_Type = ?
     AND TR_status = 'success'`,
            [table, approach_by, fromStr, toStr, transactionType]
        );

        const [totalRes] = await db.query(
            `SELECT SUM(Amount) as total FROM ?? 
     WHERE is_deleted = 0 
     AND Approach_By = ? 
     AND Received_Date BETWEEN ? AND ? 
     AND Transaction_Type = ?
     AND TR_status = 'success'`,
            [table, approach_by, fromStr, toStr, transactionType]
        );


        const total = Number(totalRes[0].total || 0);

        res.json({ total, rows });
    } catch (err) {
        console.error('Error calculating commission:', err);
        res.status(500).json({ error: 'Failed to calculate commission' });
    }
});




// === 🚀 Start Server ===
const PORT = process.env.PORT || 4000;
server.listen(PORT, () => {
    console.log(`🚀 Server running on ${PORT}`);
});
