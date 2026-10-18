const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

const JWT_SECRET = 'super-secret-key-change-me';
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const db = new sqlite3.Database('./messenger.db');
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY AUTOINCREMENT, sender_id INTEGER, receiver_id INTEGER, text TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)`);
});

app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Заполните все поля' });
    try {
        const hash = await bcrypt.hash(password, 10);
        db.run(`INSERT INTO users (username, password) VALUES (?, ?)`, [username, hash], function(err) {
            if (err) return res.status(400).json({ error: 'Имя уже занято' });
            const token = jwt.sign({ id: this.lastID, username }, JWT_SECRET);
            res.json({ token, username });
        });
    } catch (e) { res.status(500).json({ error: 'Ошибка сервера' }); }
});

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
        if (err || !user) return res.status(400).json({ error: 'Неверный логин или пароль' });
        const valid = await bcrypt.compare(password, user.password);
        if (!valid) return res.status(400).json({ error: 'Неверный логин или пароль' });
        const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET);
        res.json({ token, username: user.username });
    });
});

const onlineUsers = new Map(); // userId -> socket.id

io.use((socket, next) => {
    const token = socket.handshake.auth.token;
    if (!token) return next(new Error('Нет токена'));
    try {
        socket.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch (e) { next(new Error('Неверный токен')); }
});

io.on('connection', (socket) => {
    const user = socket.user;
    onlineUsers.set(user.id, socket.id);

    db.all(`SELECT id, username FROM users WHERE id != ?`, [user.id], (err, rows) => {
        if (!err) socket.emit('user-list', rows);
    });
    io.emit('online-status', Array.from(onlineUsers.keys()));

    socket.on('get-history', ({ withUserId }) => {
        db.all(`SELECT * FROM messages WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?) ORDER BY timestamp ASC`,
            [user.id, withUserId, withUserId, user.id],
            (err, rows) => { if (!err) socket.emit('history', { withUserId, messages: rows }); });
    });

    socket.on('send-message', ({ to, text }) => {
        if (!text.trim()) return;
        db.run(`INSERT INTO messages (sender_id, receiver_id, text) VALUES (?, ?, ?)`, [user.id, to, text], function(err) {
            if (err) return;
            const msgData = { id: this.lastID, sender_id: user.id, sender_name: user.username, receiver_id: to, text: text, timestamp: new Date().toISOString() };
            const targetSocket = onlineUsers.get(to);
            if (targetSocket) io.to(targetSocket).emit('new-message', msgData);
            socket.emit('message-sent', msgData);
        });
    });

    // Статус "печатает..."
    socket.on('typing', ({ to, isTyping }) => {
        const targetSocket = onlineUsers.get(to);
        if (targetSocket) io.to(targetSocket).emit('typing', { from: user.id, isTyping });
    });

    // --- ЗВОНКИ ---
    socket.on('call-request', ({ to, offer }) => {
        const targetSocket = onlineUsers.get(to);
        if (targetSocket) io.to(targetSocket).emit('incoming-call', { from: user.id, fromName: user.username, offer });
    });

    socket.on('call-answer', ({ to, answer }) => {
        const targetSocket = onlineUsers.get(to);
        if (targetSocket) io.to(targetSocket).emit('call-answered', { answer });
    });

    socket.on('ice-candidate', ({ to, candidate }) => {
        const targetSocket = onlineUsers.get(to);
        if (targetSocket) io.to(targetSocket).emit('ice-candidate', { candidate });
    });

    socket.on('end-call', ({ to }) => {
        const targetSocket = onlineUsers.get(to);
        if (targetSocket) io.to(targetSocket).emit('call-ended');
        if (to === user.id) socket.emit('call-ended');
    });

    socket.on('disconnect', () => {
        onlineUsers.delete(user.id);
        io.emit('online-status', Array.from(onlineUsers.keys()));
    });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Сервер: http://localhost:${PORT}`));