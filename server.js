const express = require('express');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

// In-memory users
const users = [
	{ id: 1, username: 'user1', password: 'pass1' }
];

// JWT secret
const JWT_SECRET = 'super_secret_jwt_key_change_me';

// POST /login
app.post('/login', (req, res) => {
	const { username, password } = req.body || {};
	if (!username || !password) {
		return res.status(400).json({ error: 'Username and password required' });
	}

	const user = users.find(u => u.username === username && u.password === password);
	if (!user) {
		return res.status(401).json({ error: 'Invalid credentials' });
	}

	const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '1h' });
	return res.json({ token });
});

// Authentication middleware
function authMiddleware(req, res, next) {
	const authHeader = req.headers.authorization;
	if (!authHeader) {
		return res.status(401).json({ error: 'Authorization header missing' });
	}

	const parts = authHeader.split(' ');
	if (parts.length !== 2 || parts[0] !== 'Bearer') {
		return res.status(401).json({ error: 'Invalid Authorization header format' });
	}

	const token = parts[1];
	try {
		const payload = jwt.verify(token, JWT_SECRET);
		req.user = { userId: payload.userId };
		return next();
	} catch (err) {
		return res.status(401).json({ error: 'Invalid or expired token' });
	}
}

// Protected route
app.get('/profile', authMiddleware, (req, res) => {
	return res.json({ message: 'Authenticated', userId: req.user.userId });
});

// Health route
app.get('/health', (req, res) => {
	res.json({ status: 'ok' });
});

// Start server
const PORT = 3000;
app.listen(PORT, () => {
	console.log(`Server running on http://localhost:${PORT}`);
});
