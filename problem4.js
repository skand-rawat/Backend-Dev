const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const app = express();
app.use(express.json());
const ACCESS_SECRET = 'access-secret';
const REFRESH_SECRET = 'refresh-secret';
const users = [];
const refreshTokens = new Set();

// TODO: Generate access token
function generateAccessToken(user) {
    return jwt.sign({ id: user.id, username: user.username }, ACCESS_SECRET, { expiresIn: '15m' });
}

// TODO: Generate refresh token
function generateRefreshToken(user) {
    return jwt.sign({ id: user.id }, REFRESH_SECRET, { expiresIn: '7d' });
}

// TODO: Implement login
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username);
    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(401).json({ error: 'Invalid credentials' });
    }
    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);
    refreshTokens.add(refreshToken);
    res.json({ accessToken, refreshToken });
});

// TODO: Implement token refresh
app.post('/token/refresh', (req, res) => {
    const { refreshToken } = req.body;
    if (!refreshToken || !refreshTokens.has(refreshToken)) {
        return res.status(403).json({ error: 'Invalid refresh token' });
    }
    jwt.verify(refreshToken, REFRESH_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid token' });
        const accessToken = generateAccessToken({ id: user.id, username: user.username });
        res.json({ accessToken });
    });
});

// TODO: Implement logout
app.post('/logout', (req, res) => {
    const { refreshToken } = req.body;
    refreshTokens.delete(refreshToken);
    res.json({ message: 'Logged out' });
});

// TODO: Implement protected route
app.get('/protected', (req, res) => {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'No token' });
    jwt.verify(token, ACCESS_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid token' });
        res.json({ message: 'Protected content', user });
    });
});

app.listen(3000, () => console.log('Server running on port 3000'));