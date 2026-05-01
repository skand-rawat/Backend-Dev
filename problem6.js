const express = require('express');
const bcrypt = require('bcrypt');
const app = express();
app.use(express.json());
const users = [];
const loginAttempts = new Map(); // email -> { count, lockUntil }

// TODO: Implement check login attempts
function checkLoginAttempts(email) {
    const attempt = loginAttempts.get(email);
    if (!attempt) return true;
    if (attempt.lockUntil && Date.now() < attempt.lockUntil) {
        return false;
    }
    return attempt.count < 5;
}

// TODO: Implement record failed attempt
function recordFailedAttempt(email) {
    const attempt = loginAttempts.get(email) || { count: 0 };
    attempt.count += 1;
    if (attempt.count >= 5) {
        attempt.lockUntil = Date.now() + 30 * 60 * 1000; // 30 min
    }
    loginAttempts.set(email, attempt);
}

// TODO: Implement clear attempts
function clearAttempts(email) {
    loginAttempts.delete(email);
}

// TODO: Implement login with rate limiting
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    if (!checkLoginAttempts(email)) {
        return res.status(429).json({ error: 'Account locked due to too many failed attempts' });
    }
    const user = users.find(u => u.email === email);
    if (!user || !(await bcrypt.compare(password, user.password))) {
        recordFailedAttempt(email);
        return res.status(401).json({ error: 'Invalid credentials' });
    }
    clearAttempts(email);
    res.json({ message: 'Logged in', user: { id: user.id, email: user.email } });
});

app.listen(3000, () => console.log('Server running on port 3000'));