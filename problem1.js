const express = require('express');
const bcrypt = require('bcrypt');
const app = express();
app.use(express.json());
const users = [];

// TODO: Implement password validation function
function validatePassword(password) {
    if (password.length < 8) return false;
    const hasUpper = /[A-Z]/.test(password);
    const hasLower = /[a-z]/.test(password);
    const hasNumber = /\d/.test(password);
    const hasSpecial = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password);
    return hasUpper && hasLower && hasNumber && hasSpecial;
}

// TODO: Implement registration endpoint
app.post('/register', async (req, res) => {
    const { username, email, password } = req.body;
    if (!username || !email || !password) {
        return res.status(400).json({ error: 'Username, email, and password are required' });
    }
    if (!validatePassword(password)) {
        return res.status(400).json({ error: 'Password must be at least 8 characters and contain uppercase, lowercase, number, and special character' });
    }
    const existingUser = users.find(u => u.email === email);
    if (existingUser) {
        return res.status(409).json({ error: 'User with this email already exists' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = { id: users.length + 1, username, email, password: hashedPassword };
    users.push(user);
    res.status(201).json({ message: 'User registered successfully', user: { id: user.id, username, email } });
});

app.listen(3000, () => console.log('Server running on port 3000'));