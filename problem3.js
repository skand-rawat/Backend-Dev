const express = require('express');
const session = require('express-session');
const app = express();
app.use(express.json());

app.use(session({
    secret: 'auth-secret',
    resave: false,
    saveUninitialized: false
}));
const users = [];
const posts = [];

// TODO: Implement authentication middleware
const isAuthenticated = (req, res, next) => {
    if (!req.session.user) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    next();
};

// TODO: Implement role-based authorization middleware
const requireRole = (role) => {
    return (req, res, next) => {
        if (!req.session.user) {
            return res.status(401).json({ error: 'Not authenticated' });
        }
        const roles = ['user', 'moderator', 'admin'];
        const userRoleIndex = roles.indexOf(req.session.user.role);
        const requiredIndex = roles.indexOf(role);
        if (userRoleIndex < requiredIndex) {
            return res.status(403).json({ error: 'Insufficient permissions' });
        }
        next();
    };
};

// TODO: Implement resource ownership check
const isOwnerOrModerator = (req, res, next) => {
    const post = posts.find(p => p.id == req.params.id);
    if (!post) {
        return res.status(404).json({ error: 'Post not found' });
    }
    if (req.session.user.id === post.author || req.session.user.role === 'moderator' || req.session.user.role === 'admin') {
        next();
    } else {
        res.status(403).json({ error: 'Not authorized' });
    }
};

// TODO: Implement routes
app.post('/posts', isAuthenticated, (req, res) => {
    const { title, content } = req.body;
    const post = { id: posts.length + 1, title, content, author: req.session.user.id };
    posts.push(post);
    res.status(201).json(post);
});

app.put('/posts/:id', isAuthenticated, isOwnerOrModerator, (req, res) => {
    const post = posts.find(p => p.id == req.params.id);
    const { title, content } = req.body;
    post.title = title;
    post.content = content;
    res.json(post);
});

app.delete('/posts/:id', isAuthenticated, requireRole('moderator'), (req, res) => {
    const index = posts.findIndex(p => p.id == req.params.id);
    if (index === -1) {
        return res.status(404).json({ error: 'Post not found' });
    }
    posts.splice(index, 1);
    res.json({ message: 'Post deleted' });
});

app.listen(3000, () => console.log('Server running on port 3000'));