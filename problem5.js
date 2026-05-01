const express = require('express');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const app = express();
app.use(express.json());
const users = [];

app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser((id, done) => {
    const user = users.find(u => u.id === id);
    done(null, user);
});

// TODO: Configure Local Strategy
passport.use('local', new LocalStrategy(
    async (username, password, done) => {
        const user = users.find(u => u.username === username);
        if (!user) return done(null, false, { message: 'User not found' });
        const isValid = await bcrypt.compare(password, user.password);
        if (!isValid) return done(null, false, { message: 'Invalid password' });
        return done(null, user);
    }
));

// TODO: Configure JWT Strategy
passport.use('jwt', new JwtStrategy({
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: 'jwt-secret'
}, (payload, done) => {
    const user = users.find(u => u.id === payload.id);
    if (user) return done(null, user);
    return done(null, false);
}));

// TODO: Implement login endpoint
app.post('/auth/login', passport.authenticate('local'), (req, res) => {
    res.json({ message: 'Logged in', user: req.user });
});

// TODO: Implement API login (returns JWT)
app.post('/auth/api-login', passport.authenticate('local', { session: false }), (req, res) => {
    const token = jwt.sign({ id: req.user.id }, 'jwt-secret');
    res.json({ token });
});

// TODO: Protected route with session auth
app.get('/dashboard', (req, res) => {
    if (!req.user) return res.status(401).json({ error: 'Not logged in' });
    res.json({ message: 'Dashboard', user: req.user });
});

// TODO: Protected route with JWT auth
app.get('/api/profile', passport.authenticate('jwt', { session: false }), (req, res) => {
    res.json({ profile: req.user });
});

app.listen(3000, () => console.log('Server running on port 3000'));