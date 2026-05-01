const express = require('express');
const session = require('express-session');
const app = express();
app.use(express.json());

app.use(session({
    secret: 'cart-secret',
    resave: false,
    saveUninitialized: false
}));

// TODO: Initialize cart middleware
const initCart = (req, res, next) => {
    req.session.cart = req.session.cart || [];
    next();
};

// TODO: Implement cart operations
app.post('/cart/add', initCart, (req, res) => {
    const { productId, quantity = 1, price } = req.body;
    if (!productId || !price) {
        return res.status(400).json({ error: 'productId and price required' });
    }
    const cart = req.session.cart;
    const item = cart.find(i => i.productId === productId);
    if (item) {
        item.quantity += quantity;
    } else {
        cart.push({ productId, quantity, price });
    }
    res.json({ message: 'Item added', cart });
});

app.put('/cart/update/:productId', initCart, (req, res) => {
    const { productId } = req.params;
    const { quantity } = req.body;
    if (quantity <= 0) {
        return res.status(400).json({ error: 'Quantity must be positive' });
    }
    const cart = req.session.cart;
    const item = cart.find(i => i.productId === productId);
    if (!item) {
        return res.status(404).json({ error: 'Item not in cart' });
    }
    item.quantity = quantity;
    res.json({ message: 'Item updated', cart });
});

app.delete('/cart/remove/:productId', initCart, (req, res) => {
    const { productId } = req.params;
    const cart = req.session.cart;
    const index = cart.findIndex(i => i.productId === productId);
    if (index === -1) {
        return res.status(404).json({ error: 'Item not in cart' });
    }
    cart.splice(index, 1);
    res.json({ message: 'Item removed', cart });
});

app.get('/cart', initCart, (req, res) => {
    const cart = req.session.cart;
    const total = cart.reduce((sum, item) => sum + item.quantity * item.price, 0);
    res.json({ cart, total });
});

app.delete('/cart', initCart, (req, res) => {
    req.session.cart = [];
    res.json({ message: 'Cart cleared' });
});

app.listen(3000, () => console.log('Server running on port 3000'));