const express = require("express");
const { v4: uuidv4 } = require("uuid");
const router = express.Router();

// Anonymous or logged user
router.use((req, res, next) => {
  if (!req.session.cartId) {
    req.session.cartId = uuidv4();
  }
  next();
});

router.post("/add", (req, res) => {
  if (!req.session.cart) req.session.cart = [];
  req.session.cart.push(req.body);
  res.send("Item added");
});

router.get("/", (req, res) => {
  res.json(req.session.cart || []);
});

module.exports = router;
