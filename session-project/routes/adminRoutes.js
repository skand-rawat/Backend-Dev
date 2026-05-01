const express = require("express");
const router = express.Router();

const isAdmin = (req, res, next) => {
  if (req.session.user && req.session.user.role === "admin") {
    return next();
  }
  return res.status(403).send("Access denied");
};

router.get("/dashboard", isAdmin, (req, res) => {
  res.send("Welcome Admin");
});

module.exports = router;
