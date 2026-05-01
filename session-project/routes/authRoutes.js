const express = require("express");
const router = express.Router();

// Step 1
router.post("/step1", (req, res) => {
  req.session.user = { ...req.body };
  res.send("Step 1 saved");
});

// Step 2
router.post("/step2", (req, res) => {
  req.session.user = { ...req.session.user, ...req.body };
  res.send("Step 2 saved");
});

// Final submit
router.get("/submit", (req, res) => {
  res.json(req.session.user);
});

module.exports = router;
