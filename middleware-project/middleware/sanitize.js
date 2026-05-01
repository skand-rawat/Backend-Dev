const xss = require("xss-clean");
const { body, validationResult } = require("express-validator");

module.exports = [
  xss(),
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    next();
  }
];
