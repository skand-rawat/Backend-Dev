const jwt = require("jsonwebtoken");

module.exports = (req, res, next) => {
  const token = req.headers["authorization"];
  const otp = req.headers["otp"];

  if (!token || !otp) {
    return res.status(401).json({ message: "Token & OTP required" });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    if (otp !== "123456") {
      return res.status(401).json({ message: "Invalid OTP" });
    }

    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ message: "Invalid Token" });
  }
};
