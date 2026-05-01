module.exports = (req, res, next) => {
  const timeLeft = req.session.cookie.maxAge;
  if (timeLeft < 60000) {
    console.log("Session about to expire");
  }
  next();
};
