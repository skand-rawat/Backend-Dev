module.exports = (req, res, next) => {
  const lang = req.cookies.lang || "en";
  req.lang = lang;
  next();
};
