const fs = require("fs");

module.exports = (req, res, next) => {
  const start = Date.now();

  res.on("finish", () => {
    const log = ;
    fs.appendFileSync("logs/requests.log", log);
  });

  next();
};
