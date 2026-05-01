const express = require("express");
const session = require("express-session");
const cookieParser = require("cookie-parser");
const dotenv = require("dotenv");

const app = express();
dotenv.config();

app.use(express.json());
app.use(cookieParser());

app.use(session({
  secret: "secret123",
  resave: false,
  saveUninitialized: true,
  cookie: { maxAge: 600000 } // 10 min
}));

// Routes
app.use("/auth", require("./routes/authRoutes"));
app.use("/admin", require("./routes/adminRoutes"));
app.use("/cart", require("./routes/cartRoutes"));

app.get("/", (req, res) => {
  res.send("Session Project Running");
});

app.listen(5000, () => console.log("Server running on port 5000"));
