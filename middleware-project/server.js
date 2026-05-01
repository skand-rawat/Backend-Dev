const express = require("express");
const mongoose = require("mongoose");
const dotenv = require("dotenv");

// Middlewares
const requestLogger = require("./middleware/requestLogger");
const sanitize = require("./middleware/sanitize");

const app = express();
dotenv.config();

app.use(express.json());
app.use(requestLogger);
app.use(sanitize);

mongoose.connect(process.env.MONGO_URI)
  .then(()=>console.log("MongoDB Connected"))
  .catch(err=>console.log(err));

app.get("/", (req,res)=>{
  res.send("Server Running");
});

app.listen(5000, ()=>console.log("Server started"));
