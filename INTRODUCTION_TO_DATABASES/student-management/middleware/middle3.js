const express = require("express");
const app = express();

//Built-in Middleware
app.use(express.json());

//Logger Middleware used Globally 
const logger = (req,res,next)=>{
    console.log("Method",req.method);
    console.log("URL",req.url);
    next();
};

//Apply Globally
app.use(logger);

//Validation Middleware
const validate =(req,res,next)=>{
    const {name}=req.body;
    if(!name){
        return res.status(400).json({msg:"Name is required",});
    }
    next();
};

//Route-Specific Middleware
const checkAdmin = (req,res,next)=>{
    //Dummy Check(JWT)
    const isAdmin=false;
    if(!isAdmin){
        return res.status(403).json({msg:"Access Denied",});
    }
    next();
};


//Home Route
app.get("/",(req,res)=>{
    res.send("Welcome to home page");
});

//Validation middleware Route
app.post("/user",validate,(req,res)=>{
    res.json({msg:"user created seccessfull", data:req.body,});
});

//Route-specific middleware route
app.get("/admin",checkAdmin,(req,res)=>{
    res.send("Welome admin");
});

app.listen(8080,()=>console.log("Sever Started"));