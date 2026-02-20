const express = require("express")

const app = express()

app.use(express.json())

// 👇 Static folder middleware (IMPORTANT)
app.use(express.static("public"))

app.get("/", (req, res) => {
    res.send("Welcome to Express Assignment")
})

app.get("/students", (req, res) => {
    res.json([
        { id: 1, name: "Yash", course: "NodeJS" },
        { id: 2, name: "Rahul", course: "Express" }
    ])
})

app.post("/students", (req, res) => {
    const newStudent = req.body
    res.json({
        message: "Student added successfully",
        student: newStudent
    })
})

app.listen(3000, () => {
    console.log("Server running on port 3000")
})
