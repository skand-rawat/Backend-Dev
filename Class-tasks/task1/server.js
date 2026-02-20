const express = require("express")
const app = express()

app.use(express.json())

// =========================
// In-memory Users Array
// =========================
let users = []

// =========================
// Logger Middleware
// =========================
app.use((req, res, next) => {
    console.log(`${req.method} ${req.url}`)
    next()
})

// =========================
// Validation Middleware
// =========================
function validateUser(req, res, next) {
    const { name, email, role } = req.body

    if (!name || !email || !role) {
        return res.status(400).json({
            message: "Name, email and role are required"
        })
    }

    next()
}

// =========================
// ROUTES
// =========================

// GET all users
app.get("/users", (req, res) => {
    res.json(users)
})

// GET user by ID
app.get("/users/:id", (req, res) => {
    const id = parseInt(req.params.id)
    const user = users.find(u => u.id === id)

    if (!user) {
        return res.status(404).json({ message: "User not found" })
    }

    res.json(user)
})

// POST create user
app.post("/users", validateUser, (req, res) => {
    const { name, email, role } = req.body

    const newUser = {
        id: users.length + 1,
        name,
        email,
        role
    }

    users.push(newUser)

    res.status(201).json(newUser)
})

// PUT update user
app.put("/users/:id", (req, res) => {
    const id = parseInt(req.params.id)
    const user = users.find(u => u.id === id)

    if (!user) {
        return res.status(404).json({ message: "User not found" })
    }

    const { name, email, role } = req.body

    if (name) user.name = name
    if (email) user.email = email
    if (role) user.role = role

    res.json(user)
})

// DELETE user
app.delete("/users/:id", (req, res) => {
    const id = parseInt(req.params.id)
    const index = users.findIndex(u => u.id === id)

    if (index === -1) {
        return res.status(404).json({ message: "User not found" })
    }

    users.splice(index, 1)

    res.json({ message: "User deleted successfully" })
})

// =========================
// Global Error Handler
// =========================
app.use((err, req, res, next) => {
    res.status(500).json({ message: "Internal Server Error" })
})

// =========================
// Start Server
// =========================
app.listen(4000, () => {
    console.log("Task1 server running on port 4000")
})
