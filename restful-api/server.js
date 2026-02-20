const express = require("express")
const app = express()

app.use(express.json())

const PORT = 3000

// ======================
// In-memory Data
// ======================

let books = [
    { id: 1, title: "The Great Gatsby", author: "F. Scott Fitzgerald", year: 1925 },
    { id: 2, title: "1984", author: "George Orwell", year: 1949 },
    { id: 3, title: "To Kill a Mockingbird", author: "Harper Lee", year: 1960 }
]

let nextId = 4

let authors = []
let nextAuthorId = 1

// ======================
// Exercise 2
// Year Validation Middleware
// ======================

function validateYear(req, res, next) {
    const { year } = req.body

    if (year && (typeof year !== "number" || year < 1000 || year > new Date().getFullYear())) {
        return res.status(400).json({ error: "Invalid year" })
    }

    next()
}

// ======================
// Exercise 1 + 3
// GET All Books (Filter + Pagination)
// ======================

app.get("/api/books", (req, res) => {
    let result = [...books]

    const { author, year, page = 1, limit = 10 } = req.query

    if (author) {
        result = result.filter(b =>
            b.author.toLowerCase().includes(author.toLowerCase())
        )
    }

    if (year) {
        result = result.filter(b => b.year === parseInt(year))
    }

    const start = (page - 1) * limit
    const end = start + parseInt(limit)

    res.json(result.slice(start, end))
})

// ======================
// Exercise 5
// Search by Title
// ======================

app.get("/api/books/search", (req, res) => {
    const { title } = req.query

    if (!title) {
        return res.status(400).json({ error: "Title query required" })
    }

    const result = books.filter(b =>
        b.title.toLowerCase().includes(title.toLowerCase())
    )

    res.json(result)
})

// ======================
// Books CRUD
// ======================

app.post("/api/books", validateYear, (req, res) => {
    const { title, author, year } = req.body

    if (!title || !author || !year) {
        return res.status(400).json({ error: "All fields required" })
    }

    const newBook = { id: nextId++, title, author, year }
    books.push(newBook)

    res.status(201).json(newBook)
})

app.get("/api/books/:id", (req, res) => {
    const book = books.find(b => b.id === parseInt(req.params.id))
    if (!book) return res.status(404).json({ error: "Book not found" })

    res.json(book)
})

app.put("/api/books/:id", validateYear, (req, res) => {
    const index = books.findIndex(b => b.id === parseInt(req.params.id))
    if (index === -1) return res.status(404).json({ error: "Book not found" })

    const { title, author, year } = req.body
    if (!title || !author || !year) {
        return res.status(400).json({ error: "All fields required" })
    }

    books[index] = { id: parseInt(req.params.id), title, author, year }
    res.json(books[index])
})

app.patch("/api/books/:id", validateYear, (req, res) => {
    const book = books.find(b => b.id === parseInt(req.params.id))
    if (!book) return res.status(404).json({ error: "Book not found" })

    const { title, author, year } = req.body

    if (title) book.title = title
    if (author) book.author = author
    if (year) book.year = year

    res.json(book)
})

app.delete("/api/books/:id", (req, res) => {
    const index = books.findIndex(b => b.id === parseInt(req.params.id))
    if (index === -1) return res.status(404).json({ error: "Book not found" })

    const deleted = books.splice(index, 1)
    res.json({ message: "Deleted", book: deleted })
})

// ======================
// Exercise 4
// Authors CRUD
// ======================

app.post("/api/authors", (req, res) => {
    const { name } = req.body
    if (!name) return res.status(400).json({ error: "Name required" })

    const newAuthor = { id: nextAuthorId++, name }
    authors.push(newAuthor)

    res.status(201).json(newAuthor)
})

app.get("/api/authors", (req, res) => {
    res.json(authors)
})

app.get("/api/authors/:id", (req, res) => {
    const author = authors.find(a => a.id === parseInt(req.params.id))
    if (!author) return res.status(404).json({ error: "Author not found" })

    res.json(author)
})

app.put("/api/authors/:id", (req, res) => {
    const index = authors.findIndex(a => a.id === parseInt(req.params.id))
    if (index === -1) return res.status(404).json({ error: "Author not found" })

    const { name } = req.body
    if (!name) return res.status(400).json({ error: "Name required" })

    authors[index].name = name
    res.json(authors[index])
})

app.delete("/api/authors/:id", (req, res) => {
    const index = authors.findIndex(a => a.id === parseInt(req.params.id))
    if (index === -1) return res.status(404).json({ error: "Author not found" })

    const deleted = authors.splice(index, 1)
    res.json({ message: "Deleted", author: deleted })
})

// ======================

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`)
})