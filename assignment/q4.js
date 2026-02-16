const http = require("http");

let tasks = []; // in-memory storage
let idCounter = 1;

const server = http.createServer((req, res) => {
  res.setHeader("Content-Type", "application/json");

  if (req.method === "GET" && req.url === "/tasks") {
    // Read all tasks
    res.writeHead(200);
    res.end(JSON.stringify(tasks));

  } else if (req.method === "POST" && req.url === "/tasks") {
    // Create task
    let body = "";
    req.on("data", chunk => body += chunk);
    req.on("end", () => {
      const data = JSON.parse(body || "{}");
      const newTask = { id: idCounter++, title: data.title || "Untitled", done: false };
      tasks.push(newTask);
      res.writeHead(201);
      res.end(JSON.stringify(newTask));
    });

  } else if (req.method === "PUT" && req.url.startsWith("/tasks/")) {
    // Update task
    const id = parseInt(req.url.split("/")[2]);
    let body = "";
    req.on("data", chunk => body += chunk);
    req.on("end", () => {
      const data = JSON.parse(body || "{}");
      const task = tasks.find(t => t.id === id);
      if (task) {
        task.title = data.title ?? task.title;
        task.done = data.done ?? task.done;
        res.writeHead(200);
        res.end(JSON.stringify(task));
      } else {
        res.writeHead(404);
        res.end(JSON.stringify({ error: "Task not found" }));
      }
    });

  } else if (req.method === "DELETE" && req.url.startsWith("/tasks/")) {
    // Delete task
    const id = parseInt(req.url.split("/")[2]);
    const index = tasks.findIndex(t => t.id === id);
    if (index !== -1) {
      const deleted = tasks.splice(index, 1);
      res.writeHead(200);
      res.end(JSON.stringify(deleted[0]));
    } else {
      res.writeHead(404);
      res.end(JSON.stringify({ error: "Task not found" }));
    }

  } else {
    res.writeHead(404);
    res.end(JSON.stringify({ error: "Not found" }));
  }
});

server.listen(3000, () => {
  console.log("✅ TODO API ");
});
