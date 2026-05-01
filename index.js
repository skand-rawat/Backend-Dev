const express = require("express");
const app = express();
app.use(express.json());
let students = [];
let currentid = 1;
app.post("/students",(req,res) =>{
    const {name,marks} = req.body;
    if(!name|| marks === undefined || marks<0){
        return res.status(400).json({ message: "Invalid input"});
    }
    const newStudent = {
        id: currentid++,
        name,
        marks
    };
    students.push(newStudent);
    res.status(201).json(newStudent);
});
app.get("/students",(req,res)=> {
    res.status(200).json(students);
});
app.put("/students/:id", (req, res) => {
    const id = parseInt(req.params.id);
    const { name, marks } = req.body;

    const student = students.find(s => s.id === id);

    if (!student) {
        return res.status(404).json({ message: "Student not found" });
    }
  if (!name || marks === undefined || marks < 0) {
        return res.status(400).json({ message: "Invalid input" });
    }

    student.name = name;
    student.marks = marks;

    res.status(200).json(student);
});
app.delete("/students/:id", (req, res) => {
    const id = parseInt(req.params.id);

    const index = students.findIndex(s => s.id === id);

    if (index === -1) {
        return res.status(404).json({ message: "Student not found" });
    }

    students.splice(index, 1);

    res.status(200).json({ message: "Student deleted" });
});
app.listen(3000,() =>{
    console.log("server started");
}); 