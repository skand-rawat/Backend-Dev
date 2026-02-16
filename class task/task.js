const fs=require("fs");
fs.writeFileSync("./input.txt", "Hello, World!");
// const result=fs.readFileSync("./input.txt", "utf8");
// console.log(result);
fs.readFile("./input.txt", "utf8", (err, result) => { 
    if (err) { 
        if (err.code === "ENOENT") { 
            console.error("Error: File not found."); 
        } 
        else { 
            console.error("Error reading file:", err.message); 

        } } 
        else { console.log("File contents:", result); }
     });
fs.appendFile("./input.txt","hey there \n", (err) => {
    if (err) {
        console.error(err);
        return;
    }
   });
fs.cp("./input.txt", "./backup.txt",(err)=>{
    if(err){
        console.error(err);
    }
});
// fs.unlinkSync("./backup.txt");
// console.log(fs.statSync("./unknown.txt").isFile());