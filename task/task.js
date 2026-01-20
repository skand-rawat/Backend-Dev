const fs = require('fs');
const readstream = fs.createReadStream('input.txt');
const writestream = fs.createWriteStream('output.txt');
readstream.pipe(writestream);
console.log('File copied successfully using pipes.');
