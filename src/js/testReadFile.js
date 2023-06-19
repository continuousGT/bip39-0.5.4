const fs = require('fs')

var textRead = fs.readFileSync('found.txt','utf-8')

console.log(textRead)

textRead = 1;

fs.writeFileSync('found.txt', textRead);

console.log(textRead)