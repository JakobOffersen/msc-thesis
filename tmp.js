const { dirname, basename } = require("path")
const path = "/file1.txt.sb-ab52335b-7YbfWf/file1.txt"
const path2 = "/milky-way-nasa.jpg.sb-ab52335b-hgufx0/milky-way-nasa.jpg.sb-ab52335b-V8xB5F"
const path3 = "/milky-way-nasa.jpg.sb-ab52335b-p7naPW/milky-way-nasa.jpg.sb-ab52335b-nePMlX"
const path4 = "/file1.txt"
console.log(basename(dirname(path4)).startsWith(basename(path4).split(".").slice(0, 2).join(".")))
console.log(basename(path4).split(".").slice(0, 2).join("."))
console.log(basename(dirname(path4)))
console.log(dirname(path4))
