const fs = require("fs/promises")

const path = "/Users/jakoboffersen/Dropbox/half-mb.txt.deleted"
fs.readFile(path).then(content => {
    //console.dir(content, "hex", { maxArrayLength: null })
})
