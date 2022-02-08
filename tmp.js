const fs = require("fs/promises")
const { Dropbox } = require("dropbox")
const { FSP_ACCESS_TOKEN } = require("./constants")
const { join } = require("path")

const db = new Dropbox({ accessToken: FSP_ACCESS_TOKEN })
const basedir = "/Users/jakoboffersen/Dropbox"
const path = "half-mb.txt.deleted"

fs.readFile(join(basedir, path)).then(content => {
    db.filesListRevisions({ path: "/" + path, mode: "path" }).then(response => {
        console.dir(content, { depth: null })
        console.log(response.result.entries[0].rev)
    })
})

// db.filesListRevisions({ path: "/" + path, mode: "path" }).then(response => {
//     response.result.entries.forEach(e => console.log(e.rev))
// })
