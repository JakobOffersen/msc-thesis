const fs = require("fs/promises")
const { Dropbox } = require("dropbox")
const { FSP_ACCESS_TOKEN } = require("./constants")

const db = new Dropbox({ accessToken: FSP_ACCESS_TOKEN })
const basedir = "Users/jakoboffersen/Dropbox"
const path = "/half-mb.txt.deleted"

db.filesListRevisions({ path, mode: "path", limit: 10}).then(response => {
    response.result.entries.forEach(entry => console.log(entry.rev))
})