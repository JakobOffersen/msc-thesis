const { fileAtPathMarkedAsDeleted } = require("./file-delete-utils")

const path = "/Users/jakoboffersen/Dropbox/file2.txt"

fileAtPathMarkedAsDeleted(path).then(yes => {
    console.log(yes)
})
