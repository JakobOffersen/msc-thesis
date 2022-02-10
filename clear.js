const { BASE_DIR, LOCAL_KEYRING_PATH, LOCAL_USERPAIR_PATH } = require("./constants")
const fs = require("fs/promises")
const { join, dirname } = require("path")
const { fdatasync } = require("fs")

function clearDirectory(path) {
    return fs.readdir(path).then(resources => {
        Promise.all(
            resources.map(r => {
                const fullpath = join(path, r)
                fs.rm(fullpath, { force: true, recursive: true })
            })
        )
            .then(() => console.log(`cleared ${path}`))
            .catch(console.log)
    })
}

clearDirectory(BASE_DIR).then(() => clearDirectory(dirname(LOCAL_KEYRING_PATH)))
