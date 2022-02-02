const { BASE_DIR, LOCAL_KEYRING_PATH } = require("./constants")
const fs = require("fs/promises")
const { join } = require("path")

fs.rm(LOCAL_KEYRING_PATH)
    .then(() => console.log(`cleared ${LOCAL_KEYRING_PATH}`))
    .catch(() => console.log(`aldready deleted ${LOCAL_KEYRING_PATH}`))
fs.readdir(BASE_DIR).then(resources => {
    Promise.all(
        resources.map(r => {
            const path = join(BASE_DIR, r)
            fs.rm(path, { force: true, recursive: true })
        })
    )
        .then(() => console.log(`cleared ${BASE_DIR}`))
        .catch(console.log)
})
