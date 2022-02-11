const { BASE_DIR, LOCAL_KEYRING_PATH } = require("../constants")
const fs = require("fs/promises")
const { join, dirname } = require("path")

async function clearDirectory(path) {
    const resources = await fs.readdir(path)
    await Promise.all(resources.map(res => {
        fs.rm(join(path, res), { force: true, recursive: true })
    }))
    console.log(`cleared ${path}`)
}

;(async () => {
    await clearDirectory(BASE_DIR)
    await clearDirectory(dirname(LOCAL_KEYRING_PATH))
})()
