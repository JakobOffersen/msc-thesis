const { BASE_DIR, LOCAL_KEYRING_PATH, DAEMON_CONTENT_HASH_STORE_PATH } = require("../constants")
const fs = require("fs/promises")
const { join, dirname } = require("path")

async function clearDirectory(path) {
    const resources = await fs.readdir(path)
    await Promise.all(
        resources.map(res => {
            fs.rm(join(path, res), { force: true, recursive: true })
        })
    )
    console.log(`cleared ${path}`)
}

async function unlink(path) {
    try {
        await fs.unlink(DAEMON_CONTENT_HASH_STORE_PATH)
        console.log(`deleted ${path}`)
    } catch {
        console.log(`already cleared ${path}`)
    }
}

;(async () => {
    await clearDirectory(BASE_DIR)
    await clearDirectory(dirname(LOCAL_KEYRING_PATH))
    await unlink(DAEMON_CONTENT_HASH_STORE_PATH)
})()
