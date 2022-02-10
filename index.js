const Fuse = require("fuse-native")
const { promisify } = require("util")
const { beforeShutdown, callbackifyHandlersObj } = require("./util")
const { FuseHandlers } = require("./fuse/fuse-crypto-handlers")
const KeyRing = require("./key-management/keyring")
const { LOCAL_KEYRING_PATH, BASE_DIR, MOUNT_DIR, LOCAL_USERPAIR_PATH } = require("./constants")
const { dirname, join, basename } = require("path")
const { makeUser } = require("./make-user")

;(async () => {
    const args = process.argv.slice(2)
    const username = args[0] || ""
    const keyringPath = join(dirname(LOCAL_KEYRING_PATH), username, basename(LOCAL_KEYRING_PATH))
    const userpairPath = join(dirname(LOCAL_USERPAIR_PATH), username, basename(LOCAL_USERPAIR_PATH))
    const keyRing = new KeyRing(keyringPath, userpairPath)

    const userCreated = await keyRing.hasUserKeyPair()

    if (!userCreated) {
        await makeUser(keyRing) // this creates the users key pair and postal box
    }

    const handlers = new FuseHandlers(BASE_DIR, keyRing, { debug: false })
    const cbHandlers = callbackifyHandlersObj(handlers)

    const opts = {
        force: true,
        debug: false,
        mkdir: true
    }

    const fuse = new Fuse(MOUNT_DIR, cbHandlers, opts)

    fuse.mount(function (err) {
        if (err) {
            console.error(err)
            return
        }
    })

    const unmount = promisify(fuse.unmount).bind(fuse)
    beforeShutdown(unmount)
})()
