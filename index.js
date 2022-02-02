const Fuse = require("fuse-native")
const { promisify } = require("util")
const { beforeShutdown, callbackifyHandlersObj } = require("./util")
const { FuseHandlers } = require("./fuse/fuse-crypto-handlers")
const KeyRing = require("./key-management/keyring")
const { LOCAL_KEYRING_PATH, BASE_DIR_DROPBOX, BASE_DIR_LOCAL, MOUNT_DIR } = require("./constants")

const keyRing = new KeyRing(LOCAL_KEYRING_PATH, BASE_DIR_LOCAL)
const handlers = new FuseHandlers(BASE_DIR_LOCAL, keyRing, { debug: true })
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
