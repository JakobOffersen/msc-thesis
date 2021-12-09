const { resolve } = require("path")
const Fuse = require("fuse-native")
const { promisify } = require("util")
const { beforeShutdown, callbackifyHandlersObj } = require("./util")
const { FuseHandlers } = require("./fuse-crypto-handlers")
const KeyProvider = require("./key-provider")

const keyProvider = new KeyProvider()
const MOUNT_DIR = resolve("./mnt")
const handlers = new FuseHandlers(MOUNT_DIR, keyProvider)

const opts = {
    force: true,
    ...callbackifyHandlersObj(handlers)
}

const fuse = new Fuse(MOUNT_DIR, handlers, { debug: true, mkdir: true })

fuse.mount(function (err) {
    if (err) {
        console.error(err)
        return
    }
})

const unmount = promisify(fuse.unmount).bind(fuse)
beforeShutdown(unmount)
