const { resolve } = require("path")
const Fuse = require("fuse-native")
const { promisify } = require("util")
const { beforeShutdown, callbackifyHandlersObj } = require("./util")
const { FuseHandlers } = require("./fuse-simple-handlers")
// const { FuseHandlers } = require("./fuse-crypto-handlers")
const KeyProvider = require("./key-provider")

const keyProvider = new KeyProvider()
// const BASE_DIR = resolve("./fsp")
const BASE_DIR = resolve("./fspP")
const MOUNT_DIR = resolve("./mnt2")
// const handlers = new FuseHandlers(BASE_DIR, keyProvider)
// const cbHandlers = callbackifyHandlersObj(handlers)

const handlers = new FuseHandlers(BASE_DIR)
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
