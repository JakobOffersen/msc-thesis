const fs = require("fs")
const path = require("path")
const Fuse = require("fuse-native")
const { promisify } = require("util")
const { beforeShutdown, callbackifyHandlers } = require("./util")
const handlers = require("./fuse-crypto-handlers")

callbackifyHandlers(handlers)

const MOUNT_DIR = "./mnt"
const CACHE_DIR = "./cache"

const opts = {
    force: true,
    ...handlers
}

const fuse = new Fuse(MOUNT_DIR, handlers, { debug: true, mkdir: true })

// fs.stat("/Users/augustheegaard/Desktop/MSc/msc-thesis/fsp/", (err, stats) => {
//     console.log(err, stats)
// })

fuse.mount(function (err) {
    if (err) {
        console.error(err)
        return
    }

    // fs.readFile(path.join(MOUNT_DIR, 'test'), function (err, buf) {
    //     // buf should be 'hello world'
    //     console.log(err, buf)
    // })
})

const unmount = promisify(fuse.unmount).bind(fuse)
beforeShutdown(unmount)