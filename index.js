const fs = require("fs")
const path = require("path")
const Fuse = require("fuse-native")
const { promisify } = require("util")
const { beforeShutdown } = require("./util")

const MOUNT_DIR = "./mnt"
const CACHE_DIR = "./cache"

const handlers = {
    readdir: function (path, cb) {
        if (path === '/') return cb(null, ['test'])
        return cb(Fuse.ENOENT)
    },
    getattr: function (path, cb) {
        console.log("getattr")
        // if (path === '/') return cb(null, stat({ mode: 'dir', size: 4096 }))
        // if (path === '/test') return cb(null, stat({ mode: 'file', size: 11 }))
        return cb(Fuse.ENOENT)
    },
    open: function (path, flags, cb) {
        return cb(0, 42)
    },
    release: function (path, fd, cb) {
        return cb(0)
    },
    read: function (path, fd, buf, len, pos, cb) {
        var str = 'hello world'.slice(pos, pos + len)
        if (!str) return cb(0)
        buf.write(str)
        return cb(str.length)
    }
}

const fuse = new Fuse(MOUNT_DIR, handlers, { debug: true, mkdir: true })

fuse.mount(function (err) {
    if (err) {
        console.error(err)
        return
    }

    fs.readFile(path.join(MOUNT_DIR, 'test'), function (err, buf) {
        // buf should be 'hello world'
        console.log(err, buf)
    })
})

const unmount = promisify(fuse.unmount).bind(fuse)
beforeShutdown(unmount)