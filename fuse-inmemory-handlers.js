const fs = require('fs')
const path = require('path')
const Fuse = require('fuse-native')

const NO_ERROR = 0

const files = new Map() // indexed by 'path'

const handlers = {
    readdir: function (path, cb) {
        if (path !== '/') return cb(Fuse.ENOENT)
        const names = files.values.map(f => f.name)
        return cb(NO_ERROR, names)
    },
    read: function (path, fd, buffer, length, position, cb) {
        if (!files.has(path)) return cb(1) // file not found //TODO: Use proper error code instead of '1'
        const file = files.get(path)
        const fileContent = file.buffer

        if (position >= fileContent.len) return cb(0) // mark read as complete

        const slice = fileContent.slice(position, position + length)
        slice.copy(buffer, 0, position, position + length)
        return cb(slice.length)
    },

    write: function(path, fd, buffer, length, position, cb) {
        if (!files.has(path)) files.set(path, { name: path, buffer: Buffer.alloc(1000) }) // add the new file of size 1000

        const file = files.get(path)
        buffer.copy(file.buffer, position, 0, length) // copy [0, length]-path of 'buffer' into 'file.buffer'
        return cb(length) // handled all the data
    }
}

module.exports = handlers