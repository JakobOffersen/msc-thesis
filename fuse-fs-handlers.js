const fs = require('fs')
const path = require('path')

const handlers = {
    init(cb) {

    },

    access(path, mode, cb) {

    },

    statfs(path, cb) {
        // called when the filesystem is being stat'ed
    },

    getattr(path, cb) {
        fs.stat(path, (err, stat) => {
            if (err) return cb(1) // return error code. TODO: Use proper error code
            else return cb(0, stat)
        })
    },

    fgetattr(path, fd, cb) {

    },

    flush(path, fd, cb) {

    },

    fsync(path, fd, datasync, cb) {

    },

    fsyncdir(path, fd, datasync, cb) {

    },

    readdir(path, cb) {
        fs.readdir(path, (err, fileNames) => {
            if (err) return cb(1) // mark error. TODO: Use proper error
            else return cb(0, fileNames)
        })
    },

    truncate(path, size, cb) {

    },

    ftruncate(path, fd, size, cb) {

    },

    readLink(path, cb) {

    },

    chown(path, uid, gid, cb) {

    },

    chmod(path, mode, cb) {

    },

    mknod(path, mode, deb, cb) {

    },

    setxattr(path, name, value, position, flags, cb) {

    },

    getxattr(path, name, position, cb) {

    },

    listxattr(path, name, cb) {

    },

    removexattr(path, name, cb) {

    },

    open(path, flags, cb) {
        fs.open(path, flags, (err, fd) => {
            if (err) return cb(1) // mark failed. TODO: Use proper error
            else return cb(0, fd)
        })
    },

    //TODO: Should 'flags' be used for something?
    opendir(path, flags, cb) {
        fs.opendir(path, (err, dir) => {
            if (err) return cb(1) // mark failed. TODO: Use proper error
            else return (0, dir)
        })
    },

    // write content into 'buffer' to be read by the caller
    // https://nodejs.org/api/fs.html#fscreatewritestreampath-options
    // TODO: Optimization: Instead of creating the readstream at each call, only open the file once and close when the end of the file is reached
    // TODO: Does the readstream close itself when the end its end is reached?
    read: function (path, fd, buffer, length, position, cb) {
        fs.stat(path, (err, stats) => {
            if (err) return cb(0) // Error occured. Mark file as read //TODO: Use proper error code?
            if (position >= stats.size) return cb(0) // reached end of file. Mark read completed

            const readStream = fs.createReadStream(path, { start: position, end: position + length }) // 'end' is inclusive => should it be 'position + length - 1' instead?
            readStream.on('readable', () => {
                const content = readStream.read(length) ?? Buffer.alloc(0) // 'content' may be shorter than 'length' when near the end of the stream.
                readStream.close()
                content.copy(buffer)
                return cb(content.length) // return number of bytes written to 'buffer'

            })
        })
    },

    write: function(path, fd, buffer, length, position, cb) {
        const writeStream = fs.createWriteStream(path, { start: position })
        writeStream.write(buffer, (err => {
            if (err) return cb(0) // Error occured. Mark that no bytes were written
            return cb(length) // Successful. All bytes were written
        }))
    },

    release(path, fd, cb) {

    },

    releasedir(path, fd, cb) {

    },

    create(path, mode, cb) {

    },

    utimens(path, atime, mtime, cb) {

    },

    unlink(path, cb) {

    },

    rename(src, dest, cb) {

    },

    link(src, dest, cb) {

    },

    symlink(src, dest, cb) {

    },

    mkdir(path, mode, cb) {

    },

    rmdir(path, mode, cb) {
        
    }
}

module.exports = handlers