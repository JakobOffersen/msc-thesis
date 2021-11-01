const fs = require('fs')
const path = require('path')

const handlers = {
    init(cb) {},

    access(path, mode, cb) {
        fs.access(path, mode, (err) => {
            if (err) cb(1) //mark failed. TODO: Use proper error code
            else cb(0) // success
        })
    },

    statfs(path, cb) {
        // TODO: What is the difference between 'statfs' and 'getattr'?
        // TODO: Unsure if this is a proper implementation
        fs.stat(path, (err, stat) => {
            if (err || !stat.isDirectory()) cb(1)
            else cb(0, stat)
        })
    },

    getattr(path, cb) {
        fs.stat(path, (err, stat) => {
            if (err) cb(1) // return error code. TODO: Use proper error code
            else cb(0, stat)
        })
    },

    fgetattr(path, fd, cb) {
        fs.fstat(fd, (err, stat) => {
            if(err) cb(1)
            else cb(0, stat)
        })
    },

    //TODO: Performance optimisation. Write to in-mem buffer instead of directly to disk. Then use 'flush' to store the in-mem buffer on disk.
    flush(path, fd, cb) {},

    fsync(path, fd, datasync, cb) {
        fs.fsync(fd, (err) => {
            if (err) cb(1)
            else cb(0)
        })
    },

    //TODO: Different implementation of 'fsync' and fsyncdir'?
    fsyncdir(path, fd, datasync, cb) {},

    readdir(path, cb) {
        fs.readdir(path, (err, fileNames) => {
            if (err) cb(1) // mark error. TODO: Use proper error
            else cb(0, fileNames)
        })
    },

    truncate(path, size, cb) {
        fs.truncate(path, size, (err) => {
            if (err) cb(1)
            else cb(0)
        })
    },

    ftruncate(path, fd, size, cb) {
        fs.ftruncate(fd, size, (err) => {
            if (err) cb(1)
            else cb(0)
        })
    },

    readLink(path, cb) {
        fs.readlink(path, (err, link) => {
            if (err) cb(1)
            else cb(0, link)
        })
    },

    chown(path, uid, gid, cb) {
        fs.chown(path, uid, gid, (err) =>{
            if (err) cb(1)
            else cb(0)
        })
    },

    chmod(path, mode, cb) {
        fs.chmod(path, mode, (err) => {
            if (err) cb(1)
            else cb(0)
        })
    },

    mknod(path, mode, deb, cb) {},
    setxattr(path, name, value, position, flags, cb) {},
    getxattr(path, name, position, cb) {},
    listxattr(path, name, cb) {},
    removexattr(path, name, cb) {},

    open(path, flags, cb) {
        fs.open(path, flags, (err, fd) => {
            if (err) cb(1) // mark failed. TODO: Use proper error
            else cb(0, fd)
        })
    },

    //TODO: Should 'flags' be used for something?
    opendir(path, flags, cb) {
        fs.opendir(path, (err, dir) => {
            if (err) cb(1) // mark failed. TODO: Use proper error
            else (0, dir)
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
            // Wait for the stream to be readable, otherwise '.read' is invalid.
            readStream.on('readable', () => {
                // 'content' may be shorter than 'length' when near the end of the stream.
                // The stream returns 'null' when the end is reached
                const content = readStream.read(length) ?? Buffer.alloc(0)
                readStream.close()
                content.copy(buffer)
                cb(content.length) // return number of bytes written to 'buffer'
            })
        })
    },

    write: function(path, fd, buffer, length, position, cb) {
        const writeStream = fs.createWriteStream(path, { start: position })
        writeStream.write(buffer, (err => {
            if (err) cb(0) // Error occured. Mark that no bytes were written
            else cb(length) // Successful. All bytes were written
        }))
    },

    release(path, fd, cb) {
        fs.close(fd, (err) => {
            if (err) cb(1)
            else cb(0)
        })
    },

    releasedir(path, fd, cb) {
        this.release(path, fd, cb) //TODO: Is this okay? If not, what are the differences?
    },

    create(path, mode, cb) {
        fs.open(path, 'wx+', mode, (err, fd) => { // 'wx+': Open file for reading and writing. Creates file but fails if the path exists.
            if (err) cb(1)
            else cb(0)
        })
    },

    utimens(path, atime, mtime, cb) {

    },

    unlink(path, cb) {

    },

    rename(src, dest, cb) {

    },

    link(src, dest, cb) {
        fs.link(src, dest, (err) => {
            if (err) cb(1)
            else cb(0)
        })
    },

    symlink(src, dest, cb) {
        fs.symlink(dest, src, (err) => {
            if (err) cb(1)
            else cb(0)
        })
    },

    mkdir(path, mode, cb) {
        fs.mkdir(path, {recursive: false, mode: mode}, (err) => {
            if (err) cb(1)
            else cb(0)
        })
    },

    rmdir(path, cb) {
        fs.rmdir(path, (err) => {
            if (err) cb(1)
            else cb(0)
        })
    }
}

module.exports = handlers