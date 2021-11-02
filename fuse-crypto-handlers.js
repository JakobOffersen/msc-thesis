const fs = require('fs')
const crypto = require('./crypto')

class KeyProvider {
    constructor() {
        this._keymap = new Map()
    }

    getKeyForPath(path) {
        if(!this._keymap.has(path)) this._keymap.set(path, crypto.makeSymmetricKey()) // create new key for path if existing key doesnt exist
        return this._keymap.get(path)
    }
}

function insertInto(source, target, position, length) {
    const headSlice = source.slice(0, position)
    const tailSlice = source.slice(position)
    const truncatedTarget = target.slice(0, length)
    return Buffer.concat([headSlice, truncatedTarget, tailSlice])
}

function readNonceAtPath(path, cb) {
    // Read out the nonce of the file.
    const nonceReadStream = fs.createReadStream(path, {start: 0, end: crypto.NONCE_LENGTH })

    // Wait for the stream to be readable, otherwise '.read' is invalid.
    nonceReadStream.on('readable', () => {
        const nonce = nonceReadStream.read(crypto.NONCE_LENGTH)
        nonceReadStream.close() // close stream to ensure on('readable') is not called multiple times
        if (!nonce || nonce.length !== crypto.NONCE_LENGTH) cb(null) // An error occured.
        else cb(nonce)
    })
}

const keyProvider = new KeyProvider()

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
    // TODO: Optimization: Instead of creating the readstream at each call, only open the file once and close when the end of the file is reached
    // TODO: Does the readstream close itself when the end its end is reached?
    read: function (path, fd, buffer, length, position, cb) {
        fs.stat(path, (err, stats) => {
            if (err) return cb(0) // Error occured. Mark file as read //TODO: Use proper error code?

            // Check if caller tries to read from a position after the file content.
            // Note that 'stats.size' includes the prepended buffer. Must be subtracted.
            if (position >= stats.size - crypto.NONCE_LENGTH) return cb(0) // Reached end of file. Mark read completed

            readNonceAtPath(path, (nonce) => {
                if (!nonce) return cb(0) // An error occured. Mark 0 bytes written to 'buffer'

                // Wait for the stream to be readable, otherwise '.read' is invalid.
                // Read out the cipher of the file.
                // Note that we need to offset the slice of the readstream due to the prepended nonce.
                const cipherReadStream = fs.createReadStream(path, { start: position + crypto.NONCE_LENGTH, end: position + length + crypto.NONCE_LENGTH })
                cipherReadStream.on('readable', () => {
                    // 'content' may be shorter than 'length' when near the end of the stream.
                    // The stream returns 'null' when the end is reached
                    const cipher = cipherReadStream.read(length)
                    cipherReadStream.close() // close stream to ensure on('readable') is not called multiple times
                    if (!cipher || cipher.length === 0) return cb(0) // end of file reached

                    // Decrypt the file-content
                    const key = keyProvider.getKeyForPath(path)
                    const plain = crypto.decryptSlice(cipher, nonce, key, position, length)

                    plain.copy(buffer) // copy 'plain' into buffer
                    cb(plain.length) // return number of bytes written to 'buffer'
                })
            })
        })
    },

    // Encrypts before writing to disk. Each write-call re-encrypts the file at 'path' using a fresh nonce.
    // Assumes the file at 'path' already exists
    write: function(path, fd, buffer, length, position, cb) {
        const key = keyProvider.getKeyForPath(path)

        fs.stat(path, (err, stat) => {
            if (err) return cb(1) // TODO: use proper error code

            if (stat.size === 0) {
                // nothing to decrypt
                const nonce = crypto.makeNonce()
                const ic = 0
                const cipher = crypto.streamXOR(buffer, nonce, ic, key)
                const nonceAndCipher = Buffer.concat([nonce, cipher])

                const writeStream = fs.createWriteStream(path)
                writeStream.write(nonceAndCipher, (err => {
                    if (err) return cb(0) // Error occured. Mark that no bytes were written
                    else return cb(cipher.length) // Successful. All bytes of 'buffer' were written
                }))
            } else {
                // We need to decrypt the existing content of file at 'path',
                // add the new write and re-encrypt it all under a new nonce

                // Read all of the existing content into 'readBuffer'
                const readBuffer = Buffer.alloc(stat.size - crypto.NONCE_LENGTH)
                this.read(path, fd, readBuffer, readBuffer.length, 0, (readLength) => {
                    if (readLength !== readBuffer.length) return cb(1) // read-error occured. TODO: use proper error code
                    if (position > readBuffer.length) return cb(1) // We try to write 'buffer' into a 'position' in 'readBuffer' that does not exist. TODO: Unsure how to handle this case yet.
                    // insert 'buffer' into the 'readBuffer' at position
                    const updatedReadBuffer = insertInto(readBuffer, buffer, position, length)

                    // Encrypt using a fresh nonce
                    const nonce = crypto.makeNonce()
                    const ic = 0 // We start from 0 since the entire buffer is re-encrypted
                    const cipher = crypto.streamXOR(updatedReadBuffer, nonce, ic, key)

                    // prepend nonce
                    const nonceAndCipher = Buffer.concat([nonce, cipher])

                    // write to 'path'
                    const writeStream = fs.createWriteStream(path)
                    writeStream.write(nonceAndCipher, (err => {
                        if (err) return cb(0) // Error occured. Mark that no bytes were written
                        else return cb(length) // Successful. All bytes of 'buffer' were written
                    }))
                })
            }
        })
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

    utimens(path, atime, mtime, cb) {},
    unlink(path, cb) {},
    rename(src, dest, cb) {},

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