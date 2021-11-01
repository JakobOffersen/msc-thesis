const fs = require('fs')
const path = require('path')

const handlers = {
    readdir: function (path, cb) {

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
    }
}

module.exports = handlers