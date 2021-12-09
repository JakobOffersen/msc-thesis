const fsS = require("fs")
const { promisify } = require("util")

/*
The fs/promises module in Node.js provides functions that that take a FileHandle object,
whereas the functions in the fs module take a file descriptor (number).
Since most handlers are called with a file descriptor that we need to operate on, we have to
use the fs module and provide promise support ourselves.
*/
module.exports = {
    read: promisify(fsS.read).bind(fsS),
    write: promisify(fsS.write).bind(fsS),
    truncate: promisify(fsS.truncate).bind(fsS),
    ftruncate: promisify(fsS.ftruncate).bind(fsS),
    fdatasync: promisify(fsS.fdatasync).bind(fsS),
    fsync: promisify(fsS.fsync).bind(fsS),
    close: promisify(fsS.close).bind(fsS),
    fstat: promisify(fsS.fstat).bind(fsS),
}
