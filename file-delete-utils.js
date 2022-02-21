const fs = require("fs/promises")
const { extname } = require("path")
const crypto = require("./crypto")
const { FILE_DELETE_PREFIX_BUFFER } = require("./constants")

function createDeleteFileContent(writeKey, remotePath) {
    const sig = crypto.signCombined(Buffer.from(remotePath), writeKey) // note this returns the signature combined with the message
    return Buffer.concat([FILE_DELETE_PREFIX_BUFFER, sig]) // prepend the file-delete marker
}

/**
 *
 * @param {String} localPath The local path of the file to be checked
 * @returns true iff 'content' is marked as a delete-operation (e.g made by 'createDeleteFileContent')
 */
async function fileAtPathMarkedAsDeleted(localPath) {
    if (extname(localPath) !== ".deleted") localPath = localPath + ".deleted"
    const prefix = Buffer.alloc(FILE_DELETE_PREFIX_BUFFER.length)

    let file
    try {
        file = await fs.open(localPath, "r")
        await file.read(prefix, 0, prefix.byteLength, 0)
        return Buffer.compare(prefix, FILE_DELETE_PREFIX_BUFFER) === 0
    } catch {
        // An error can occur if the file does not exist or is shorter than the marker.
        return false
    } finally {
        if (!!file) await file.close()
    }
}

module.exports = {
    createDeleteFileContent,
    fileAtPathMarkedAsDeleted,
}
