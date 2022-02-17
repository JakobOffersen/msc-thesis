const fs = require("fs/promises")
const { extname } = require("path")
const crypto = require("./crypto")
const { FILE_DELETE_PREFIX_BUFFER } = require("./constants")

function createDeleteFileContent(writeKey, remotePath) {
    const sig = crypto.signCombined(Buffer.from(remotePath, "hex"), writeKey) // note this returns the signature combined with the message
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
        await file.close()
    }
}

/**
 *
 * @param {Buffer} content the signature and message combined (created using crypto.signCombined)
 * @param {Buffer} verifyKey the key to verify the signature embedded in 'mark'
 * @param {Buffer | String} expectedRevisionID the revision ID of the file before the delete.
 * This ID must match the signed message for the mark to be valid
 * @returns {boolean} true if the delete-mark is valid, else false
 */
function verifyDeleteFileContent(content, verifyKey, expectedRevisionID) {
    const signedMessage = content.subarray(FILE_DELETE_PREFIX_BUFFER.length)
    try {
        const { verified, message } = crypto.verifyCombined(signedMessage, verifyKey)
        return verified && Buffer.compare(message, Buffer.from(expectedRevisionID)) === 0 // .compare returns 0 iff the two buffers are equal
    } catch {
        return false
    }
}

module.exports = {
    createDeleteFileContent,
    fileAtPathMarkedAsDeleted,
    verifyDeleteFileContent
}
