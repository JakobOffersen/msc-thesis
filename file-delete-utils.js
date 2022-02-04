const crypto = require("./crypto")
const fsFns = require("./fsFns")
const { FILE_DELETE_PREFIX_BUFFER } = require("./constants")
/**
 *
 * @param {FileMetaData} fileMetaData The metadata for the file to be marked as deleted
 * @param {Buffer} writekey The write key used to sign the mark
 * @returns {Buffer} the content of the file about to be deleted
 */
function createDeleteFileContent(rev, writekey) {
    rev = Buffer.from(rev)
    const sig = crypto.signCombined(rev, writekey) // note this returns the signature combined with the message
    return Buffer.concat([FILE_DELETE_PREFIX_BUFFER, sig]) // prepend the file-delete marker
}

/**
 *
 * @param {String} localPath The local path of the file to be checked
 * @returns true iff 'content' is marked as a delete-operation (e.g made by 'createDeleteFileContent')
 */
async function fileAtPathMarkedAsDeleted(localPath) {
    let fd
    try {
        const prefix = Buffer.alloc(FILE_DELETE_PREFIX_BUFFER.length)

        fd = await fsFns.open(localPath, "r")
        await fsFns.read(fd, prefix, 0, FILE_DELETE_PREFIX_BUFFER.length, 0)

        return Buffer.compare(prefix, FILE_DELETE_PREFIX_BUFFER) === 0
    } catch {
    } finally {
        if (!!fd) await fsFns.close(fd)
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
    fileAtPathMarkedAsDeleted,
    createDeleteFileContent,
    verifyDeleteFileContent
}
