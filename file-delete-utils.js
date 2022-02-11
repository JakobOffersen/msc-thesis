const { createReadStream } = require("fs")
const { extname } = require("path")
const { Dropbox } = require("dropbox")
const crypto = require("./crypto")
const fsFns = require("./fsFns")
const dch = require("./dropbox-content-hasher")
const { FILE_DELETE_PREFIX_BUFFER, FSP_ACCESS_TOKEN } = require("./constants")

const dbx = new Dropbox({ accessToken: FSP_ACCESS_TOKEN })

async function createDeleteFileContent({ writeKey, localPath, remotePath }) {
    console.log(`unlink ${localPath}`)
    const revisionID = await fetchRevisionForPath({ remotePath, localPath })
    const sig = crypto.signCombined(Buffer.from(revisionID, "hex"), writeKey) // note this returns the signature combined with the message
    console.log(`\tchosen rev ID ${revisionID}`)
    console.log(`\tsig ${sig.toString("hex")}`)

    return Buffer.concat([FILE_DELETE_PREFIX_BUFFER, sig]) // prepend the file-delete marker
}

async function fetchRevisionForPath({ remotePath, localPath }) {
    const contentHash = await dropboxContentHash(localPath)

    const response = await dbx.filesListRevisions({ path: remotePath, mode: "path", limit: 10 })

    let revisionIndex = response.result.entries.findIndex(entry => entry.content_hash === contentHash)
    if (revisionIndex === -1) console.log("NO INDEX MATCHED CONTENT HASH OF", localPath)
    if (revisionIndex === -1) revisionIndex = 0 // default to the latest revision.

    return response.result.entries[revisionIndex].rev
}

/**
 *
 * @param {String} localPath The local path of the file to be checked
 * @returns true iff 'content' is marked as a delete-operation (e.g made by 'createDeleteFileContent')
 */
async function fileAtPathMarkedAsDeleted(localPath) {
    if (extname(localPath) !== ".deleted") localPath = localPath + ".deleted"
    const prefix = Buffer.alloc(FILE_DELETE_PREFIX_BUFFER.length)

    let fd
    try {
        fd = await fsFns.open(localPath, "r")
        await fsFns.read(fd, prefix, 0, FILE_DELETE_PREFIX_BUFFER.length, 0)

        return Buffer.compare(prefix, FILE_DELETE_PREFIX_BUFFER) === 0
    } catch {
        return false // if the file does not exist, it cannot be marked as deleted
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

// TODO: Refactor this and the same function in integrity-checker into own module
const dropboxContentHash = async localPath => {
    return new Promise((resolve, reject) => {
        //TODO: lock while hashing?
        const hasher = dch.create()
        const stream = createReadStream(localPath)
        stream.on("data", data => hasher.update(data))
        stream.on("end", () => resolve(hasher.digest("hex")))
        stream.on("error", err => reject(err))
    })
}

module.exports = {
    fileAtPathMarkedAsDeleted,
    createDeleteFileContent,
    verifyDeleteFileContent
}
