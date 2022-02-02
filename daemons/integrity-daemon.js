const IntegrityChecker = require("./integrity-checker")
const { DropboxProvider } = require("../storage_providers/storage_provider")
const { beforeShutdown } = require("../util")
const { DateTime } = require("luxon")
const KeyRing = require("../key-management/keyring")
const sodium = require("sodium-native")
const { fileAtPathMarkedAsDeleted, verifyDeleteFileContent } = require("../file-delete-utils")
const { LOCAL_KEYRING_PATH, FSP_ACCESS_TOKEN, BASE_DIR_LOCAL, SIGNATURE_MARK, STREAM_CIPHER_CHUNK_SIZE, TOTAL_SIGNATURE_SIZE } = require("../constants")
const { createHash } = require("crypto")
const { verifyDetached } = require("../crypto")
const fsFns = require("../fsFns")

const fsp = new DropboxProvider(FSP_ACCESS_TOKEN, __dirname)

const kr = new KeyRing(LOCAL_KEYRING_PATH, BASE_DIR_LOCAL)

//TODO: How do we ensure that valid writes to already-deleted (with mark) are rejected?
const verifySignature = async ({ localPath, remotePath }) => {
    const verifyCapability = await kr.getCapabilityWithPathAndType(remotePath, "verify")

    if (!verifyCapability) return true // we accept files we cannot check.

    if (await fileAtPathMarkedAsDeleted(localPath)) {
        const latestRevisionID = await fetchLatestRevisionID(remotePath)
        const verified = verifyDeleteFileContent(content, verifyCapability.key, latestRevisionID)
        console.log(timestamp(`${remotePath}: marked as deleted. Verified: ${verified}`))
        return verified
    } else {
        // is a regular write-operation: verify the signature
        // compute the hash from the macs in all chunks
        const hash = createHash("sha256")

        try {
            const fd = await fsFns.open(localPath, "r")
            const size = (await fsFns.fstat(fd)).size

            const chunkCount = Math.ceil(size / STREAM_CIPHER_CHUNK_SIZE) // ceil to include the last (potentially) non-full chunk
            const offset = TOTAL_SIGNATURE_SIZE + sodium.crypto_secretbox_NONCEBYTES

            for (let chunkIndex = 0; chunkIndex < chunkCount; chunkIndex++) {
                const start = chunkIndex * STREAM_CIPHER_CHUNK_SIZE + offset
                const mac = Buffer.alloc(sodium.crypto_secretbox_MACBYTES)
                await fsFns.read(fd, mac, 0, sodium.crypto_secretbox_MACBYTES, start)
                hash.update(mac)
            }

            const digest = Buffer.from(hash.digest("hex"), "hex")

            const signature = Buffer.alloc(sodium.crypto_sign_BYTES)
            await fsFns.read(fd, expectedSignature, 0, sodium.crypto_sign_BYTES, SIGNATURE_MARK.length)

            return verifyDetached(signature, digest, verifyCapability.key)
        } catch {
            // the file has been deleted. We dont allow files to be deleted
            return false
        }
    }
}

//TODO: Refactor this (and everything from file-delete-utils into Integrity-Checker later)

// TODO: refactor this into
const fetchLatestRevisionID = async remotePath => {
    const { entries } = await fsp.listRevisions(remotePath)
    const entry = entries[1] // [0] is the revision of the file that contains 'content'. Look at the one before that
    return entry.rev
}

const checker = new IntegrityChecker({
    fsp,
    watchPath: BASE_DIR_LOCAL,
    predicate: verifySignature
})

checker.on(IntegrityChecker.READY, () => {
    console.log(timestamp("ready"))
})

checker.on(IntegrityChecker.CONFLICT_FOUND, ({ remotePath }) => {
    console.log(timestamp(`${remotePath}: conflict found.`))
})

checker.on(IntegrityChecker.NO_CONFLICT, ({ remotePath }) => {
    console.log(timestamp(`${remotePath}: No conflict.`))
})

checker.on(IntegrityChecker.CONFLICT_RESOLUTION_SUCCEEDED, ({ remotePath }) => {
    console.log(timestamp(`${remotePath}: conflict resolution succeeded `))
})

checker.on(IntegrityChecker.CONFLICT_RESOLUTION_FAILED, ({ remotePath, error }) => {
    console.error(timestamp(`${remotePath}: conflict resolution failed. Error: ${error}`))
})

checker.on(IntegrityChecker.CHANGE, ({ remotePath, eventType }) => {
    console.log(timestamp(`${remotePath}: detected '${eventType}'`))
})

checker.on(IntegrityChecker.EQUIVALENT_CONFLICT_IS_PENDING, ({ remotePath }) => {
    console.log(timestamp(`${remotePath}: equivalent conflict is already pending on job queue`))
})

beforeShutdown(() => {
    console.log(timestamp(`shutdown integrity-daemon`))
})

function timestamp(msg) {
    const format = { ...DateTime.TIME_24_WITH_SECONDS, ...DateTime.DATE_SHORT }
    return `[${DateTime.now().toLocaleString(format)}] ${msg}`
}
