const { signDetached } = require("./../crypto")
const { createHash } = require("crypto")
const { createReadStream } = require("fs")
const sodium = require("sodium-native")
const fsFns = require("./../fsFns")
const { basename } = require("path")

const SIGNATURE_SIZE = sodium.crypto_sign_BYTES
const SIGNATURE_MARK = Buffer.from("signature:")
const TOTAL_SIGNATURE_SIZE = SIGNATURE_SIZE + SIGNATURE_MARK.length

const STREAM_CHUNK_SIZE = 4096 //TODO: REFACTOR our of sile-signer + file-handle

// The maximum size of a chunk after it has been encrypted.
const STREAM_CIPHER_CHUNK_SIZE = STREAM_CHUNK_SIZE + sodium.crypto_secretbox_MACBYTES + sodium.crypto_secretbox_NONCEBYTES //TODO: REFACTOR our of sile-signer + file-handle

async function prependSignature(filehandle) {
    console.log(`prependSig start... ${basename(filehandle.path)}`)
    const macs = await readMACs(filehandle.path)
    const hash = hashArray(macs)
    console.log(`prependSig macs ${macs.length}, hash ${hash.length}`)
    const signature = signDetached(hash, filehandle.writeCapability.key)
    const combined = Buffer.concat([SIGNATURE_MARK, signature])
    await prepend(filehandle.fd, combined)
    console.log(`prependSig complete ${basename(filehandle.path)}, signature ${signature.length}`)
}

// Documentation crypto_secretbox_easy: https://libsodium.gitbook.io/doc/secret-key_cryptography/secretbox
// According to docs, the MAC is *prepended* to the message.
// In #write, we *prepend* the nonce to the entire MAC+cipher.
// Thus each chunk follows this pattern:
// | NONCE (24B) | MAC (16B) | CIPHER (variable length) |
// This function returns the MAC.
// NOTE: The MAC must *NOT* be modified. It is intented to be read-only
async function readMACs(path) {
    console.log("\tread macs:")
    try {
        // we make a new fd to ensure it is allowed to read ("r")
        const fd = await fsFns.open(path, "r")
        const fileSize = (await fsFns.fstat(fd)).size
        console.log(`\tread macs: size ${fileSize}`)
        const res = []

        const chunkCount = Math.ceil(fileSize / STREAM_CIPHER_CHUNK_SIZE) // ceil to include the last (potentially) non-full chunk
        const offset = TOTAL_SIGNATURE_SIZE + sodium.crypto_secretbox_NONCEBYTES

        for (let chunkIndex = 0; chunkIndex < chunkCount; chunkIndex++) {
            const start = chunkIndex * STREAM_CIPHER_CHUNK_SIZE + offset
            const mac = Buffer.alloc(sodium.crypto_secretbox_MACBYTES)
            await fsFns.read(fd, mac, 0, sodium.crypto_secretbox_MACBYTES, start)
            res.push(mac)
        }
        console.log(`\tread macs. size: ${fileSize}, chunks: ${chunkCount}, macs: ${res.length}`)
        return res
    } catch (error) {
        console.log(`READ MACS ERROR ${error}`)
    }
}

async function prepend(fd, content) {
    await fsFns.write(fd, content, 0, content.length, 0)
    console.log(`\tprepend bytes: ${content.length}`)
}

function hashArray(array) {
    if (array.length === 0) return Buffer.alloc(0)

    const hash = createHash("sha256")

    for (const entry of array) {
        hash.update(entry)
    }

    const digest = hash.digest("hex")
    return Buffer.from(digest, "hex")
}

async function hashFile(filehandle) {
    const fileSize = (await fsFns.fstat(filehandle.fd)).size
    if (fileSize.length === 0) return ""

    return new Promise((resolve, reject) => {
        const stream = createReadStream(filehandle.path, { start: TOTAL_SIGNATURE_SIZE })
        const hash = createHash("sha256")
        stream.on("data", data => hash.update(data))
        stream.on("end", () => stream.destroy()) // emits 'close'
        stream.on("error", err => reject(err))
        stream.on("close", () => resolve(hash.digest("hex")))
    })
}

module.exports = {
    prependSignature,
    TOTAL_SIGNATURE_SIZE
}
