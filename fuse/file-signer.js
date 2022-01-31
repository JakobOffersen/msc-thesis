const { signDetached } = require("./../crypto")
const { createHash } = require("crypto")
const { createWriteStream, createReadStream } = require("fs")
const sodium = require("sodium-native")
const fsFns = require("./../fsFns")

const SIGNATURE_SIZE = sodium.crypto_sign_BYTES
const SIGNATURE_MARK = Buffer.from("signature:")
const TOTAL_SIGNATURE_SIZE = SIGNATURE_SIZE + SIGNATURE_MARK.length

async function hasSignature(path) {
    const fd = await fsFns.open(path, "r")
    const fileSize = (await fsFns.fstat(fd)).size

    const signatureMarkSize = SIGNATURE_MARK.length
    const position = fileSize - signatureMarkSize - SIGNATURE_SIZE
    if (position < 0) return false // the file is smaller than the marker + signature => the signature cannot be there

    // read the marker from the file
    const marker = Buffer.alloc(signatureMarkSize)
    await fsFns.read(fd, marker, 0, signatureMarkSize, position)

    return Buffer.compare(SIGNATURE_MARK, marker) === 0 // .compare returns 0 iff buffers are equal
}

async function appendSignature(path, key) {
    const hash = await hashFile(path)
    const signature = signDetached(Buffer.from(hash, "hex"), key)
    const combined = Buffer.concat([SIGNATURE_MARK, signature])
    await append(path, combined)
}

async function append(path, content) {
    return new Promise((resolve, reject) => {
        const stream = createWriteStream(path, { flags: "a" })
        stream.on("error", reject)
        stream.on("close", resolve)
        stream.on("ready", () => {
            stream.write(content, error => {
                if (error) return reject(error)
                stream.close(error => {
                    // emits 'close'
                    if (error) reject(error)
                })
            })
        })
    })
}

async function hashFile(path) {
    return new Promise((resolve, reject) => {
        const stream = createReadStream(path)
        const hash = createHash("sha256")
        stream.on("data", data => hash.update(data))
        stream.on("end", () => stream.destroy()) // emits 'close'
        stream.on("error", err => reject(err))
        stream.on("close", () => resolve(hash.digest("hex")))
    })
}

module.exports = {
    appendSignature,
    hasSignature,
    TOTAL_SIGNATURE_SIZE
}
