const { signDetached } = require("./../crypto")
const { createHash } = require("crypto")
const { createReadStream } = require("fs")
const sodium = require("sodium-native")
const fsFns = require("./../fsFns")
const { truncate } = require("fs/promises")
const { assert } = require("console")
const { basename } = require("path")

const SIGNATURE_SIZE = sodium.crypto_sign_BYTES
const SIGNATURE_MARK = Buffer.from("signature:")
const TOTAL_SIGNATURE_SIZE = SIGNATURE_SIZE + SIGNATURE_MARK.length

async function prependSignature(filehandle) {
    console.log(`prependSig start... ${basename(filehandle.path)}`)
    const hash = await hashFile(filehandle)
    const signature = signDetached(Buffer.from(hash, "hex"), filehandle.writeCapability.key)
    const combined = Buffer.concat([SIGNATURE_MARK, signature])
    await prepend(filehandle.fd, combined)
    console.log(`prependSig complete ${basename(filehandle.path)}`)
}

async function removeSignature(filehandle) {
    const fileSize = (await fsFns.fstat(filehandle.fd)).size
    await truncate(filehandle.path, fileSize - TOTAL_SIGNATURE_SIZE)

    const sizeAfter = (await fsFns.fstat(filehandle.fd)).size
    assert(fileSize - sizeAfter === TOTAL_SIGNATURE_SIZE, `removeSignature: signature not removed correctly`)
}

async function prepend(fd, content) {
    await fsFns.write(fd, content, 0, content.length, 0)
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
    removeSignature,
    TOTAL_SIGNATURE_SIZE
}
