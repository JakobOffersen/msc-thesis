const fs = require("fs/promises")
const fsS = require("fs")
const { promisify } = require("util")
const { join, resolve } = require("path")
const sodium = require("sodium-native")
const { assert } = require("console")
const crypto = require("./crypto")

const FSP_DIR = resolve("./fsp")

const fsFns = {
    read: promisify(fsS.read).bind(fsS),
    write: promisify(fsS.write).bind(fsS),
    truncate: promisify(fsS.truncate).bind(fsS),
    ftruncate: promisify(fsS.ftruncate).bind(fsS),
    fdatasync: promisify(fsS.fdatasync).bind(fsS),
    fsync: promisify(fsS.fsync).bind(fsS),
    close: promisify(fsS.close).bind(fsS)
}

const STREAM_CHUNK_SIZE = 4096

// Computes the plaintext size of a file that has been encrypted using secretstream.
function messageSize(ciphertextBytes) {
    const blockSize = STREAM_CHUNK_SIZE + sodium.crypto_secretbox_MACBYTES + sodium.crypto_secretbox_NONCEBYTES
    const blockCount = Math.ceil(ciphertextBytes / blockSize)
    const tagSizes = blockCount * (sodium.crypto_secretbox_MACBYTES + sodium.crypto_secretbox_NONCEBYTES)

    return ciphertextBytes - tagSizes
}

;(async () => {
    const path = "image.enc.png"
    const fullPath = join(FSP_DIR, path)
    const file = await fs.open(fullPath, "w+")
    const fd = file.fd

    const message = await fs.readFile(join(FSP_DIR, "image.png"))
    // const message = Buffer.alloc(4097)

    const key = Buffer.from("K/NUabfB3pz1IkThGO/oXDfzoHkUl6tQEsnl6sDi+yo=", "base64")

    // Push
    let remaining = message.byteLength

    while (remaining > 0) {
        // Write nonce
        const nonce = crypto.makeNonce()
        await fsFns.write(fd, nonce)

        const toBeWritten = Math.min(remaining, STREAM_CHUNK_SIZE)
        const ciphertext = Buffer.alloc(toBeWritten + sodium.crypto_secretbox_MACBYTES)

        const start = message.byteLength - remaining
        const end = start + toBeWritten
        const window = message.subarray(start, end)

        const res = sodium.crypto_secretbox_easy(ciphertext, window, nonce, key)
        if (res !== 0) {
            // TODO: Handle error
        }

        // Write ciphertext
        await fsFns.write(fd, ciphertext)

        remaining -= toBeWritten
    }

    await file.close()

    const sizeOnDisk = (await fs.stat(fullPath)).size
    console.log("File size: ", sizeOnDisk)
    console.log("Computed msg size: ", messageSize(sizeOnDisk))
    console.log("Actual msg size: ", message.byteLength)

    // Read back
    // const file2 = await fs.open(join(FSP_DIR, "image.dec.png"), "r")
    // const fd2 = file2.fd

    // await file2.close()
})().catch(error => {
    console.error(error)
    process.exit(1)
})
