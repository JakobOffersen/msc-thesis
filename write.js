const fs = require("fs/promises")
const fsS = require("fs")
const { promisify } = require("util")
const { join, resolve } = require("path")
const sodium = require("sodium-native")
const { assert } = require("console")

const FSP_DIR = resolve("./fsp")

const fsFns = {
    read: promisify(fsS.read).bind(fsS),
    write: promisify(fsS.write).bind(fsS),
    truncate: promisify(fsS.truncate).bind(fsS),
    ftruncate: promisify(fsS.ftruncate).bind(fsS),
    fdatasync: promisify(fsS.fdatasync).bind(fsS),
    fsync: promisify(fsS.fsync).bind(fsS),
    close: promisify(fsS.close).bind(fsS)
};

// Computes the plaintext size of a file that has been encrypted using secretstream.
function messageSize(fileSize) {

    let size = fileSize
    
    // Subtract header
    size -= sodium.crypto_secretstream_xchacha20poly1305_HEADERBYTES

    // Subtract block tags
    const blockSize = 4096 + sodium.crypto_secretstream_xchacha20poly1305_ABYTES
    const blockCount = Math.ceil(size / blockSize)
    console.log("blockCount: ", blockCount)
    size -= blockCount * sodium.crypto_secretstream_xchacha20poly1305_ABYTES

    return size

}

// assert(messageSize(1) == 24 + 17 + 1)
// assert(messageSize(64) == 24 + 17 + 64)
// assert(messageSize(65) == 24 + 17 + 65)
// assert(messageSize(4200) == 24 + 2 * 17 + 4200)

(async () => {

    const path = "./image.png"
    const fullPath = join(FSP_DIR, path)
    const file = await fs.open(fullPath, "w+")
    const fd = file.fd

    console.log("NONCE Length: ", sodium.crypto_secretbox_NONCEBYTES)
    console.log("HEADER BYTES: ", sodium.crypto_secretstream_xchacha20poly1305_HEADERBYTES)
    console.log("A BYTES: ", sodium.crypto_secretstream_xchacha20poly1305_ABYTES)

    const message = await fs.readFile("./image.png")
    // const message = Buffer.alloc(4097)

    const header = Buffer.alloc(sodium.crypto_secretstream_xchacha20poly1305_HEADERBYTES)
    // const key = Buffer.alloc(sodium.crypto_secretstream_xchacha20poly1305_KEYBYTES)
    // sodium.crypto_secretstream_xchacha20poly1305_keygen(key)
    const key = Buffer.from("K/NUabfB3pz1IkThGO/oXDfzoHkUl6tQEsnl6sDi+yo=", "base64")

    // The documentation says to use `crypto_secretstream_xchacha20poly1305_state_new()`
    // but it doesn't exist in sodium-native.
    const state = Buffer.alloc(sodium.crypto_secretstream_xchacha20poly1305_STATEBYTES)
    
    sodium.crypto_secretstream_xchacha20poly1305_init_push(state, header, key)
    
    // Write header
    await fsFns.write(fd, header)

    // Push
    const tag = sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE
    let remaining = message.byteLength

    while (remaining > 0) {
        const toBeWritten = Math.min(remaining, 4096)
        const ciphertext = Buffer.alloc(toBeWritten + sodium.crypto_secretstream_xchacha20poly1305_ABYTES)
        
        const start = message.byteLength - remaining
        const end = start + toBeWritten
        const window = message.subarray(start, end)
        sodium.crypto_secretstream_xchacha20poly1305_push(state, ciphertext, window, null, tag)

        // Write ciphertext
        await fsFns.write(fd, ciphertext)

        remaining -= toBeWritten
    }

    await file.close()

    const sizeOnDisk = (await fs.stat(fullPath)).size
    console.log("File size: ", sizeOnDisk)
    console.log("Computed msg size: ", messageSize(sizeOnDisk))

    // Read back
    const file2 = await fs.open(fullPath, "r")
    const fd2 = file2.fd


    await file2.close()

})().catch(error => {
    console.error(error)
    process.exit(1)
})