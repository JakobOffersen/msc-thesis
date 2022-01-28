const fs = require("fs/promises")
const { join } = require("path")
const { createReadStream, createWriteStream } = require("fs")
const { createHash, sign } = require("crypto")
const watchPath = "/Users/jakoboffersen/Desktop/msc-thesis/cac-project-test/msc-thesis/fsp"
const dropboxClientPath = "/Users/jakoboffersen/Dropbox"
const crypto = require("./../crypto")
const fsFns = require("../fsFns")
const { verifyDetached } = require("./../crypto")
const file = join(watchPath, "file2.txt")

const pair = {
    sk: Buffer.from("f7b98c3b8f00f2ae3f256747125da9a20ee96fa4f6b2f10a7752d27d17ca475625452cfa31784686ac94120074e3fef0e33636361833112508c3107b4f165d94", "hex"),
    pk: Buffer.from("25452cfa31784686ac94120074e3fef0e33636361833112508c3107b4f165d94", "hex")
}

class SignatureHandler {
    constructor(path, { sk, pk }) {
        this.path = path
        this.sk = sk
        this.pk = pk
    }

    async verifySignature() {
        const signatureSize = 64
        const fd = await fsFns.open(this.path, "r")
        const filesize = (await fsFns.fstat(fd)).size
        const signature = Buffer.alloc(signatureSize)

        const position = filesize - signatureSize

        await fsFns.read(fd, signature, 0, signatureSize, position)

        const hash = Buffer.from(await this.hash({ until: position }), "hex")
        return verifyDetached(signature, hash, this.pk)
    }

    async detachSignature() {
    }

    async appendSignature() {
        const hash = await this.hash()
        console.log("hash A:", hash)
        const signature = crypto.signDetached(Buffer.from(hash, "hex"), this.sk)
        console.log("signature A:", signature.toString("hex"))
        await this.append(signature)
    }

    async append(content) {
        return new Promise((resolve, reject) => {
            const stream = createWriteStream(this.path, { flags: "a" })
            stream.on("error", reject)
            stream.on("close", resolve)
            stream.on("ready", () => {
                stream.write(content, error => {
                    if (error) return reject(error)
                    // emits 'close'
                    stream.close(error => {
                        if (error) reject(error)
                    })
                })
            })
        })
    }

    async hash({ until = Infinity } = {}) {
        return new Promise((resolve, reject) => {
            const stream = createReadStream(this.path, { end: until - 1 })
            const hash = createHash("sha256")
            stream.on("data", data => hash.update(data))
            stream.on("end", () => stream.destroy()) // emits 'close'
            stream.on("error", err => reject(err))
            stream.on("close", () => resolve(hash.digest("hex")))
        })
    }
}

;(async () => {
    const handler = new SignatureHandler(file, pair)
    //await handler.appendSignature()
    console.log(await handler.verifySignature())
})()
