const fs = require('fs/promises')
const { signDetached } = require('./../crypto')
const { createHash } = require('crypto')
const { createWriteStream, createReadStream } = require('fs')

class FileSigner {
    constructor(path, key) {
        this.path = path
        this.key = key
    }

    async sign() {
        try {
            //TODO: Clean up
            const content = await fs.readFile(this.path)
            const hash = await this.#hash()
            console.log(`sign before ${this.path}, content length: ${content.length}`)
            const signature = signDetached(Buffer.from(hash, "hex"), this.key)
            await this.#append(signature)
            const content2 = await fs.readFile(this.path)
            console.log(`sign after  ${this.path}, content length: ${content2.length}`)
        } catch (error) {
            console.log(`sign error ${this.path}: ${error}`)
        }
    }

    async #append(content) {
        return new Promise((resolve, reject) => {
            const stream = createWriteStream(this.path, { flags: "a" })
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

    async #hash() {
        return new Promise((resolve, reject) => {
            const stream = createReadStream(this.path)
            const hash = createHash("sha256")
            stream.on("data", data => hash.update(data))
            stream.on("end", () => stream.destroy()) // emits 'close'
            stream.on("error", err => reject(err))
            stream.on("close", () => resolve(hash.digest("hex")))
        })
    }
}

module.exports = FileSigner