const fs = require("fs/promises")
const { path, join, dirname } = require("path")

class ContentHashStore {
    constructor(storePath) {
        this.storePath = storePath
        this.hashes // (remote-path) => [content-hash]. Newest content hash is the last entry
    }

    /// adds 'hash' to the list of content hashes for 'path'. Automatically saves to disk.
    async add(path, hash) {
        if (!this.hashes) this.hashes = await this._read()

        this._append(path, hash)
        await this._save()
    }

    /// returns true iff the list of hashes of 'path' contains 'hash'
    async has(path, hash) {
        if (!this.hashes) this.hashes = await this._read()

        return this.hashes.has(path) && this.hashes.get(path).includes(hash)
    }

    async newest(path) {
        if (!this.hashes) this.hashes = await this._read()

        if (!this.hashes.has(path)) return null

        const hashes = this.hashes.get(path)

        return hashes[hashes.length - 1] // return the last entry, since newer entries are appended.
    }

    /// Appends 'hash' to the array of 'path'
    async _append(path, hash) {
        if (!this.hashes.has(path)) this.hashes.set(path, [])

        let hashes = this.hashes.get(path)
        hashes.push(hash)
        this.hashes.set(path, hashes)
    }

    async _read() {
        try {
            const content = await fs.readFile(this.storePath)
            return JSON.parse(content, reviver)
        } catch {
            // the file does not exist.
            return new Map()
        }
    }

    async _save() {
        try {
            await fs.writeFile(this.storePath, JSON.stringify(this.hashes, replacer, 2))
        } catch {
            // the path does not exist. create it
            const dirpath = dirname(this.storePath)
            await fs.mkdir(dirpath, { recursive: true })
            await this._save()
        }
    }
}

function replacer(_, value) {
    if (!(value instanceof Map)) return value

    return { dataType: "Map", value: [...value] }
}

function reviver(_, value) {
    return typeof value === "object" && value !== null && value.dataType === "Map" ? new Map(value.value) : value
}

module.exports = ContentHashStore