const fs = require("fs/promises")
const { resolve, dirname } = require("path")
const { DateTime } = require("luxon")
const { CAPABILITY_TYPE_READ, CAPABILITY_TYPE_WRITE, CAPABILITY_TYPE_VERIFY } = require("../constants")
const { clone, cloneAll, generateCapabilitiesForPath } = require("./capability-utils")
const { makeEncryptionKeyPair } = require("../utilities/crypto")
const ignore = ["/.DS_Store"]

class Keyring {
    constructor(keyringPath, userPairPath) {
        this.keyringPath = keyringPath
        this.userPairPath = userPairPath
    }

    async hasUserKeyPair() {
        try {
            await fs.access(this.userPairPath)
            return true
        } catch {
            return false
        }
    }

    async makeUserKeyPair() {
        const { sk, pk } = makeEncryptionKeyPair()
        const pair = {
            sk: sk.toString("hex"),
            pk: pk.toString("hex")
        }

        const stringified = JSON.stringify(pair, null, 4)
        try {
            await fs.writeFile(this.userPairPath, stringified)
        } catch {
            // path does not exist. create it
            const parent = dirname(this.userPairPath)
            await fs.mkdir(parent, { recursive: true })
            await fs.writeFile(this.userPairPath, stringified)
        }

        return { sk, pk }
    }

    async getUserKeyPair() {
        const content = await fs.readFile(this.userPairPath)
        const { sk, pk } = JSON.parse(content)
        return {
            sk: Buffer.from(sk, "hex"),
            pk: Buffer.from(pk, "hex")
        }
    }

    async createNewCapabilitiesForRelativePath(relativePath) {
        if (ignore.includes(relativePath)) return []

        let capabilities = generateCapabilitiesForPath(relativePath)
        for (const cap of capabilities) {
            await this.addCapability(cap)
        }
        return capabilities
    }

    async removeCapability(capability) {
        if (!this.validateCapability(capability)) throw new Error("Cannot remove invalid capability in keyring. Received " + JSON.stringify(capability))
        await this.removeCapabilitiesWithPath(capability.path, capability.type)
    }

    // Removes all capabilities for 'path'.
    // If the optional param 'type' is given, only the capability matching
    // 'path' and 'type' is removed
    async removeCapabilitiesWithPath(path, type) {
        if (!!type && !this._isValidCapabilityType(type)) {
            throw new Error("Recieved invalid type: " + type)
        }

        let capabilities = await this._read()

        capabilities = capabilities.filter(capability => {
            return !(capability.path === path && (!!type ? capability.type === type : true))
        })

        await this._write(capabilities)
    }

    /// Adds the capability to the keyring.
    /// The received capability overrides an already existing entry
    /// if they have the same 'path' and 'type'
    async addCapability(capability) {
        if (!capability.hasOwnProperty("createdAt")) capability.createdAt = DateTime.now()
        if (!capability.hasOwnProperty("updatedAt")) capability.updatedAt = DateTime.now()

        if (!this.validateCapability(capability)) {
            throw new Error("Cannot add invalid capability to keyring. Received " + JSON.stringify(capability))
        }

        const capabilities = await this._read()

        // Check if keyring already contains a capability for 'path' of 'type'
        const indexOfExistingCapability = this._indexMatchingPathAndType(capabilities, capability.path, capability.type)

        if (indexOfExistingCapability === -1) {
            capabilities.push(capability)
        } else {
            // override existing capability
            capabilities[indexOfExistingCapability] = capability
        }

        await this._write(capabilities)
    }

    async getCapabilitiesWithPath(relativePath, keytype = "buffer") {
        const capabilities = await this._read()
        relativePath = resolve(relativePath.replace("/._", "/")) // TODO: Add descriptive comment to the method for why we do this
        const filtered = capabilities.filter(capability => capability.path === relativePath)
        return cloneAll(filtered, keytype)
    }

    async getCapabilityWithPathAndType(path, type, keytype = "buffer") {
        if (!path.startsWith("/")) path = "/" + path
        path = path.replace(".deleted", "")

        if (!this._isValidCapabilityType(type)) {
            throw new Error("Recieved invalid type: " + type)
        }

        const capabilities = await this._read()
        for (const capability of capabilities) {
            if (capability.path === path && capability.type === type) return clone(capability, keytype)
        }
        return null
    }


    /// Returns 'true' if a capability has been updated, otherwise returns 'false'
    async updateCapabilitiesWithPath(oldPath, newPath) {
        const capabilities = await this._read()
        let updateHappened = false

        for (const capability of capabilities) {
            if (capability.path === oldPath) {
                capability.path = newPath
                capability.updatedAt = DateTime.now()
                updateHappened = true
            }
        }

        if (updateHappened) {
            await this._write(capabilities)
            return true
        }

        return false
    }

    async updateCapabilityKey(path, type, newKey) {
        if (!this._isValidCapabilityType(type)) {
            throw new Error("Recieved invalid type: " + type)
        }

        const capabilities = await this._read()
        for (const capability of capabilities) {
            if (capability.path === path && capability.type === type) {
                capability.key = Buffer.isBuffer(newKey) ? newKey.toString("hex") : newKey
                capability.updatedAt = DateTime.now()
                await this._write(capabilities)
                return true
            }
        }
        return false
    }

    async _read() {
        try {
            const content = await fs.readFile(this.keyringPath)
            let capabilities = JSON.parse(content)
            capabilities.forEach(cap => (cap.key = Buffer.from(cap.key, "hex")))
            return capabilities
        } catch (error) {
            // file does not exist. Return empty capabilities
            return []
        }
    }

    async _write(capabilities) {
        try {
            // convert all keys to 'hex'-strings before saving
            const clone = cloneAll(capabilities, "string")
            await fs.writeFile(this.keyringPath, JSON.stringify(clone, null, 2))
        } catch {
            // the path does not exist. create it
            const dirpath = dirname(this.keyringPath)
            await fs.mkdir(dirpath, { recursive: true })
            await this._write(capabilities)
        }
    }

    validateCapability(capability) {
        const res =
            Object.keys(capability).length === 5 &&
            capability.hasOwnProperty("createdAt") &&
            capability.hasOwnProperty("updatedAt") &&
            capability.hasOwnProperty("type") &&
            capability.hasOwnProperty("key") &&
            capability.hasOwnProperty("path") &&
            DateTime.isDateTime(DateTime.fromISO(capability.createdAt)) &&
            DateTime.isDateTime(DateTime.fromISO(capability.updatedAt)) &&
            [CAPABILITY_TYPE_READ, CAPABILITY_TYPE_WRITE, CAPABILITY_TYPE_VERIFY].includes(capability.type) &&
            (typeof capability.key === "string" || Buffer.isBuffer(capability.key)) &&
            typeof capability.path === "string"

        return res
    }

    _isValidCapabilityType(type) {
        return type === CAPABILITY_TYPE_READ || type === CAPABILITY_TYPE_WRITE || type === CAPABILITY_TYPE_VERIFY
    }

    _indexMatchingPathAndType(capabilities, path, type) {
        for (const [index, capability] of capabilities.entries()) {
            if (capability.path === path && capability.type === type) {
                return index
            }
        }
        return -1
    }
}

module.exports = Keyring
