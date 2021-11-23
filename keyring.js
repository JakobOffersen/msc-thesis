const fs = require("fs/promises")
const { DateTime } = require("luxon")

class KeyRing {
	TYPE_READ = "read"
	TYPE_WRITE = "write"
	TYPE_VERIFY = "verify"

	constructor(path) {
		this.path = path
	}

	async removeKeyObject(keyObject) {
		if (!this._keyObjectIsValid(keyObject))
			throw new Error(
				"Cannot remove invalid key-object in keyring. Received " +
					JSON.stringify(keyObject)
			)
		await this.removeKeyObjectsWithPath(keyObject.path, keyObject.type)
	}

	// Removes all keys for 'path'.
	// If the optional param 'type' is given, only the keyObject matching
	// 'path' and 'type' is removed
	async removeKeyObjectsWithPath(path, type) {
		if (!!type && !this._isValidType(type)) {
			throw new Error("Recieved invalid type: " + type)
		}

		let keys = await this._read()

		keys = keys.filter((keyObject) => {
			return !(
				keyObject.path === path &&
				(!!type ? keyObject.type === type : true)
			)
		})

		await this._write(keys)
	}

    /// Adds the keyObject to the keyring.
    /// The received keyObject overrides an already existing entry
    /// if they have the same 'path' and 'type'
	async addKeyObject(keyObject) {
		if (!this._keyObjectIsValid(keyObject)) {
			throw new Error(
				"Cannot add invalid key-object to keyring. Received " +
					JSON.stringify(keyObject)
			)
		}

		const keys = await this._read()

        // Check if keyring already contains a keyObject for 'path' of 'type'
        const indexOfExistingKeyObject = this._indexMatchingPathAndType(keys, keyObject.path, keyObject.type)

        if (indexOfExistingKeyObject === -1) {
            keys.push(keyObject)
        } else {
            // override existing keyObject
            keys[indexOfExistingKeyObject] = keyObject
        }

        await this._write(keys)
	}

    async getKeyObjectsWithPath(path) {
		const keys = await this._read()
		return keys.filter((keyObject) => keyObject.path === path)
	}

	async getKeyObjectWithPathAndType(path, type) {
		if (!this._isValidType(type)) {
			throw new Error("Recieved invalid type: " + type)
		}

		const keys = await this._read()
		for (const keyObject of keys) {
			if (keyObject.path === path && keyObject.type === type)
				return keyObject
		}
		return null
	}

	/// Returns 'true' if a key-object has been updated, otherwise returns 'false'
	async updateKeyObjectsWithPath(oldPath, newPath) {
		const keys = await this._read()
		let updateHappened = false

		for (const keyObject of keys) {
			if (keyObject.path === oldPath) {
				keyObject.path = newPath
				keyObject.updatedAt = DateTime.now()
				updateHappened = true
			}
		}

		if (updateHappened) {
			await this._write(keys)
			return true
		}

		return false
	}

	async updateKeyObjectKey(path, type, newKey) {
		if (!this._isValidType(type)) {
			throw new Error("Recieved invalid type: " + type)
		}

		const keys = await this._read()
		for (const keyObject of keys) {
			if (keyObject.path === path && keyObject.type === type) {
				keyObject.key = Buffer.isBuffer(newKey)
					? newKey.toString("hex")
					: newKey
				keyObject.updatedAt = DateTime.now()
				await this._write(keys)
				return true
			}
		}
		return false
	}

	async _read() {
		try {
			const content = await fs.readFile(this.path)
			return JSON.parse(content)
		} catch {
			// file does not exist. Return empty keys
			return []
		}
	}

	async _write(keys) {
		await fs.writeFile(this.path, JSON.stringify(keys))
	}

	_keyObjectIsValid(keyObject) {
		return (
			Object.keys(keyObject).length === 5 &&
			keyObject.hasOwnProperty("createdAt") &&
			keyObject.hasOwnProperty("updatedAt") &&
			keyObject.hasOwnProperty("type") &&
			keyObject.hasOwnProperty("key") &&
			keyObject.hasOwnProperty("path") &&
			DateTime.isDateTime(DateTime.fromISO(keyObject.createdAt)) &&
			DateTime.isDateTime(DateTime.fromISO(keyObject.updatedAt)) &&
			[this.TYPE_READ, this.TYPE_WRITE, this.TYPE_VERIFY].includes(
				keyObject.type
			) &&
			typeof keyObject.key === "string" &&
			typeof keyObject.path === "string"
		)
	}

	_isValidType(type) {
		return (
			type === this.TYPE_READ ||
			type === this.TYPE_WRITE ||
			type === this.TYPE_VERIFY
		)
	}

    _indexMatchingPathAndType(keys, path, type) {
        for (const [index, keyObject] of keys.entries()) {
            if (keyObject.path === path && keyObject.type === type) {
                return index
            }
        }
        return -1
    }
}

module.exports = KeyRing
