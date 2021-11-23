const fs = require("fs/promises")
const { DateTime } = require("luxon")

class KeyRing {
	constructor(path) {
		this.path = path
	}

	async removeKeyObject(keyObject) {
		if (!this._keyObjectIsValid(keyObject))
			throw new Error(
				"Cannot remove invalid key-object in keyring. Received " +
					JSON.stringify(keyObject)
			)
        await this.removeKeyObjectWithPath(keyObject.path)
	}

	async removeKeyObjectWithPath(path) {
		const keys = await this._read()

		const indexToRemove = keys.findIndex(
			(keyObject) => keyObject.path === path
		)

		if (indexToRemove === -1) return // keyring does not contain 'keyObject'

		keys.splice(indexToRemove, 1) // removes the object at 'indexToRemove'

		await this._write(keys)
	}

	async addKeyObject(keyObject) {
		if (!this._keyObjectIsValid(keyObject)) {
			throw new Error(
				"Cannot add invalid key-object to keyring. Received " +
					JSON.stringify(keyObject)
			)
		}

		const keys = await this._read()
		if (this._hasKeyForPath(keys, keyObject.path)) return // dont allow duplicates

		keys.push(keyObject)
		await this._write(keys)
	}

	async getKeyObjectWithPath(path) {
		const keys = await this._read()
		for (const keyObject of keys) {
			if (keyObject.path === path) return keyObject
		}
		return null
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

	_hasKeyForPath(keys, path) {
		for (const keyObject of keys) {
			if (keyObject.path === path) return true
		}
		return false
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
			["read", "write", "verify"].includes(keyObject.type) &&
			typeof keyObject.key === "string" &&
			typeof keyObject.path === "string"
		)
	}
}

module.exports = KeyRing
