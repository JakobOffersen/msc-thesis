const assert = require("chai").assert
const { join } = require("path")
const fs = require("fs/promises")
const KeyRing = require("../keyring")
const { DateTime } = require("luxon")

const testDirPath = join(__dirname, "keyrings")

describe("Key Ring", function () {
	before("setup local test-folder", async function () {
		try {
			await fs.access(testDirPath)
		} catch {
			await fs.mkdir(testDirPath)
		}
	})

	afterEach("clear test-folder content", async function () {
		await fs.rm(testDirPath, { recursive: true, force: true })
		await fs.mkdir(testDirPath)
	})

	after("teardown local test-folder", async function () {
		await fs.rm(testDirPath, { recursive: true, force: true })
	})

	it("should reject adding an invalid key-object", async function () {
		const kr = new KeyRing(join(testDirPath, "keyring1"))

		const k1 = {
			// should be rejected since it does not have a 'type' property
			createdAt: DateTime.now(),
			updatedAt: DateTime.now(),
			key: Buffer.alloc(32, "random key").toString("hex"),
			path: join(testDirPath, "file1"),
		}

		try {
			await kr.addKeyObject(k1)
			assert.fail()
		} catch {}
	})

	it("should accept adding a valid key-object", async function () {
		const kr = new KeyRing(join(testDirPath, "keyring1.txt"))

		const k1 = {
			// should be rejected since it does not have a 'type' property
			createdAt: DateTime.now(),
			updatedAt: DateTime.now(),
			key: Buffer.alloc(32, "random key").toString("hex"),
			path: join(testDirPath, "file1"),
			type: "write",
		}

		try {
			await kr.addKeyObject(k1)
		} catch {
			assert.fail()
		}

		const actual = await kr.getKeyObjectWithPath(join(testDirPath, "file1"))

		assert.equal(JSON.stringify(k1), JSON.stringify(actual))
	})

	it("should remove key object", async function () {
		const kr = new KeyRing(join(testDirPath, "keyring2.txt"))

		const path = join(testDirPath, "file")
		const k1 = {
			// should be rejected since it does not have a 'type' property
			createdAt: DateTime.now(),
			updatedAt: DateTime.now(),
			key: Buffer.alloc(32, "random key").toString("hex"),
			path: path,
			type: "write",
		}

		await kr.addKeyObject(k1)
		const k1Actual = await kr.getKeyObjectWithPath(path)
		assert.isNotNull(k1Actual)

		await kr.removeKeyObject(k1)
		const k1ActualAfterRemoval = await kr.getKeyObjectWithPath(path)
		assert.isNull(k1ActualAfterRemoval)
	})

	it("should update key object with new path", async function () {
		const kr = new KeyRing(join(testDirPath, "keyring3.txt"))

		const oldPath = join(testDirPath, "initifial-file-name.txt")
		const newPath = join(testDirPath, "updated-file-name.txt")

		const k = {
			// should be rejected since it does not have a 'type' property
			createdAt: DateTime.now(),
			updatedAt: DateTime.now(),
			key: Buffer.alloc(32, "random key").toString("hex"),
			path: oldPath,
			type: "write",
		}

		await kr.addKeyObject(k)
		await kr.updateKeyObjectPath(oldPath, newPath)

		const actual = await kr.getKeyObjectWithPath(newPath)
		assert.equal(actual.path, newPath)
		assert.isTrue(actual.createdAt < actual.updatedAt)
	})

	it("should update key object with new key", async function () {
		const kr = new KeyRing(join(testDirPath, "keyring3.txt"))

		const path = join(testDirPath, "initifial-file-name.txt")

		const oldKey = Buffer.alloc(32, "old key").toString("hex")
		const newKey = Buffer.alloc(32, "new key")

		const k = {
			// should be rejected since it does not have a 'type' property
			createdAt: DateTime.now(),
			updatedAt: DateTime.now(),
			key: oldKey,
			path: path,
			type: "write",
		}

		await kr.addKeyObject(k)
		await kr.updateKeyObjectKey(path, newKey)

		const actual = await kr.getKeyObjectWithPath(path)
		assert.equal(actual.key, newKey.toString("hex"))
		assert.isTrue(actual.createdAt < actual.updatedAt)
	})
})
