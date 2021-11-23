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

		const k1 = { // should be rejected since it does not have a 'type' property
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
			createdAt: DateTime.now(),
			updatedAt: DateTime.now(),
			key: Buffer.alloc(32, "random key").toString("hex"),
			path: join(testDirPath, "file1"),
			type: kr.TYPE_WRITE,
		}

		try {
			await kr.addKeyObject(k1)
		} catch {
			assert.fail()
		}

		const actual = await kr.getKeyObjectWithPathAndType(join(testDirPath, "file1"), kr.TYPE_WRITE)

		assert.equal(JSON.stringify(k1), JSON.stringify(actual))
	})

	it("should remove key object", async function () {
		const kr = new KeyRing(join(testDirPath, "keyring2.txt"))

		const path = join(testDirPath, "file")
		const k1 = {
			createdAt: DateTime.now(),
			updatedAt: DateTime.now(),
			key: Buffer.alloc(32, "random key").toString("hex"),
			path: path,
			type: kr.TYPE_WRITE,
		}

		await kr.addKeyObject(k1)
		const k1Actual = await kr.getKeyObjectWithPathAndType(path, kr.TYPE_WRITE)
		assert.isNotNull(k1Actual)

		await kr.removeKeyObject(k1)
		const k1ActualAfterRemoval = await kr.getKeyObjectWithPathAndType(path, kr.TYPE_WRITE)
		assert.isNull(k1ActualAfterRemoval)
	})

    it("should remove key object by path and optional type", async function() {
        const kr = new KeyRing(join(testDirPath, "keyring.txt"))

        const path = join(testDirPath, "test-file.txt")

        const k = {
			createdAt: DateTime.now(),
			updatedAt: DateTime.now(),
			key: Buffer.alloc(32, "random key").toString("hex"),
			path: path,
			type: kr.TYPE_WRITE,
		}

        await kr.addKeyObject(k)

        await kr.removeKeyObjectsWithPath(path)

        const actual = await kr.getKeyObjectsWithPath(path)
        assert.isEmpty(actual)
    })

    it("should remove key object by path and optional type", async function() {
        const kr = new KeyRing(join(testDirPath, "keyring.txt"))

        const path = join(testDirPath, "test-file.txt")

        const k1 = {
			createdAt: DateTime.now(),
			updatedAt: DateTime.now(),
			key: Buffer.alloc(32, "random key").toString("hex"),
			path: path,
			type: kr.TYPE_WRITE,
		}

        const k2 = {
			createdAt: DateTime.now(),
			updatedAt: DateTime.now(),
			key: Buffer.alloc(32, "other random key").toString("hex"),
			path: path,
			type: kr.TYPE_READ,
		}

        await kr.addKeyObject(k1)
        await kr.addKeyObject(k2)

        await kr.removeKeyObjectsWithPath(path, kr.TYPE_WRITE)

        const actualWrite = await kr.getKeyObjectWithPathAndType(path, kr.TYPE_WRITE)
        const [ actualVerify ] = await kr.getKeyObjectsWithPath(path)

        assert.isNull(actualWrite)
        assert.equal(JSON.stringify(k2), JSON.stringify(actualVerify))
    })

	it("should update all key objects with new path", async function () {
		const kr = new KeyRing(join(testDirPath, "keyring3.txt"))

		const oldPath = join(testDirPath, "initifial-file-name.txt")
		const newPath = join(testDirPath, "updated-file-name.txt")

		const k1 = {
			createdAt: DateTime.now(),
			updatedAt: DateTime.now(),
			key: Buffer.alloc(32, "random key").toString("hex"),
			path: oldPath,
			type: kr.TYPE_WRITE,
		}

        const k2 = {
			createdAt: DateTime.now(),
			updatedAt: DateTime.now(),
			key: Buffer.alloc(32, "other random key").toString("hex"),
			path: oldPath,
			type: kr.TYPE_READ,
		}

		await kr.addKeyObject(k1)
        await kr.addKeyObject(k2)
        await kr.updateKeyObjectsWithPath(oldPath, newPath)

		const [actual1, actual2] = await kr.getKeyObjectsWithPath(newPath)

        assert.equal(actual1.path, newPath)
		assert.equal(actual2.path, newPath)
        assert.isTrue(actual1.createdAt < actual1.updatedAt)
        assert.isTrue(actual2.createdAt < actual2.updatedAt)
	})

	it("should only update the right key object with new key", async function () {
		const kr = new KeyRing(join(testDirPath, "keyring3.txt"))

		const path = join(testDirPath, "initifial-file-name.txt")

		const oldWriteKey = Buffer.alloc(32, "old key").toString("hex")
		const newWriteKey = Buffer.alloc(32, "new key")
        const verifyKey = Buffer.alloc(32, "verify key").toString("hex")

		const k1 = {
			createdAt: DateTime.now(),
			updatedAt: DateTime.now(),
			key: oldWriteKey,
			path: path,
			type: kr.TYPE_WRITE,
		}

        const k2 = {
			createdAt: DateTime.now(),
			updatedAt: DateTime.now(),
			key: verifyKey,
			path: path,
			type: kr.TYPE_VERIFY
		}

		await kr.addKeyObject(k1)
        await kr.addKeyObject(k2)
		await kr.updateKeyObjectKey(path, kr.TYPE_WRITE, newWriteKey)


		const actualWrite = await kr.getKeyObjectWithPathAndType(path, kr.TYPE_WRITE)
		assert.equal(actualWrite.key, newWriteKey.toString("hex"))
		assert.isTrue(actualWrite.createdAt < actualWrite.updatedAt)

        const actualVerify = await kr.getKeyObjectWithPathAndType(path, kr.TYPE_VERIFY)
        assert.equal(actualVerify.key, verifyKey)
	})
})
