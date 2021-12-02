const assert = require("chai").assert
const { join } = require("path")
const fs = require("fs/promises")
const KeyRing = require("../keyring")
const { DateTime } = require("luxon")
const { TYPE_READ, TYPE_WRITE, TYPE_VERIFY } = require('../capability-utils')

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

		const cap = { // should be rejected since it does not have a 'type' property
			createdAt: DateTime.now(),
			updatedAt: DateTime.now(),
			key: Buffer.alloc(32, "random key").toString("hex"),
			path: join(testDirPath, "file1"),
		}

		try {
			await kr.addCapability(cap)
			assert.fail()
		} catch {}
	})

	it("should accept adding a valid key-object", async function () {
		const kr = new KeyRing(join(testDirPath, "keyring1.txt"))

		const cap = {
			createdAt: DateTime.now(),
			updatedAt: DateTime.now(),
			key: Buffer.alloc(32, "random key").toString("hex"),
			path: join(testDirPath, "file1"),
			type: TYPE_WRITE,
		}

		try {
			await kr.addCapability(cap)
		} catch {
			assert.fail()
		}

        const keytype = "string"
		const actual = await kr.getCapabilityWithPathAndType(join(testDirPath, "file1"), TYPE_WRITE, keytype)

		assert.equal(JSON.stringify(cap), JSON.stringify(actual))
	})

	it("should remove key object", async function () {
		const kr = new KeyRing(join(testDirPath, "keyring2.txt"))

		const path = join(testDirPath, "file")
		const cap = {
			createdAt: DateTime.now(),
			updatedAt: DateTime.now(),
			key: Buffer.alloc(32, "random key").toString("hex"),
			path: path,
			type: TYPE_WRITE,
		}

		await kr.addCapability(cap)
        const keytype = "string"
		const capabilityActual = await kr.getCapabilityWithPathAndType(path, TYPE_WRITE, keytype)
		assert.isNotNull(capabilityActual)

		await kr.removeCapability(cap)
		const k1ActualAfterRemoval = await kr.getCapabilityWithPathAndType(path, TYPE_WRITE, keytype)
		assert.isNull(k1ActualAfterRemoval)
	})

    it("should remove key object by path and optional type", async function() {
        const kr = new KeyRing(join(testDirPath, "keyring.txt"))

        const path = join(testDirPath, "test-file.txt")

        const cap = {
			createdAt: DateTime.now(),
			updatedAt: DateTime.now(),
			key: Buffer.alloc(32, "random key").toString("hex"),
			path: path,
			type: TYPE_WRITE,
		}

        await kr.addCapability(cap)

        await kr.removeCapabilitiesWithPath(path)

        const actual = await kr.getCapabilitiesWithPath(path)
        assert.isEmpty(actual)
    })

    it("should remove key object by path and optional type", async function() {
        const kr = new KeyRing(join(testDirPath, "keyring.txt"))

        const path = join(testDirPath, "test-file.txt")

        const cap1 = {
			createdAt: DateTime.now(),
			updatedAt: DateTime.now(),
			key: Buffer.alloc(32, "random key").toString("hex"),
			path: path,
			type: TYPE_WRITE,
		}

        const cap2 = {
			createdAt: DateTime.now(),
			updatedAt: DateTime.now(),
			key: Buffer.alloc(32, "other random key").toString("hex"),
			path: path,
			type: TYPE_READ,
		}

        await kr.addCapability(cap1)
        await kr.addCapability(cap2)

        await kr.removeCapabilitiesWithPath(path, TYPE_WRITE)

        const keytype = "string"
        const actualWrite = await kr.getCapabilityWithPathAndType(path, TYPE_WRITE, keytype)
        const [ actualVerify ] = await kr.getCapabilitiesWithPath(path, keytype)

        assert.isNull(actualWrite)
        assert.equal(JSON.stringify(cap2), JSON.stringify(actualVerify))
    })

	it("should update all key objects with new path", async function () {
		const kr = new KeyRing(join(testDirPath, "keyring3.txt"))

		const oldPath = join(testDirPath, "initifial-file-name.txt")
		const newPath = join(testDirPath, "updated-file-name.txt")

		const cap1 = {
			createdAt: DateTime.now(),
			updatedAt: DateTime.now(),
			key: Buffer.alloc(32, "random key").toString("hex"),
			path: oldPath,
			type: TYPE_WRITE,
		}

        const cap2 = {
			createdAt: DateTime.now(),
			updatedAt: DateTime.now(),
			key: Buffer.alloc(32, "other random key").toString("hex"),
			path: oldPath,
			type: TYPE_READ,
		}

		await kr.addCapability(cap1)
        await kr.addCapability(cap2)
        await kr.updateCapabilitiesWithPath(oldPath, newPath)

        const keytype = "string"
		const [actual1, actual2] = await kr.getCapabilitiesWithPath(newPath, keytype)

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

		const cap1 = {
			createdAt: DateTime.now(),
			updatedAt: DateTime.now(),
			key: oldWriteKey,
			path: path,
			type: TYPE_WRITE,
		}

        const cap2 = {
			createdAt: DateTime.now(),
			updatedAt: DateTime.now(),
			key: verifyKey,
			path: path,
			type: TYPE_VERIFY
		}

		await kr.addCapability(cap1)
        await kr.addCapability(cap2)
		await kr.updateCapabilityKey(path, TYPE_WRITE, newWriteKey)


        const keytype = "buffer"
		const actualWrite = await kr.getCapabilityWithPathAndType(path, TYPE_WRITE, keytype)
        assert.isTrue(Buffer.compare(actualWrite.key, newWriteKey) === 0)
		assert.isTrue(actualWrite.createdAt < actualWrite.updatedAt)

        const actualVerify = await kr.getCapabilityWithPathAndType(path, TYPE_VERIFY, "string")
        assert.equal(actualVerify.key, verifyKey)
	})
})
