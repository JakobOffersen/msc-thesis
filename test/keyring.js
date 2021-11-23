const assert = require("chai").assert
const path = require("path")
const fs = require("fs/promises")
const KeyRing = require("../keyring")

const testDirPath = path.join(__dirname, "keyrings")

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
		const kr = new KeyRing(path.join(testDirPath, "keyring1"))

		const k1 = {
			// should be rejected since it does not have a 'type' property
			createdAt: Date(),
			updatedAt: Date(),
			key: Buffer.alloc(32, "random key").toString("hex"),
			path: path.join(testDirPath, "file1"),
		}

		try {
			await kr.addKeyObject(k1)
			assert.fail()
		} catch {}
	})

	it("should accept adding a valid key-object", async function () {
		const kr = new KeyRing(path.join(testDirPath, "keyring1.txt"))

		const k1 = {
			// should be rejected since it does not have a 'type' property
			createdAt: Date(),
			updatedAt: Date(),
			key: Buffer.alloc(32, "random key").toString("hex"),
			path: path.join(testDirPath, "file1"),
			type: "write",
		}

		try {
			await kr.addKeyObject(k1)
		} catch {
			assert.fail()
		}

		const actual = await kr.getKeyObjectWithPath(
			path.join(testDirPath, "file1")
		)

		assert.equal(JSON.stringify(k1), JSON.stringify(actual))
	})

    it("should remove key object", async function() {
        const kr = new KeyRing(path.join(testDirPath, "keyring2.txt"))

        const p = path.join(testDirPath, "file")
        const k1 = {
			// should be rejected since it does not have a 'type' property
			createdAt: Date(),
			updatedAt: Date(),
			key: Buffer.alloc(32, "random key").toString("hex"),
			path: p,
			type: "write",
		}

        await kr.addKeyObject(k1)
        const k1Actual = await kr.getKeyObjectWithPath(p)
        assert.isNotNull(k1Actual)

        await kr.removeKeyObject(k1)
        const k1ActualAfterRemoval = await kr.getKeyObjectWithPath(p)
        assert.isNull(k1ActualAfterRemoval)
    })
})
