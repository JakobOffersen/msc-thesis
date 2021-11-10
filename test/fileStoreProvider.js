const assert = require("chai").assert
const { DropboxProvider } = require("../storage_providers/storage_provider")
const path = require("path")
const fs = require("fs/promises")

const dropboxApp = {
	key: "b2gdry5rbkoq1jm",
	secret: "0ye07t7186lht1e",
	accessToken:
		"rxnh5lxxqU8AAAAAAAAAATBaiYe1b-uzEIe4KlOijCQD-Faam2Bx5ykV6XldV86W",
}

// local paths
const testDirName = "test-longpoll"
const fullTestPathLocal = path.join(__dirname, testDirName)
const filename = "longpoll-test1.txt"

// FSP paths
const rootPathFSP = "/"
const fullTestPathFSP = path.join("/", testDirName)

const fsp = new DropboxProvider(dropboxApp.accessToken, rootPathFSP)

describe("FSP", function () {
	before("setup local test files and dropbox test-folder", async function () {
		// setup test-dir if needed
		try {
			await fs.access(fullTestPathLocal)
		} catch (err) {
			try {
				await fs.mkdir(fullTestPathLocal)
			} catch (err) {
				assert.fail()
			}
		}

		try {
			const filepath = path.join(fullTestPathLocal, filename)
			await fs.open(filepath, "w+")

			// Create FSP test-directory
			await fsp.createDirectory(fullTestPathFSP)
		} catch (err) {
			assert.fail()
		}
	})

	after("tear-down local test files", async function () {
		// tear-down fsp test-directory
		try {
			await fsp.deleteDirectory(fullTestPathFSP)
		} catch (err) {
			assert.fail()
		}

		// tear-down local test directory
		try {
			await fs.rm(fullTestPathLocal, { recursive: true, force: true })
		} catch (err) {
			assert.fail()
		}
	})

	// it("should upload the local file to dropbox", async function () {
	// 	try {
	// 		const filepath = path.join(fullTestPathLocal, filename)
	// 		await fsp.upload(filepath)
	// 	} catch (err) {
	// 		assert.fail("file upload failed")
	// 	}
	// })

	it("should trigger longpoll when a new file is uploaded to test-folder", async function () {
		// setup longpoll
		fsp.longpoll(fullTestPathFSP).then((response) => {
			assert.isTrue(response.result.changes)
		})

		// upload a new file to trigger the longpoll
		const filename = "long-poll-test2.txt"
		const filepathLocal = path.join(fullTestPathLocal, filename)

		fs.open(filepathLocal, "w+")
			//.then(fsp.upload(filepathLocal))
			.catch(() => assert.fail())
	})
})
