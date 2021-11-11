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
const fullPathLocal = path.join(__dirname, testDirName)

const fsp = new DropboxProvider(dropboxApp.accessToken, __dirname)

describe("FSP", function () {
	before("setup local test files and dropbox test-folder", async function () {
		// setup local test-dir if needed
		try {
			await fs.access(fullPathLocal)
		} catch (_) {
			try {
				await fs.mkdir(fullPathLocal)
			} catch (err) {
				assert.fail()
			}
		}

		try {
			// Create FSP test-directory if it does not already exist
			await fsp.createDirectory(testDirName)
		} catch (err) {
			// if 409 is returned, it means the folder already exist.
			if (err.status !== 409) {
				assert.fail()
			}
		}
	})

	after("tear-down local test files", async function () {
		// tear-down fsp test-directory
		try {
			await fsp.deleteDirectory(testDirName)
		} catch (err) {
			assert.fail()
		}

		// tear-down local test directory
		try {
			await fs.rm(fullPathLocal, { recursive: true, force: true })
		} catch (err) {
			assert.fail()
		}
	})

	it("longpolling should emit new entries when they are uploaded to the FSP", async function () {
		// This test sets up a listener for changes in a folder, and then checks if
		// the listener is called when a file is uploaded to the folder.
		// We test the listener by having it resolve a promise ('promiseResolve)
		// which the test is await'ing.

		const timeoutMs = 10 * 1000 // 10 seconds
		this.timeout(timeoutMs) // set this test to fail after 10 seconds

		const filename = "long-poll-test2.txt"

		var promiseResolve, promiseReject
		const promise = new Promise((resolve, reject) => {
			promiseResolve = resolve
			promiseReject = reject
		})

		// we expect this handler to be called when a new file upload to the test-folder has succeeded
		fsp.on(fsp.LONGPOLL_NEW_ENTRIES, ({ path, entries }) => {
            // check if the new entry is the one we just uploaded
			if (entries.length !== 1 || entries[0].name !== filename)
				promiseReject() // fail the test
			else {
				promiseResolve() // succeed the test
			}
		})

		await fsp.startLongpoll(testDirName)

		// Create and upload a test-file to trigger the listener
		const filepathLocal = path.join(fullPathLocal, filename)
		const filePathRemote = path.join(testDirName, filename)

		await fs.writeFile(filepathLocal, Date().toString())
		await fsp.upload(filePathRemote)

		try {
			await promise
			assert.isTrue(true)
		} catch (err) {
            assert.fail()
		} finally {
			fsp.stopLongpoll()
		}
	})
})
