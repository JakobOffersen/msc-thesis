const assert = require("chai").assert
const { DropboxProvider } = require("../storage_providers/storage_provider")
const path = require("path")
const fs = require("fs/promises")
const { inversePromise } = require('./testUtil')

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
	before("setup local and remote test-folder", async function () {
		// setup local test-dir if needed
		try {
			await fs.access(fullPathLocal)
		} catch {
			await fs.mkdir(fullPathLocal)
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

    afterEach("Clear local and remote test-folder if needed", async function() {
        // Clear the local and remote folder
        const filenames = await fs.readdir(fullPathLocal)

        this.timeout(filenames.length * 3 * 1000) // allow for 3 seconds per filename needed to be deleted from FSP

        for (const filename of filenames) {
            await fs.unlink(path.join(fullPathLocal, filename))
            await fsp.delete(path.join(testDirName, filename))
        }
    })

	after("tear-down local test folder", async function () {
		// tear-down fsp test-directory
		try {
			await fsp.deleteDirectory(testDirName)
            console.log("after success")
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

		const { promise, promiseResolve, promiseReject } = inversePromise()

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

    it("longpolling should keep emiting file-changes when longpolling ", async function () {
		const timeoutMs = 10 * 1000 // 10 seconds
		this.timeout(timeoutMs) // set this test to fail after 10 seconds

        // Prepare local files
		const filename1 = "long-poll-test1.txt"
        const filename2 = "long-poll-test2.txt"
        await fs.writeFile(path.join(fullPathLocal, filename1), Date().toString())
        await fs.writeFile(path.join(fullPathLocal, filename2), Date().toString())

        const inverse1 = inversePromise()
        const inverse2 = inversePromise()
        inverse1.called = false

		fsp.on(fsp.LONGPOLL_NEW_ENTRIES, async ({ entries }) => {
            if (!inverse1.called) {
                // check the first upload
                inverse1.called = true
                if (entries.length === 1 && entries[0].name === filename1) {
                    inverse1.promiseResolve()
                    // upload the second file
                    await fsp.upload(path.join(testDirName, filename2))
                } else {
                    inverse1.promiseReject()
                }
            } else {
                // check the second upload
                if (entries.length === 1 && entries[0].name === filename2) {
                    inverse2.promiseResolve()
                } else {
                    inverse2.promiseReject()
                }
            }
		})

		await fsp.startLongpoll(testDirName)

		// Upload the file 'filename1' to trigger the listener
        try {
            await fsp.upload(path.join(testDirName, filename1))
        } catch (error) {
            console.log("TEST ERROR!!!!", error)
        }

		try {
			await inverse1.promise
            await inverse2.promise
			assert.isTrue(true)
		} catch (err) {
            assert.fail()
		} finally {
			fsp.stopLongpoll()
		}
	})
})
