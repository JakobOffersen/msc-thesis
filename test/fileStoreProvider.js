const assert = require("chai").assert
const { DropboxProvider } = require("../storage_providers/storage_provider")
const path = require("path")
const fs = require("fs/promises")
const { inversePromise } = require("./testUtil")

const dropboxApp = {
	key: "b2gdry5rbkoq1jm",
	secret: "0ye07t7186lht1e",
	accessToken:
		"rxnh5lxxqU8AAAAAAAAAATBaiYe1b-uzEIe4KlOijCQD-Faam2Bx5ykV6XldV86W",
}

// local paths
const longpollDirName = "test-longpoll"
const rollbackDirName = "test-rollback"
const longpollFullPathLocal = path.join(__dirname, longpollDirName)

const fsp = new DropboxProvider(dropboxApp.accessToken, __dirname)

// before(each)/after(each) handlers
const setupLocalAndRemoteTestFolder = async (testFolderName) => {
	// setup local test-dir if needed
	try {
		await fs.access(path.join(__dirname, testFolderName))
	} catch {
		await fs.mkdir(path.join(__dirname, testFolderName))
	}

	try {
		// Create FSP test-directory if it does not already exist
		await fsp.createDirectory(testFolderName)
	} catch (err) {
		// if 409 is returned, it means the folder already exist.
		if (err.status !== 409) {
			throw err
		}
	}
}

const clearLocalAndRemoteTestFolderIfNecessary = async (testFolderName) => {
	// Clear remote folder by deleting it and creating it again
	await fsp.delete(testFolderName)
	await fsp.createDirectory(testFolderName)

	// clear local folder by removing it and creating it again
    const localTestPath = path.join(__dirname, testFolderName)
	await fs.rm(localTestPath, { recursive: true, force: true })
	await fs.mkdir(localTestPath)
}

const teardownLocalAndRemoteTestFolder = async (testFolderName) => {
	// tear-down fsp test-directory
	await fsp.deleteDirectory(testFolderName)

	// tear-down local test directory
	await fs.rm(path.join(__dirname, testFolderName), { recursive: true, force: true })
}

describe("FSP", function () {
	describe("long poll", function () {
		before("setup local and remote test-folder", async function () {
			await setupLocalAndRemoteTestFolder(longpollDirName)
		})

		afterEach(
			"Clear local and remote test-folder if necessary",
			async function () {
				// Clear the local and remote folder
				this.timeout(5 * 1000) // allow for 3 seconds per filename needed to be deleted from FSP
				await clearLocalAndRemoteTestFolderIfNecessary(longpollDirName)
			}
		)

		after("tear-down local test folder", async function () {
            this.timeout(10 * 1000)
			await teardownLocalAndRemoteTestFolder(longpollDirName)
		})

		// This test sets up a listener for changes in a folder, and then checks if
		// the listener is called when a file is uploaded to the folder.
		// We test the listener by having it resolve a promise ('promiseResolve)
		// which the test is await'ing.
		it("longpolling should emit new entries when they are uploaded to the FSP", async function () {
			const timeoutMs = 10 * 1000 // 10 seconds
			this.timeout(timeoutMs) // set this test to fail after 10 seconds

			const filename = "long-poll-test2.txt"

			const { promise, resolve, reject } = inversePromise()

			const callback = async ({ entries }) => {
				// check if the new entry is the one we just uploaded
				if (entries.length !== 1 || entries[0].name !== filename)
					reject()
				// fail the test
				else {
					resolve() // succeed the test
				}
			}
			// we expect this handler to be called when a new file upload to the test-folder has succeeded
			fsp.on(fsp.LONGPOLL_NEW_ENTRIES, callback)

			await fsp.startLongpoll(longpollDirName)

			// Create and upload a test-file to trigger the listener
			const filepathLocal = path.join(longpollFullPathLocal, filename)
			const filePathRemote = path.join(longpollDirName, filename)

			await fs.writeFile(filepathLocal, Date().toString())
			await fsp.upload(filePathRemote)

			try {
				await promise // This blocks until reject/resolve is called
				assert.isTrue(true)
			} catch {
				assert.fail()
			} finally {
				// Avoid interference with other tests by stopping polling and removing the added listener
				fsp.stopLongpoll()
				fsp.removeListener(fsp.LONGPOLL_NEW_ENTRIES, callback)
			}
		})

		// This test sets up a listener for changes in a folder, and then checks if the
		// listener is called two times for two changes to the folder.
		// The flow is:
		// 1) create the two local files to be uploaded later
		// 2) setup and register the listener-callback
		// 3) Upload the first file
		// 4) Wait for the listener to be called with the uploaded file. If success, upload the second file
		// 5) Wait for the listener to be called again with the second uploaded file. If sucess, we're done.
		// The waiting in step 4 and 5 happen with inverted promises that are rejected/resolved from the outsite.
		it("longpolling should keep emiting file-changes when longpolling ", async function () {
			const timeoutMs = 10 * 1000 // 10 seconds
			this.timeout(timeoutMs) // set this test to fail after 10 seconds

			// Prepare local files
			const filename1 = "long-poll-test1.txt"
			const filename2 = "long-poll-test2.txt"
			await fs.writeFile(
				path.join(longpollFullPathLocal, filename1),
				Date().toString()
			)
			await fs.writeFile(
				path.join(longpollFullPathLocal, filename2),
				Date().toString()
			)

			const inversePromise1 = inversePromise()
			const inversePromise2 = inversePromise()
			inversePromise1.called = false

			const callback = async ({ entries }) => {
				if (!inversePromise1.called) {
					// check the first upload
					inversePromise1.called = true
					if (entries.length === 1 && entries[0].name === filename1) {
						inversePromise1.resolve() // mark the first emit as successful
						await fsp.upload(path.join(longpollDirName, filename2))
					} else {
						inversePromise1.reject() // mark the first emit as failed
					}
				} else {
					// check the second upload
					if (entries.length === 1 && entries[0].name === filename2) {
						inversePromise2.resolve() // mark the second emit as successful
					} else {
						inversePromise2.reject() // mark the second emit as failed
					}
				}
			}

			fsp.on(fsp.LONGPOLL_NEW_ENTRIES, callback)

			await fsp.startLongpoll(longpollDirName)

			// Upload the file 'filename1' to trigger the callback
			await fsp.upload(path.join(longpollDirName, filename1))

			try {
				await inversePromise1.promise // this blocks until reject/resolve is called when the first file is emitted
				await inversePromise2.promise // this blocks until reject/resolve is called when the second file is emitted
				assert.isTrue(true)
			} catch (err) {
				assert.fail()
			} finally {
				// Avoid interference with other tests by stopping polling and removing the added listener
				fsp.stopLongpoll()
				fsp.removeListener(fsp.LONGPOLL_NEW_ENTRIES, callback)
			}
		})

		it("longpolling should emit when a subfolder is created", async function () {
			const timeoutMs = 10 * 1000
			this.timeout(timeoutMs) // set this test to fail after 10 seconds
			const { promise, reject, resolve } = inversePromise()

			const dirname = "dirname"

			function entryIsDirectoryWithName(entry, expectedName) {
				return entry[".tag"] === "folder" && entry.name === expectedName
			}

			const callback = async ({ entries }) => {
				if (
					entries.length === 1 &&
					entryIsDirectoryWithName(entries[0], dirname)
				) {
					resolve() // mark the emit as successful
				} else {
					const errorMessage =
						"Expected received entry to be a directory, but received " +
						entries[0]
					reject(errorMessage) // markfirst emit as failed
				}
			}

			fsp.on(fsp.LONGPOLL_NEW_ENTRIES, callback)

			try {
				await fsp.startLongpoll(longpollDirName)
				// create the new directory to trigger the callback
				await fsp.createDirectory(path.join(longpollDirName, dirname))
				await promise
				assert.isTrue(true)
			} catch (err) {
				console.dir(err)
				assert.fail()
			} finally {
				fsp.stopLongpoll()
				fsp.removeListener(fsp.LONGPOLL_NEW_ENTRIES, callback)
			}
		})

		it("longpolling should emit when a deep-change occurs", async function () {
			const timeoutMs = 10 * 1000
			this.timeout(timeoutMs) // set this test to fail after 10 seconds
			const { promise, reject, resolve } = inversePromise()

			const dirname = "dirname"
			const filename = "filename"
			const subfolderPathLocal = path.join(longpollFullPathLocal, dirname)
			const subfolderPathRemote = path.join(longpollDirName, dirname)

			try {
				// setup sub-folder and sub-file
				await fs.mkdir(subfolderPathLocal)
				await fs.writeFile(
					path.join(subfolderPathLocal, filename),
					Date.toString()
				)

				// setup remote subfolder
				await fsp.createDirectory(subfolderPathRemote)
			} catch (err) {
				console.dir(err, { maxArrayLength: null })
				return assert.fail(err)
			}

			// setup longpoll
			const callback = async ({ entries }) => {
				//TODO: Check if entries include the file named "filename" in the subfolder
				resolve()
			}
			fsp.on(fsp.LONGPOLL_NEW_ENTRIES, callback)

			try {
				await fsp.startLongpoll(longpollDirName) // listen to parent-folder

				// upload test-file in sub-folder to trigger
				await fsp.upload(path.join(subfolderPathRemote, filename))
				await promise
			} catch (err) {
				assert.fail(err)
			} finally {
				fsp.stopLongpoll()
				fsp.removeListener(fsp.LONGPOLL_NEW_ENTRIES, callback)
			}
		})
	})

    describe("rollback", function () {
        before("setup local and remote test-folder", async function () {
			await setupLocalAndRemoteTestFolder(rollbackDirName)
		})

		afterEach(
			"Clear local and remote test-folder if necessary",
			async function () {
				// Clear the local and remote folder
				this.timeout(5 * 1000) // allow for 3 seconds per filename needed to be deleted from FSP
				await clearLocalAndRemoteTestFolderIfNecessary(rollbackDirName)
			}
		)

		after("tear-down local test folder", async function () {
            this.timeout(10 * 1000)
			await teardownLocalAndRemoteTestFolder(rollbackDirName)
		})

		it("rollback file with ID to latest non-deleted version", async function () {
			// We upload a file
		})
	})
})
