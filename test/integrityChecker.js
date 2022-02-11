const assert = require("chai").assert
const path = require("path")
const fs = require("fs/promises")
const { DropboxProvider } = require("../storage_providers/storage_provider")
const {
	inversePromise,
	clearLocalAndRemoteTestFolderIfNecessary,
	setupLocalAndRemoteTestFolder,
	teardownLocalAndRemoteTestFolder,
} = require("./testUtil")
const IntegrityChecker = require("../daemons/integrity-checker")
const { tmpdir } = require("os")

const dropboxApp = {
	key: "b2gdry5rbkoq1jm",
	secret: "0ye07t7186lht1e",
	accessToken:
		"rxnh5lxxqU8AAAAAAAAAATBaiYe1b-uzEIe4KlOijCQD-Faam2Bx5ykV6XldV86W",
}

const testDirName = "integrityChecker"
const tempDir = tmpdir()

const fsp = new DropboxProvider(dropboxApp.accessToken, tempDir)
const dropboxClientPath = "/Users/jakoboffersen/Dropbox"

describe.skip("integrity-checker", function () {
	before("setup local and remote test-folder", async function () {
		await setupLocalAndRemoteTestFolder(tempDir, testDirName, fsp)
	})

	afterEach(
		"Clear local and remote test-folder if necessary",
		async function () {
			this.timeout(5 * 1000) // allow for 5 seconds per filename needed to be deleted from FSP
			await clearLocalAndRemoteTestFolderIfNecessary(
				tempDir,
				testDirName,
				fsp
			)
		}
	)

	after("tear down local test folder", async function () {
		this.timeout(10 * 1000)
		await teardownLocalAndRemoteTestFolder(tempDir, testDirName, fsp)
	})

	it("should rollback a file not meeting a condition until to the most-recent version meeting that condition", async function () {
		this.timeout(30 * 1000) // fail after 15 seconds

		const { promise, reject, resolve } = inversePromise()
		// create and upload initial, valid file. Note that we write the file to
		// a path outside of our local dropbox-client-folder.
		// This mocks an update coming from another party through the fsp.
		const filename = "filename.txt"
		const filecontent = Buffer.from("initial and valid content")
		const relativeFilePath = path.join(testDirName, filename)
		const localFullPath = path.join(tempDir, relativeFilePath)
		await fs.writeFile(localFullPath, filecontent)
		await fsp.upload(relativeFilePath)

		// setup rollbacker to watch our local dropbox-client directory
		// 'predicate' returns 'true' if the revision's content is equal to 'filecontent'
		const predicate = ({ content }) => {
			return Buffer.compare(content, filecontent) === 0
		}
		const integrityChecker = new IntegrityChecker({
			fsp,
			predicate,
			watchPath: dropboxClientPath,
		})

		integrityChecker.on(IntegrityChecker.READY, async () => {
			// Trigger the rollbacker by mocking an invalid write to the same file
			await fs.writeFile(localFullPath, Buffer.from("invalid update"))
			await fsp.upload(relativeFilePath)
		})

		integrityChecker.on(IntegrityChecker.CONFLICT_RESOLUTION_FAILED, () => {
			reject()
		})
		integrityChecker.on(IntegrityChecker.CONFLICT_RESOLUTION_SUCCEEDED, ({ remotePath }) => {
			remotePath === relativeFilePath ? resolve() : reject()
		})

		try {
			await promise
		} catch {
			assert.fail()
		} finally {
			await integrityChecker.stopWatching()
		}
	})
})
