const assert = require("chai").assert
const { DropboxProvider } = require("../storage_providers/storage_provider")
const { join } = require("path")
const fs = require("fs/promises")
const { setupLocalAndRemoteTestFolder, teardownLocalAndRemoteTestFolder } = require("./testUtil")
const crypto = require("../crypto")
const { generateCapabilitiesForPath, decryptCapabilities, encryptCapabilities, TYPE_READ, TYPE_VERIFY, TYPE_WRITE } = require("../capability-utils")
const { v4: uuidv4 } = require("uuid")
const KeyRing = require("./keyring")

const dropboxAccessToken = "rxnh5lxxqU8AAAAAAAAAATBaiYe1b-uzEIe4KlOijCQD-Faam2Bx5ykV6XldV86W"
const testDirName = "keyring-system-test"

const fsp = new DropboxProvider(dropboxAccessToken, __dirname)

describe("Keyring system test", function () {
	before("setup local and remote test-folder", async function () {
		await setupLocalAndRemoteTestFolder(__dirname, testDirName, fsp)
	})

	beforeEach("Clear local and remote test-folder if necessary", async function () {
		// Clear the local and remote folder
		this.timeout(5 * 1000) // allow for 5 seconds per filename needed to be deleted from FSP
		// Clear remote folder by deleting it and creating it again
		await fsp.deleteDirectory(testDirName)
		await fsp.createDirectory(testDirName)
		await fsp.createDirectory(join(testDirName, "users"))

		// clear local folder by removing it and creating it again
		const localTestPath = join(__dirname, testDirName)
		await fs.rm(localTestPath, { recursive: true, force: true })
		await fs.mkdir(localTestPath)
		await fs.mkdir(join(localTestPath, "users"))
	})

	after("tear-down local test folder", async function () {
		this.timeout(10 * 1000)
		await teardownLocalAndRemoteTestFolder(__dirname, testDirName, fsp)
	})

	it("one user shares capabilities with another user", async function () {
		const user = crypto.makeEncryptionKeyPair() // the recipient

		const filename = "file-to-be-shared.txt"
		const capabilites = generateCapabilitiesForPath(join(testDirName, filename))

		const encryptedCapabilities = crypto.encryptWithPublicKey(JSON.stringify(capabilites), user.pk)

		// we imagine 'encryptedCapabilities' is shared with user2
		const decrypted = crypto.decryptWithPublicKey(encryptedCapabilities, user.pk, user.sk)

		assert.equal(decrypted, JSON.stringify(capabilites))
	})

	it("one user shares capabilities with another user using their postalbox", async function () {
		this.timeout(10 * 1000)
		// setup recipient and their postal box
		const recipient = crypto.makeEncryptionKeyPair()
		const recipientPostalBox = join(testDirName, "users", recipient.pk.toString("hex"))
		await fs.mkdir(join(__dirname, recipientPostalBox))

		// Actions made by sender
		const filename = "file-to-be-shared.txt"

		// Generate capabilities
		const capabilites = generateCapabilitiesForPath(join(testDirName, filename))
		const encryptedCapabilities = crypto.encryptWithPublicKey(JSON.stringify(capabilites), recipient.pk)
		await fs.writeFile(join(__dirname, recipientPostalBox, "capability.txt"), encryptedCapabilities)

		// upload the capability to recipients postalbox
		await fsp.upload(join(recipientPostalBox, "capability.txt"))

		// actions made by recipient. We assume that the recipient is notified of the newly added file to their postal box
		const cipher = await fsp.downloadFile(join(recipientPostalBox, "capability.txt"), { shouldWriteToDisk: false })
		const decrypted = crypto.decryptWithPublicKey(cipher.fileBinary, recipient.pk, recipient.sk)

		assert.equal(decrypted, JSON.stringify(capabilites))
	})

	it("two users read and write to shared file", async function () {
		this.timeout(20 * 1000)

		const recipient = crypto.makeEncryptionKeyPair()

		// setup recipient postal box
		const postalBoxPath = join(testDirName, "users")
		const recipientPostalBox = join(postalBoxPath, recipient.pk.toString("hex"))
		await fs.mkdir(join(__dirname, recipientPostalBox))

		// setup file-paths
		const filename = "filename.txt"
		const relativeFilePath = join(testDirName, filename)
		const fullFilePath = join(__dirname, relativeFilePath)

		// sender generates capabilities for the file and encrypts them in a file (with random filename)
		const capabilites = generateCapabilitiesForPath(join(testDirName, filename))
		const readCap = capabilites.find((cap) => cap.type === TYPE_READ)
		const writeCap = capabilites.find((cap) => cap.type === TYPE_WRITE)
		const encryptedCapabilities = encryptCapabilities(capabilites, recipient.pk)
		const randomNameOfCapabilitiesFile = uuidv4()
		const relativePathEncryptedCapabilities = join(postalBoxPath, recipient.pk.toString("hex"), randomNameOfCapabilitiesFile + ".capability")
		await fs.writeFile(join(__dirname, relativePathEncryptedCapabilities), encryptedCapabilities)

		// sender uploads encrypted capabilities to recipient
		await fsp.upload(relativePathEncryptedCapabilities)

		// sender writes to the file
		const plain = "hello, anyone there?"
		const cipher = crypto.encrypt(plain, readCap.key)

		const signedCipher = crypto.signCombined(cipher, writeCap.key)

		await fs.writeFile(fullFilePath, signedCipher)

		// sender uploads the file
		await fsp.upload(relativeFilePath)

		// recipient downloads capabilities. Here it is assumed that the recipient has listened for changes and has been notified of the change
		const encryptedFile = await fsp.downloadFile(relativePathEncryptedCapabilities, {
			shouldWriteToDisk: false,
		})

		// recipient decrypts capabilities
		const recipientCapabilities = decryptCapabilities(encryptedFile.fileBinary, recipient.pk, recipient.sk)
		const recipientReadCap = recipientCapabilities.find((c) => c.type === TYPE_READ)
		const recipientVerifyCap = recipientCapabilities.find((c) => c.type === TYPE_VERIFY)

		// recipient downloads the file from the received capabilities
		const signedCipherFile = await fsp.downloadFile(recipientReadCap.path, { shouldWriteToDisk: false })

		// recipient verifies signature if downloaded file using verify-capability
		const { verified, message: cipherContent } = crypto.verifyCombined(signedCipherFile.fileBinary, recipientVerifyCap.key)

		assert.isTrue(verified)

		// recipient decrypts file using read-capability
		const decryptedFileContent = crypto.decrypt(cipherContent, recipientReadCap.key)

		assert.equal(decryptedFileContent, plain)
	})
})
