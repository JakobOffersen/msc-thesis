const assert = require("chai").assert
const { DropboxProvider } = require("../storage_providers/storage_provider")
const { join } = require("path")
const fs = require("fs/promises")
const {
	inversePromise,
	clearLocalAndRemoteTestFolderIfNecessary,
	setupLocalAndRemoteTestFolder,
	teardownLocalAndRemoteTestFolder,
} = require("./testUtil")
const KeyRing = require("../keyring")
const crypto = require("../crypto")
const { generateCapabilitiesForPath, createCapabilitiesInvite } = require("../capability-utils")

const dropboxAccessToken =
	"rxnh5lxxqU8AAAAAAAAAATBaiYe1b-uzEIe4KlOijCQD-Faam2Bx5ykV6XldV86W"
const testDirName = "keyring-system-test"

const fsp = new DropboxProvider(dropboxAccessToken, __dirname)

describe("Keyring system test", function () {
	before("setup local and remote test-folder", async function () {
		await setupLocalAndRemoteTestFolder(__dirname, testDirName, fsp)
	})

	beforeEach(
		"Clear local and remote test-folder if necessary",
		async function () {
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
		}
	)

	after("tear-down local test folder", async function () {
		this.timeout(10 * 1000)
		await teardownLocalAndRemoteTestFolder(__dirname, testDirName, fsp)
	})

	it("one user shares capabilities with another user", async function () {
		const user = crypto.makeEncryptionKeyPair() // the recipient

		const filename = "file-to-be-shared.txt"
		const capabilites = generateCapabilitiesForPath(
			join(testDirName, filename)
		)

		const encryptedCapabilities = crypto.encryptWithPublicKey(
			JSON.stringify(capabilites),
			user.pk
		)

		// we imagine 'encryptedCapabilities' is shared with user2
		const decrypted = crypto.decryptWithPublicKey(
			encryptedCapabilities,
			user.pk,
			user.sk
		)

		assert.equal(decrypted, JSON.stringify(capabilites))
	})

	it("one user shares capabilities with another user using their postalbox", async function () {
		this.timeout(10 * 1000)
		// setup recipient and their postal box
		const recipient = crypto.makeEncryptionKeyPair()
		const recipientPostalBox = join(
			testDirName,
			"users",
			recipient.pk.toString("hex")
		)
		await fs.mkdir(join(__dirname, recipientPostalBox))

		// Actions made by sender
		const filename = "file-to-be-shared.txt"

		// Generate capabilities
		const capabilites = generateCapabilitiesForPath(
			join(testDirName, filename)
		)
		const encryptedCapabilities = crypto.encryptWithPublicKey(
			JSON.stringify(capabilites),
			recipient.pk
		)
		await fs.writeFile(
			join(__dirname, recipientPostalBox, "capability.txt"),
			encryptedCapabilities
		)

		// upload the capability to recipients postalbox
		await fsp.upload(join(recipientPostalBox, "capability.txt"))

		// actions made by recipient. We assume that the recipient is notified of the newly added file to their postal box
		const cipher = await fsp.downloadFile(
			join(recipientPostalBox, "capability.txt"),
			{ shouldWriteToDisk: false }
		)
		const decrypted = crypto.decryptWithPublicKey(
			cipher.fileBinary,
			recipient.pk,
			recipient.sk
		)

		assert.equal(decrypted, JSON.stringify(capabilites))
	})

	it("two users read and write to shared file", async function () {
		this.timeout(10 * 1000)

		const recipient = crypto.makeEncryptionKeyPair()

		// setup recipient postal box
		const recipientPostalBox = join(
			testDirName,
			"users",
			recipient.pk.toString("hex")
		)

		await fs.mkdir(join(__dirname, recipientPostalBox))

		const filename = "filename.txt"

		// sender generates capabilities
		const capabilites = generateCapabilitiesForPath(
			join(testDirName, filename)
		)
        // sender writes (locally) a capability invite for the recipient. The name of the file is returned
		const nameOfCapabilityFile = await createCapabilitiesInvite(capabilites, recipient.pk, join(__dirname, testDirName, "users"))

		// sender uploads capabilities to recipient
		await fsp.upload(join(recipientPostalBox, nameOfCapabilityFile + ".capability"))

		// sender writes to the file
		const plain = "hello, anyone there?"
		const cipher = crypto.encrypt(
			plain,
			Buffer.from(capabilites.read.key, "hex")
		)
		await fs.writeFile(join(__dirname, testDirName, filename), cipher)

		// sender uploads the file
		await fsp.upload(join(testDirName, filename))

		// recipient downloads capabilities
		const cipherCapabilities = await fsp.downloadFile(
			join(recipientPostalBox, nameOfCapabilityFile + ".capability"),
			{ shouldWriteToDisk: false }
		)
		const recipientCapabilitiesData = crypto.decryptWithPublicKey(
			cipherCapabilities.fileBinary,
			recipient.pk,
			recipient.sk
		)

        const recipientCapabilities = JSON.parse(recipientCapabilitiesData)

		// recipient downloads the file from the received capabilities
		const cipherFile = await fsp.downloadFile(
			recipientCapabilities.read.path,
			{ shouldWriteToDisk: false }
		)
		const decryptedFile = crypto.decrypt(
			cipherFile.fileBinary,
			Buffer.from(recipientCapabilities.read.key, "hex")
		)

		assert.equal(decryptedFile, plain)
	})
})
