const assert = require("chai").assert
const { join } = require("path")
const fs = require("fs/promises")
const crypto = require("../crypto")
const { generateCapabilitiesForPath, decryptCapabilities, encryptCapabilities } = require("../key-management/capability-utils")
const { CAPABILITY_TYPE_READ, CAPABILITY_TYPE_WRITE, CAPABILITY_TYPE_VERIFY, FSP_ACCESS_TOKEN } = require("../constants")
const { v4: uuidv4 } = require("uuid")
const { tmpdir } = require("os")
const { Dropbox } = require("dropbox")

const testDirName = "/keyring-system-test"
const tempDir = tmpdir()

const dbx = new Dropbox({ accessToken: FSP_ACCESS_TOKEN })

describe("Keyring system test", function () {
    before("setup local and remote test-folder", async function () {
        // setup local test-dir if needed
        try {
            await fs.access(join(tempDir, testDirName))
        } catch {
            await fs.mkdir(join(tempDir, testDirName))
        }

        try {
            // Create FSP test-directory if it does not already exist
            await dbx.filesCreateFolderV2({ path: testDirName })
        } catch (err) {
            // if 409 is returned, it means the folder already exist.
            if (err.status !== 409) {
                throw err
            }
        }
    })

    beforeEach("Clear local and remote test-folder if necessary", async function () {
        // Clear the local and remote folder
        this.timeout(5 * 1000) // allow for 5 seconds per filename needed to be deleted from FSP
        // Clear remote folder by deleting it and creating it again
        await dbx.filesDeleteV2({ path: testDirName })
        await dbx.filesCreateFolderV2({ path: testDirName })
        await dbx.filesCreateFolderV2({ path: join(testDirName, "users") })

        // clear local folder by removing it and creating it again
        const localTestPath = join(tempDir, testDirName)
        await fs.rm(localTestPath, { recursive: true, force: true })
        await fs.mkdir(localTestPath)
        await fs.mkdir(join(localTestPath, "users"))
    })

    after("tear down local test folder", async function () {
        this.timeout(10 * 1000)

        // tear-down fsp test-directory
        await dbx.filesDeleteV2({ path: testDirName })

        // tear-down local test directory
        await fs.rm(join(tempDir, testDirName), { recursive: true, force: true })
    })

    it("one user shares capabilities with another user", async function () {
        const user = crypto.makeEncryptionKeyPair() // the recipient

        const filename = "file-to-be-shared.txt"
        const capabilites = generateCapabilitiesForPath(join(testDirName, filename))

        const encryptedCapabilities = crypto.encryptAsymmetric(JSON.stringify(capabilites), user.pk)

        // we imagine 'encryptedCapabilities' is shared with user2
        const decrypted = crypto.decryptAsymmetric(encryptedCapabilities, user.pk, user.sk)

        assert.equal(decrypted, JSON.stringify(capabilites))
    })

    it("one user shares capabilities with another user using their postalbox", async function () {
        this.timeout(10 * 1000)
        // setup recipient and their postal box
        const recipient = crypto.makeEncryptionKeyPair()
        const recipientPostalBox = join(testDirName, "users", recipient.pk.toString("hex"))
        await fs.mkdir(join(tempDir, recipientPostalBox))

        const filename = "file-to-be-shared.txt"

        // Generate capabilities
        const capabilities = generateCapabilitiesForPath(join(testDirName, filename))
        const encryptedCapabilities = crypto.encryptAsymmetric(JSON.stringify(capabilities), recipient.pk)
        const capabilityPath = join(recipientPostalBox, "capability.txt")
        // upload the capability to recipients postalbox
        await dbx.filesUpload({ path: capabilityPath, mode: "overwrite", contents: encryptedCapabilities })

        // actions made by recipient. We assume that the recipient is notified of the newly added file to their postal box
        const cipher = (await dbx.filesDownload({ path: capabilityPath })).result
        const decrypted = crypto.decryptAsymmetric(cipher.fileBinary, recipient.pk, recipient.sk)

        assert.equal(decrypted, JSON.stringify(capabilities))
    })

    it("two users read and write to shared file", async function () {
        this.timeout(20 * 1000)

        const recipient = crypto.makeEncryptionKeyPair()

        // setup recipient postal box
        const postalBoxPath = join(testDirName, "users")
        const recipientPostalBox = join(postalBoxPath, recipient.pk.toString("hex"))
        await fs.mkdir(join(tempDir, recipientPostalBox))

        // setup file-paths
        const filename = "filename.txt"
        const relativeFilePath = join(testDirName, filename)
        const fullFilePath = join(tempDir, relativeFilePath)

        // sender generates capabilities for the file and encrypts them in a file (with random filename)
        const capabilites = generateCapabilitiesForPath(join(testDirName, filename))
        const readCap = capabilites.find(cap => cap.type === CAPABILITY_TYPE_READ)
        const writeCap = capabilites.find(cap => cap.type === CAPABILITY_TYPE_WRITE)
        const encryptedCapabilities = encryptCapabilities(capabilites, recipient.pk)
        const randomNameOfCapabilitiesFile = uuidv4()
        const relativePathEncryptedCapabilities = join(postalBoxPath, recipient.pk.toString("hex"), randomNameOfCapabilitiesFile + ".capability")

        // sender uploads encrypted capabilities to recipient
        await dbx.filesUpload({ path: relativePathEncryptedCapabilities, mode: "overwrite", contents: encryptedCapabilities })

        // sender writes to the file
        const plain = "hello, anyone there?"
        const cipher = crypto.encrypt(plain, readCap.key)

        const signedCipher = crypto.signCombined(cipher, writeCap.key)

        // sender uploads the file
        await dbx.filesUpload({ path: relativeFilePath, mode: "overwrite", contents: signedCipher })

        // recipient downloads capabilities. Here it is assumed that the recipient has listened for changes and has been notified of the change
        const encryptedFile = (await dbx.filesDownload({ path: relativePathEncryptedCapabilities })).result

        // recipient decrypts capabilities
        const recipientCapabilities = decryptCapabilities(encryptedFile.fileBinary, recipient.pk, recipient.sk)
        const recipientReadCap = recipientCapabilities.find(c => c.type === CAPABILITY_TYPE_READ)
        const recipientVerifyCap = recipientCapabilities.find(c => c.type === CAPABILITY_TYPE_VERIFY)

        // recipient downloads the file from the received capabilities
        const signedCipherFile = (await dbx.filesDownload({ path: recipientReadCap.path })).result

        // recipient verifies signature if downloaded file using verify-capability
        const { verified, message: cipherContent } = crypto.verifyCombined(signedCipherFile.fileBinary, recipientVerifyCap.key)

        assert.isTrue(verified)

        // recipient decrypts file using read-capability
        const decryptedFileContent = crypto.decrypt(cipherContent, recipientReadCap.key)

        assert.equal(decryptedFileContent, plain)
    })
})
