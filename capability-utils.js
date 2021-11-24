const crypto = require('./crypto')
const KeyRing = require('./keyring')
const fs = require('fs/promises')
const { v4: uuidv4 } = require('uuid')
const { join } = require('path')

function generateCapabilitiesForPath(relativePath) {
    const read = crypto.makeSymmetricKey()
    const pair = crypto.makeEncryptionKeyPair()
    const write = pair.sk
    const verify = pair.pk

    return {
        read: {
            key: read.toString("hex"),
            path: relativePath,
            type: KeyRing.TYPE_READ
        },
        write: {
            key: write.toString("hex"),
            path: relativePath,
            type: KeyRing.TYPE_WRITE
        },
        verify: {
            key: verify.toString("hex"),
            path: relativePath,
            type: KeyRing.TYPE_VERIFY
        }
    }
}

/// returns name of the capability written locally in recipients postal box
async function createCapabilitiesInvite(capabilities, recipientPublicKey, postalboxPath) {
    const encoded = JSON.stringify(capabilities)
    const cipher = crypto.encryptWithPublicKey(encoded, recipientPublicKey)
    const randomNameOfCapabilitiesFile = uuidv4()
    const localPath = join(postalboxPath, recipientPublicKey.toString('hex'), randomNameOfCapabilitiesFile + ".capability")
    await fs.writeFile(localPath, cipher)
    return randomNameOfCapabilitiesFile
}

module.exports = {
    generateCapabilitiesForPath,
    createCapabilitiesInvite
}