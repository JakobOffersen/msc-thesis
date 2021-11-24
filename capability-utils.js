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

function createCapabilitiesInvite(capabilities, recipientPublicKey, relativePostalBoxPath) {
    const encoded = JSON.stringify(capabilities)
    const cipher = crypto.encryptWithPublicKey(encoded, recipientPublicKey)
    const randomNameOfCapabilitiesFile = uuidv4()
    const localPath = join(relativePostalBoxPath, recipientPublicKey.toString('hex'), randomNameOfCapabilitiesFile + ".capability")
    return { cipher, path : localPath }
}

function decryptCapabilities(cipher, recipientPublicKey, recipientPrivateKey) {
    const decrypted = crypto.decryptWithPublicKey(cipher, recipientPublicKey, recipientPrivateKey)
    const decoded = JSON.parse(decrypted)
    return decoded
}

module.exports = {
    generateCapabilitiesForPath,
    createCapabilitiesInvite,
    decryptCapabilities
}