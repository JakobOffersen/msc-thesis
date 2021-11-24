const crypto = require('./crypto')
const KeyRing = require('./keyring')
const fs = require('fs/promises')
const { v4: uuidv4 } = require('uuid')
const { join } = require('path')

function generateCapabilitiesForPath(relativePath) {
    const read = crypto.makeSymmetricKey()
    const pair = crypto.makeSigningKeyPair()

    return {
        read: {
            key: read,
            path: relativePath,
            type: KeyRing.TYPE_READ
        },
        write: {
            key: pair.sk,
            path: relativePath,
            type: KeyRing.TYPE_WRITE
        },
        verify: {
            key: pair.pk,
            path: relativePath,
            type: KeyRing.TYPE_VERIFY
        }
    }
}

function createCapabilitiesInvite(capabilities, recipientPublicKey, relativePostalBoxPath) {
    const encoded = encode(capabilities)
    const cipher = crypto.encryptWithPublicKey(encoded, recipientPublicKey)
    const randomNameOfCapabilitiesFile = uuidv4()
    const localPath = join(relativePostalBoxPath, recipientPublicKey.toString('hex'), randomNameOfCapabilitiesFile + ".capability")
    return { cipher, path : localPath }
}

function decryptCapabilities(cipher, recipientPublicKey, recipientPrivateKey) {
    const decrypted = crypto.decryptWithPublicKey(cipher, recipientPublicKey, recipientPrivateKey)
    const decoded = decode(decrypted)
    return decoded
}

function encode(capabilities) {
    const cloned = clone(capabilities)
    if (!!cloned.read) cloned.read.key = cloned.read.key.toString("hex")
    if (!!cloned.write) cloned.write.key = cloned.write.key.toString("hex")
    if (!!cloned.verify) cloned.verify.key = cloned.verify.key.toString("hex")

    return JSON.stringify(cloned)
}

function decode(encoded) {
    const decoded = JSON.parse(encoded)

    if (!!decoded.read) decoded.read.key = Buffer.from(decoded.read.key, "hex")
    if (!!decoded.write) decoded.write.key = Buffer.from(decoded.write.key, "hex")
    if (!!decoded.verify) decoded.verify.key = Buffer.from(decoded.verify.key, "hex")
    return decoded
}

function clone(capabilities) {
    let clone = {}
    for (let capability in capabilities) {
        clone[capability] = {}
        for (let property in capabilities[capability]) {
            clone[capability][property] = capabilities[capability][property]
        }
    }
    return clone
}

module.exports = {
    generateCapabilitiesForPath,
    createCapabilitiesInvite,
    decryptCapabilities
}