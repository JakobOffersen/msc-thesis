const crypto = require("../crypto")
const { DateTime } = require("luxon")
const { TYPE_READ, TYPE_WRITE, TYPE_VERIFY } = require('./config')

function generateCapabilitiesForPath(relativePath) {
    const read = crypto.makeSymmetricKey()
    const pair = crypto.makeSigningKeyPair()
    const createdAt = DateTime.now()
    const updatedAt = DateTime.now()

    return [
        {
            key: read,
            path: relativePath,
            type: TYPE_READ,
            createdAt,
            updatedAt
        },
        {
            key: pair.sk,
            path: relativePath,
            type: TYPE_WRITE,
            createdAt,
            updatedAt
        },
        {
            key: pair.pk,
            path: relativePath,
            type: TYPE_VERIFY,
            createdAt,
            updatedAt
        }
    ]
}

function encryptCapabilities(capabilities, recipientPublicKey) {
    const encoded = encode(capabilities)
    const cipher = crypto.encryptWithPublicKey(encoded, recipientPublicKey)
    return cipher
}

function decryptCapabilities(cipher, recipientPublicKey, recipientPrivateKey) {
    const decrypted = crypto.decryptWithPublicKey(cipher, recipientPublicKey, recipientPrivateKey)
    const decoded = decode(decrypted)
    return decoded
}

function encode(capabilities) {
    const cloned = cloneAll(capabilities, "string")
    return JSON.stringify(cloned)
}

function decode(encoded) {
    const decoded = JSON.parse(encoded)

    for (let cap of decoded) {
        cap.key = Buffer.from(cap.key, "hex")
    }
    return decoded
}

/// Returns a deep-clone of 'capabilities' where all keys are converted to be hex-encoded 'keytype' (defaults to 'buffer')
function cloneAll(capabilities, keytype = "buffer") {
    const cloned = _clone(capabilities)

    for (let cap of cloned) {
        cap.key = keytype.toLowerCase() === "string" ? cap.key.toString("hex") : Buffer.from(cap.key, "hex")
    }

    return cloned
}

function clone(capability, keytype = "buffer") {
    const cloned = { ...capability }
    cloned.key = keytype.toLowerCase() === "string" ? cloned.key.toString("hex") : Buffer.from(cloned.key, "hex")
    return cloned
}

/// Returns a deep-clone of array of capabilities
function _clone(capabilities) {
    return capabilities.map(cap => {
        return { ...cap }
    })
}

module.exports = {
    generateCapabilitiesForPath,
    encryptCapabilities,
    decryptCapabilities,
    cloneAll,
    clone
}
