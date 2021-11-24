const crypto = require('./crypto')
const KeyRing = require('./keyring')

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

module.exports = {
    generateCapabilitiesForPath
}