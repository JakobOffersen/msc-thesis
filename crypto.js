const sodium = require('sodium-native')

function makeNonce() {
    let nonce = Buffer.alloc(sodium.crypto_secretbox_NONCEBYTES)
    sodium.randombytes_buf(nonce)
    return nonce
}

function makeSymmetricKey() {
    let nonce = Buffer.alloc(sodium.crypto_secretbox_KEYBYTES)
    sodium.randombytes_buf(nonce)
    return nonce
}

function encrypt(plainMessage, key) {
    let ciphertext = Buffer.alloc(plainMessage.length + sodium.crypto_secretbox_MACBYTES)
    let message = Buffer.from(plainMessage, 'utf-8')
    let nonce = makeNonce()

    sodium.crypto_secretbox_easy(ciphertext, message, nonce, key)

    return Buffer.concat([nonce, ciphertext]) // Prepend nonce to ciphertext
}

function decrypt(nonceAndCipher, key) {
    if (!Buffer.isBuffer(nonceAndCipher)) throw new Error("cipher must be of type Buffer")
    if (!Buffer.isBuffer(key)) throw new Error("key must be of type Buffer")
    if (key.length !== sodium.crypto_secretbox_KEYBYTES) throw new Error("key kust be of size " + sodium.crypto_secretbox_KEYBYTES)

    let { nonce, cipher } = _splitNonceAndCipher(nonceAndCipher)
    let plainTextBuffer = Buffer.alloc(cipher.length - sodium.crypto_secretbox_MACBYTES)
    if (sodium.crypto_secretbox_open_easy(plainTextBuffer, cipher, nonce, key)) {
        return plainTextBuffer
    } else {
        return null // Decryption failed.
    }
}

function _splitNonceAndCipher(cipherAndNonce) {
    // nonce is always prepended to cipher when encrypted.
    // Thus we copy the first part into 'nonce' and second part into 'ciphertext'
    let nonce = Buffer.alloc(sodium.crypto_secretbox_NONCEBYTES)
    let cipher = Buffer.alloc(cipherAndNonce.length - nonce.length)
    cipherAndNonce.copy(nonce, 0, 0, sodium.crypto_secretbox_NONCEBYTES)
    cipherAndNonce.copy(cipher, 0, sodium.crypto_secretbox_NONCEBYTES, cipherAndNonce.length)

    return { nonce, cipher }
}

function hash(input) {
    let output = Buffer.alloc(sodium.crypto_generichash_BYTES_MIN)
    sodium.crypto_generichash(output, input)
    return output
}

module.exports = {
    hash,
    makeNonce,
    makeSymmetricKey,
    encrypt,
    decrypt,
    SYM_KEY_LENGTH: sodium.crypto_secretbox_KEYBYTES
}