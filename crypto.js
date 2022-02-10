const sodium = require("sodium-native")

function _makeNonce() {
    let nonce = Buffer.alloc(sodium.crypto_secretbox_NONCEBYTES)
    sodium.randombytes_buf(nonce)
    return nonce
}

function makeSymmetricKey() {
    let nonce = Buffer.alloc(sodium.crypto_secretbox_KEYBYTES)
    sodium.randombytes_buf(nonce)
    return nonce
}

function encryptWithPublicKey(plain, pk) {
    let m = Buffer.from(plain, "utf-8")
    let ciphertext = Buffer.alloc(m.length + sodium.crypto_box_SEALBYTES)
    sodium.crypto_box_seal(ciphertext, m, pk)
    return ciphertext
}

function decryptWithPublicKey(ciphertext, recipientPublicKey, recipientSecretKey) {
    let m = Buffer.alloc(ciphertext.length - sodium.crypto_box_SEALBYTES)
    sodium.crypto_box_seal_open(m, ciphertext, recipientPublicKey, recipientSecretKey)
    return m
}

function encrypt(plainMessage, key) {
    let ciphertext = Buffer.alloc(plainMessage.length + sodium.crypto_secretbox_MACBYTES)
    let message = Buffer.from(plainMessage, "utf-8")
    let nonce = _makeNonce()

    sodium.crypto_secretbox_easy(ciphertext, message, nonce, key)

    return Buffer.concat([nonce, ciphertext]) // Prepend nonce to ciphertext
}

function decrypt(nonceAndCipher, key) {
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

function makeSigningKeyPair() {
    let sk = Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES)
    let pk = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
    sodium.crypto_sign_keypair(pk, sk)
    return { sk, pk }
}

function makeEncryptionKeyPair() {
    let sk = Buffer.alloc(sodium.crypto_box_SECRETKEYBYTES)
    let pk = Buffer.alloc(sodium.crypto_box_PUBLICKEYBYTES)
    sodium.crypto_box_keypair(pk, sk)
    return { sk, pk }
}

function signDetached(message, sk) {
    let sig = Buffer.alloc(sodium.crypto_sign_BYTES)
    sodium.crypto_sign_detached(sig, message, sk)
    return sig
}

function signCombined(message, sk) {
    let signedMessage = Buffer.alloc(sodium.crypto_sign_BYTES + message.length)
    sodium.crypto_sign(signedMessage, message, sk)
    return signedMessage
}

function verifyCombined(signedMessage, pk) {
    try {
        let message = Buffer.alloc(signedMessage.length - sodium.crypto_sign_BYTES)
        const verified = sodium.crypto_sign_open(message, signedMessage, pk)
        return { verified, message: verified ? message : null }
    } catch {
        // 'crypto_sign_open' throws an error if the inputs are of the wrong size.
        return { verified: false, message: null }
    }
}

function verifyDetached(signature, message, pk) {
    try {
        return sodium.crypto_sign_verify_detached(signature, message, pk)
    } catch (error) {
        return false // 'crypto_sign_verify_detached' throws an error if the inputs are of wrong size.
    }
}

module.exports = {
    hash,
    makeSymmetricKey,
    encryptWithPublicKey,
    decryptWithPublicKey,
    encrypt,
    decrypt,
    makeSigningKeyPair,
    makeEncryptionKeyPair,
    signDetached,
    verifyDetached,
    signCombined,
    verifyCombined
}
