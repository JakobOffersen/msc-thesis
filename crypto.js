const sodium = require("sodium-native")

function makeSymmetricKey() {
    const key = Buffer.alloc(sodium.crypto_secretstream_xchacha20poly1305_KEYBYTES)
    sodium.crypto_aead_xchacha20poly1305_ietf_keygen(key)
    return key
}

function encryptAsymmetric(plain, pk) {
    const m = Buffer.from(plain, "utf-8")
    const ciphertext = Buffer.alloc(m.length + sodium.crypto_box_SEALBYTES)
    sodium.crypto_box_seal(ciphertext, m, pk)
    return ciphertext
}

function decryptAsymmetric(ciphertext, recipientPublicKey, recipientSecretKey) {
    const m = Buffer.alloc(ciphertext.length - sodium.crypto_box_SEALBYTES)
    sodium.crypto_box_seal_open(m, ciphertext, recipientPublicKey, recipientSecretKey)
    return m
}

function encrypt(plainMessage, key) {
    const ciphertext = Buffer.alloc(plainMessage.length + sodium.crypto_aead_xchacha20poly1305_ietf_ABYTES)
    const message = Buffer.from(plainMessage, "utf-8")
    const nonce = _makeNonce(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES)

    sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(ciphertext, message, null, null, nonce, key)

    return Buffer.concat([nonce, ciphertext]) // Prepend nonce to ciphertext
}

function decrypt(nonceAndCipher, key) {
    const { nonce, ciphertext } = _splitNonceAndCipher(nonceAndCipher)
    const out = Buffer.alloc(ciphertext.length - sodium.crypto_aead_xchacha20poly1305_ietf_ABYTES)

    try {
        sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(out, null, ciphertext, null, nonce, key)
        return out
    } catch (error) {
        return null
    }
}

function makeSigningKeyPair() {
    const sk = Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES)
    const pk = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
    sodium.crypto_sign_keypair(pk, sk)
    return { sk, pk }
}

function makeEncryptionKeyPair() {
    const sk = Buffer.alloc(sodium.crypto_box_SECRETKEYBYTES)
    const pk = Buffer.alloc(sodium.crypto_box_PUBLICKEYBYTES)
    sodium.crypto_box_keypair(pk, sk)
    return { sk, pk }
}

function signDetached(message, sk) {
    const signature = Buffer.alloc(sodium.crypto_sign_BYTES)
    sodium.crypto_sign_detached(signature, message, sk)
    return signature
}

function signCombined(message, sk) {
    const signedMessage = Buffer.alloc(sodium.crypto_sign_BYTES + message.length)
    sodium.crypto_sign(signedMessage, message, sk)
    return signedMessage
}

function verifyCombined(signedMessage, pk) {
    try {
        const message = Buffer.alloc(signedMessage.length - sodium.crypto_sign_BYTES)
        const verified = sodium.crypto_sign_open(message, signedMessage, pk)
        return { verified, message: verified ? message : null }
    } catch {
        // 'crypto_sign_open' throws an error if the inputs are of the wrong size.
        return { verified: false, message: null }
    }
}

function verifyDetached(signature, message, pk) {
    return sodium.crypto_sign_verify_detached(signature, message, pk)
}

function _splitNonceAndCipher(combined) {
    const nonce = combined.subarray(0, sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES)
    const ciphertext = combined.subarray(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES)

    return { nonce, ciphertext }
}

function _makeNonce(size) {
    const nonce = Buffer.alloc(size)
    sodium.randombytes_buf(nonce)
    return nonce
}

class Hasher {
    constructor() {
        this.state = Buffer.alloc(sodium.crypto_generichash_STATEBYTES)
        sodium.crypto_generichash_init(this.state, null, sodium.crypto_generichash_BYTES)
    }

    update(buffer) {
        sodium.crypto_generichash_update(this.state, buffer)
    }

    final() {
        const out = Buffer.alloc(sodium.crypto_generichash_BYTES)

        // Create a copy of the state so we can keep calling update on the hasher.
        const tempState = Buffer.alloc(sodium.crypto_generichash_STATEBYTES)
        this.state.copy(tempState)

        sodium.crypto_generichash_final(tempState, out)
        return out
    }
}

module.exports = {
    makeSymmetricKey,
    encryptAsymmetric,
    decryptAsymmetric,
    encrypt,
    decrypt,
    makeSigningKeyPair,
    makeEncryptionKeyPair,
    signDetached,
    verifyDetached,
    signCombined,
    verifyCombined,
    Hasher
}
