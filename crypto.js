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
    if (key.length !== sodium.crypto_secretbox_KEYBYTES) throw new Error("Key-length error: Expected: " + sodium.crypto_secretbox_KEYBYTES + ", Received: " + key.length)

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

function makeKeyPair() {
    let sk = Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES)
    let pk = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
    sodium.crypto_sign_keypair(pk, sk)
    return {sk, pk}
}

function sign(message, sk) {
    if (!Buffer.isBuffer(message)) throw new Error("Message-type error. Expected: Buffer. Received: " + typeof(message))
    if (!Buffer.isBuffer(sk)) throw new Error("Signing key-type error. Expected: Buffer. Received: " + typeof(sk))

    let sig = Buffer.alloc(sodium.crypto_sign_BYTES)
    sodium.crypto_sign_detached(sig, message, sk)
    return sig
}

function verify(signature, message, pk) {
    if (!Buffer.isBuffer(signature)) throw new Error("Signature-type error. Expected: Buffer. Received: " + typeof(signature))
    if (signature.length !== sodium.crypto_sign_BYTES) throw new Error("Signature-length error. Expected: " + sodium.crypto_sign_BYTES + ", Received: " + signature.length)
    if (!Buffer.isBuffer(message)) throw new Error("Message-type error. Expected: Buffer. Received: " + typeof(message))
    if (!Buffer.isBuffer(pk)) throw new Error("Public Key-type error. Expected: Buffer. Received: " + typeof(pk))
    if (pk.length !== sodium.crypto_sign_PUBLICKEYBYTES) throw new Error("Public Key-length error. Expected: " + sodium.crypto_sign_PUBLICKEYBYTES + ", Received: " + pk.length)

    return sodium.crypto_sign_verify_detached(signature, message, pk)
}

module.exports = {
    hash,
    makeNonce,
    makeSymmetricKey,
    encrypt,
    decrypt,
    makeKeyPair,
    sign,
    verify,
    SYM_KEY_LENGTH: sodium.crypto_secretbox_KEYBYTES
}