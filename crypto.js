const sodium = require('sodium-native')

const STREAM_BLOCK_SIZE = 64

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
    let sig = Buffer.alloc(sodium.crypto_sign_BYTES)
    sodium.crypto_sign_detached(sig, message, sk)
    return sig
}

function verify(signature, message, pk) {
    return sodium.crypto_sign_verify_detached(signature, message, pk)
}

function streamXOR(input, nonce, initializationCounter, key) {
    const res = Buffer.alloc(input.length)
    sodium.crypto_stream_xchacha20_xor_ic(res, input, nonce, initializationCounter, key)
    return res
}

function sliceDecrypt(cipher, nonce, key, position, length) {
    if (!Number.isInteger(position)) throw new Error ("'position' must be integer but received " + position)
    if (position < 0) throw new Error("'position' must be non-negative but received " + position)
    if (!Number.isInteger(length)) throw new Error ("'length' must be integer but received " + length)
    if (length < 0) throw new Error("'length' must be non-negative but received " + length)

    const ic = Math.floor(position / STREAM_BLOCK_SIZE)             // the block containing 'position' (i.e the first block)
    const blockCount = Math.floor(length / STREAM_BLOCK_SIZE) + 1   // the number of blocks to decrypt.

    const startPositionOfFirstBlock = ic * STREAM_BLOCK_SIZE
    const endPositionOfLastBlock = Math.min((ic + blockCount) * STREAM_BLOCK_SIZE - 1, cipher.length - 1)

    // Decrypt only the blocks containing the interval from 'position' and 'length' positions forwards.
    const slice = cipher.slice(startPositionOfFirstBlock, endPositionOfLastBlock + 1) //  add 1 to 'end' since '.slice' to include last element
    const decrypted = streamXOR(slice, nonce, ic, key)

    // Return only the relevant interval of 'decrypted' by offsetting
    const startPosition = position % STREAM_BLOCK_SIZE
    return decrypted.slice(startPosition, startPosition + length)
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
    streamXOR,
    sliceDecrypt,
    SYM_KEY_LENGTH: sodium.crypto_secretbox_KEYBYTES,
    STREAM_BLOCK_SIZE: STREAM_BLOCK_SIZE,
}