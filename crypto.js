const sodium = require("sodium-native")

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

// assumes that 'nonce' is prepended to 'cipher'
function splitNonceAndCipher(nonceAndCipher) {
    const nonceLength = sodium.crypto_secretbox_NONCEBYTES
    return {
        nonce: nonceAndCipher.slice(0, nonceLength), // first 'nonceLength' bytes
        cipher: nonceAndCipher.slice(nonceLength) // remaining bytes
    }
}

function encrypt(plainMessage, key) {
    let ciphertext = Buffer.alloc(plainMessage.length + sodium.crypto_secretbox_MACBYTES)
    let message = Buffer.from(plainMessage, "utf-8")
    let nonce = makeNonce()

    sodium.crypto_secretbox_easy(ciphertext, message, nonce, key)

    return Buffer.concat([nonce, ciphertext]) // Prepend nonce to ciphertext
}

function encryptWithPublicKey(plainMessage, recipientPublicKey) {
    let m = Buffer.from(plainMessage, "utf-8")
    let ciphertext = Buffer.alloc(m.length + sodium.crypto_box_SEALBYTES)
    sodium.crypto_box_seal(ciphertext, m, recipientPublicKey)
    return ciphertext
}

function decryptWithPublicKey(ciphertext, recipientPublicKey, recipientSecretKey) {
    let m = Buffer.alloc(ciphertext.length - sodium.crypto_box_SEALBYTES)
    sodium.crypto_box_seal_open(m, ciphertext, recipientPublicKey, recipientSecretKey)
    return m
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
    let message = Buffer.alloc(signedMessage.length - sodium.crypto_sign_BYTES)
    const verified = sodium.crypto_sign_open(message, signedMessage, pk)
    return { verified, message: verified ? message : null }
}

function verifyDetached(signature, message, pk) {
    try {
        return sodium.crypto_sign_verify_detached(signature, message, pk)
    } catch (error) {
        return false // 'crypto_sign_verify_detached' throws an error if the inputs are of wrong size. 
    }

}

function streamXOR(input, nonce, initializationCounter, key) {
    const res = Buffer.alloc(input.length)
    sodium.crypto_stream_xchacha20_xor_ic(res, input, nonce, initializationCounter, key)
    return res
}

// - XChaCha20 crypt-streams. En/Decrypting streams using xchacha20. TODO: Refactor into own file
/**
 * Decrypts a slice of 'cipher', which has been encrypted with 'nonce' and 'key' using XChaCha20.
 * The slice starts at 'position' (is included) and ends 'length' elements later.
 * If the slice exceeds 'cipher', the slice ends at the end of 'cipher'.
 * @param {Buffer} cipher
 * @param {Buffer} nonce
 * @param {Buffer} key
 * @param {int} position
 * @param {int} length
 * @returns {Buffer} the decrypted slice
 */
function decryptSlice(cipher, nonce, key, position, length) {
    if (!Number.isInteger(position)) throw new Error("'position' must be integer but received " + position)
    if (position < 0) throw new Error("'position' must be non-negative but received " + position)
    if (!Number.isInteger(length)) throw new Error("'length' must be integer but received " + length)
    if (length < 0) throw new Error("'length' must be non-negative but received " + length)

    const ic = Math.floor(position / STREAM_BLOCK_SIZE) // the block containing 'position' (i.e the first block)
    const blockCount = Math.floor(length / STREAM_BLOCK_SIZE) + 1 // the number of blocks to decrypt.

    const startPositionOfFirstBlock = ic * STREAM_BLOCK_SIZE
    const endPositionOfLastBlock = Math.min(
        // The end position can at most be the index of the last element in 'cipher'.
        (ic + blockCount) * STREAM_BLOCK_SIZE - 1,
        cipher.length - 1
    )

    // Decrypt only the blocks containing the interval from 'position' and 'length' positions forwards.
    const slice = cipher.slice(startPositionOfFirstBlock, endPositionOfLastBlock + 1) //  add 1 to 'end' since '.slice' to include last element
    const decrypted = streamXOR(slice, nonce, ic, key)

    // Return only the relevant interval of 'decrypted' by offsetting
    const startPosition = position % STREAM_BLOCK_SIZE
    return decrypted.slice(startPosition, startPosition + length)
}

/**
 * Decrypts a slice of 'cipher' using 'nonce' and 'key'. The slice starts at 'position' and is 'length' long if possible.
 * It is assumed that 'cipher' starts from the beginning of the block containing 'position'.
 * Example:
 *      original cipher = [B1, B2, B3, B4, B5], where each B is a block (64 bytes each)
 *      Say 'position' = 77
 *      Then 'position' points to B2, and it is assumed that the 'cipher' passed to this function also starts at B2.
 * @param {Buffer} cipher
 * @param {Buffer} nonce (24 bytes)
 * @param {Buffer} key (32 bytes)
 * @param {number} position (non-negative)
 * @param {number} length (non-negative)
 * @returns Buffer. Is truncated if the requested slice overflows 'cipher'
 */
function decryptSlice2(cipher, nonce, key, position, length) {
    //TODO: Come up with a better name
    if (!Number.isInteger(position)) throw new Error("'position' must be integer but received " + position)
    if (position < 0) throw new Error("'position' must be non-negative but received " + position)
    if (!Number.isInteger(length)) throw new Error("'length' must be integer but received " + length)
    if (length < 0) throw new Error("'length' must be non-negative but received " + length)

    const ic = Math.floor(position / STREAM_BLOCK_SIZE)
    const decrypted = streamXOR(cipher, nonce, ic, key)
    const startPosition = position % STREAM_BLOCK_SIZE

    return decrypted.slice(startPosition, startPosition + length)
}

/**
 * Encrypts 'buffer' using 'key' and 'nonce' and inserts it into 'cipher'
 * at [position, position + length] and "pushes" the tail of further back in the buffer.
 * @param {d} cipher
 * @param {*} nonce
 * @param {*} key
 * @param {*} buffer
 * @param {*} position
 * @param {*} length
 * @returns cipher
 */
function encryptSlice(cipher, nonce, key, buffer, position, length) {
    if (!Number.isInteger(position)) throw new Error("position must be integer but received " + typeof position)
    if (position < 0) throw new Error("'position' must be non-negagive, but received " + position)
    if (position > cipher.length) throw new Error("'position' must be greater or less than cipher.length but received " + position)
    if (!Number.isInteger(length)) throw new Error("length must be integer but received " + typeof length)
    if (length < 0) throw new Error("'length' must be non-negagive, but received " + length)

    // Compute the version of 'ic' for the underlying xor-stream used to encrypt 'cipher' up until 'position'. This assumes ic started at 0
    const ic = Math.floor(position / STREAM_BLOCK_SIZE)

    // There are 2 possible scenarios for 'position':
    // #1: 'position' points to right after the entire 'cipher'. This means appending 'buffer' to 'cipher'
    // #2: 'position' points inside of an existing block, B. B can be already used or it can be partially used, if it is the last block of 'cipher'.
    //      In both cases, we need to perform the following steps:
    //      1) Slice and decrypt B and all blocks coming after B. This is necessary since all aftercoming blocks should be re-encrypted under a new 'ic'
    //      2) Insert the incoming buffer inbetween B and the aftercoming blocks
    //      3) Encrypt B + buffer + remaining blocks starting with 'ic' for B.
    //      4) Concat all the pieces together

    const startPositionOfBlockContainingPosition = ic * STREAM_BLOCK_SIZE
    const cipherSliceUpToBlockContainingPosition = cipher.slice(0, startPositionOfBlockContainingPosition)
    const cipherSliceFromBlockContainingPosition = cipher.slice(startPositionOfBlockContainingPosition)
    const decryptedStreamStartingFromBlockContainingPosition = streamXOR(cipherSliceFromBlockContainingPosition, nonce, ic, key)

    // Split the block containing 'position' into two slices: [0, position[ (denoted blockPre) and [position, end-of-block] (denoted blockPost)
    const blockPre = decryptedStreamStartingFromBlockContainingPosition.slice(0, position % STREAM_BLOCK_SIZE)
    const blockPost = decryptedStreamStartingFromBlockContainingPosition.slice(position % STREAM_BLOCK_SIZE, STREAM_BLOCK_SIZE)
    const remainingBlocks = decryptedStreamStartingFromBlockContainingPosition.slice(STREAM_BLOCK_SIZE)

    // Inject the prefix of length 'length' of 'buffer' between 'blockPre' and 'blockPost' followed by remaining blocks
    const bufferPrefix = buffer.slice(0, length)
    const combinedPlainBlocks = Buffer.concat([blockPre, bufferPrefix, blockPost, remainingBlocks])

    // Re-encrypt 'combinedPlainBlocks'
    const cipherTail = streamXOR(combinedPlainBlocks, nonce, ic, key)
    const combined = Buffer.concat([cipherSliceUpToBlockContainingPosition, cipherTail])
    return combined
}

module.exports = {
    hash,
    makeNonce,
    makeSymmetricKey,
    encrypt,
    encryptWithPublicKey,
    decrypt,
    decryptWithPublicKey,
    makeSigningKeyPair,
    makeEncryptionKeyPair,
    signDetached,
    verifyDetached,
    signCombined,
    verifyCombined,
    streamXOR,
    splitNonceAndCipher,
    decryptSlice,
    decryptSlice2,
    encryptSlice,
    SYM_KEY_LENGTH: sodium.crypto_secretbox_KEYBYTES,
    STREAM_BLOCK_SIZE: STREAM_BLOCK_SIZE,
    NONCE_LENGTH: sodium.crypto_secretbox_NONCEBYTES
}
