const sodium = require("sodium-native")
const { join, resolve } = require("path")

const MAC_LENGTH = sodium.crypto_aead_xchacha20poly1305_ietf_ABYTES
const NONCE_LENGTH = sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
const SIGNATURE_SIZE = sodium.crypto_sign_BYTES

// The maximum size of a message appended to the stream
// Every chunk, except for the last, in the stream is of this size.
const STREAM_CHUNK_SIZE = 4096
const STREAM_CIPHER_CHUNK_SIZE = STREAM_CHUNK_SIZE + MAC_LENGTH + NONCE_LENGTH

const CAPABILITY_TYPE_READ = "read"
const CAPABILITY_TYPE_WRITE = "write"
const CAPABILITY_TYPE_VERIFY = "verify"

const LOCAL_KEYRING_PATH = join(__dirname, "keys", "local.keyring")
const LOCAL_USERPAIR_PATH = join(__dirname, "keys", "user.keys")

const BASE_DIR = resolve("./fsp")
const MOUNT_DIR = resolve("./mnt")

const FSP_ACCESS_TOKEN = "rxnh5lxxqU8AAAAAAAAAATBaiYe1b-uzEIe4KlOijCQD-Faam2Bx5ykV6XldV86W"

const FILE_DELETE_PREFIX_BUFFER = Buffer.from("2E96CNuTm63uwUlvjSWiXaOtU8xk48qh0Gjz83sf")

module.exports = {
    STREAM_CHUNK_SIZE,
    STREAM_CIPHER_CHUNK_SIZE,
    MAC_LENGTH,
    NONCE_LENGTH,
    SIGNATURE_SIZE,
    CAPABILITY_TYPE_READ,
    CAPABILITY_TYPE_WRITE,
    CAPABILITY_TYPE_VERIFY,
    LOCAL_KEYRING_PATH,
    LOCAL_USERPAIR_PATH,
    BASE_DIR,
    MOUNT_DIR,
    FSP_ACCESS_TOKEN,
    FILE_DELETE_PREFIX_BUFFER,
}
