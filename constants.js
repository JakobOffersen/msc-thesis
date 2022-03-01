const sodium = require("sodium-native")
const { join } = require("path")
const homedir = require("os").homedir()

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

const BASE_DIR = join(homedir, "Dropbox")
const MOUNT_DIR = join(__dirname, "mnt")

const FSP_ACCESS_TOKEN = "rxnh5lxxqU8AAAAAAAAAATBaiYe1b-uzEIe4KlOijCQD-Faam2Bx5ykV6XldV86W"

const DAEMON_CONTENT_HASH_STORE_PATH = join(__dirname, "daemons", "hash-store.json")

const POSTAL_BOX = "/users"
const POSTAL_BOX_SHARED = join("/", "users", "shared")

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
    DAEMON_CONTENT_HASH_STORE_PATH,
    POSTAL_BOX_SHARED,
    POSTAL_BOX
}
