const assert = require("chai").assert
const crypto = require("../crypto")

describe.skip("Crypto.js", function () {
	describe("#hash(input)", function () {
		it("input must be of type Buffer", function () {
			const input = Buffer.from("hello world")
			const output = crypto.hash(input)
			assert.isTrue(Buffer.isBuffer(input))
			assert.isNotNull(output)
		})

		it("throws error if input is not of type Buffer", function () {
			const input = "plain message"
			assert.throws(() => {
				crypto.hash(input)
			})
		})

		it("output is of type Buffer", function () {
			const input = Buffer.from("input")
			const output = crypto.hash(input)
			assert.isTrue(Buffer.isBuffer(output))
		})
	})
	describe("#makeNonce()", function () {
		it("should return a fresh nonce at each function-call", function () {
			const n1 = crypto.makeNonce()
			const n2 = crypto.makeNonce()
			assert.notEqual(n1, n2)
		})

		it("should be of type Buffer", function () {
			const n1 = crypto.makeNonce()
			assert.isTrue(Buffer.isBuffer(n1))
		})

		it("should be of length 24", function () {
			const n1 = crypto.makeNonce()
			assert.equal(n1.length, 24)
		})
	})

	describe("Symmetric Cryptography", function () {
		describe("#makeSymmetricKey()", function () {
			it("should return a fresh key at each function-call", function () {
				const k1 = crypto.makeSymmetricKey()
				const k2 = crypto.makeSymmetricKey()
				assert.notEqual(k1, k2)
			})

			it("returns type Buffer", function () {
				const k1 = crypto.makeSymmetricKey()
				assert.isTrue(Buffer.isBuffer(k1))
			})

			it("returns Buffer of length 32", function () {
				const k1 = crypto.makeSymmetricKey()
				assert.equal(k1.length, 32)
			})
		})

		describe("#encrypt(message, key)", function () {
			it("message can be type string", function () {
				const m = "hello world"
				const k = crypto.makeSymmetricKey()
				const c = crypto.encrypt(m, k)
				assert.isString(m)
				assert.isNotNull(c)
				assert.isNotEmpty(c)
			})

			it("message can be type Buffer", function () {
				const m = Buffer.from("hello world", "utf-8")
				const k = crypto.makeSymmetricKey()
				const c = crypto.encrypt(m, k)
				assert.isTrue(Buffer.isBuffer(m))
				assert.isNotNull(c)
				assert.isNotEmpty(c)
			})

			it("key is type Buffer", function () {
				const m = "hello world"
				const k = crypto.makeSymmetricKey()
				const c = crypto.encrypt(m, k)
				assert.isTrue(Buffer.isBuffer(k))
				assert.isNotNull(c)
				assert.isNotEmpty(c)
			})

			it("returns type Buffer", function () {
				const m = "hello world"
				const k = crypto.makeSymmetricKey()
				const c = crypto.encrypt(m, k)
				assert.isTrue(Buffer.isBuffer(c))
			})

			it("key is length 32", function () {
				const m = "hello world"
				const k = crypto.makeSymmetricKey()
				const tooShortKey = Buffer.alloc(
					31,
					"this is a random key string that is filled into the allocated 31 bytes"
				)
				const tooLongKey = Buffer.alloc(
					33,
					"this is a random key string that is filled into the allocated 33 bytes"
				)

				assert.equal(k.length, 32)
				assert.notEqual(tooShortKey.length, 32)
				assert.notEqual(tooLongKey.length, 32)

				assert.doesNotThrow(() => {
					crypto.encrypt(m, k)
				})
				assert.throws(() => {
					crypto.encrypt(m, tooShortKey)
				})
				assert.throws(() => {
					crypto.encrypt(m, tooLongKey)
				})
			})

			it("should create a new cipher every time", function () {
				const m = "hello world"
				const k = crypto.makeSymmetricKey()
				const c1 = crypto.encrypt(m, k)
				const c2 = crypto.encrypt(m, k)
				assert.notEqual(c1, c2)
			})
		})

		describe("#decrypt(cipher, key)", function () {
			it("cipher must be type Buffer", function () {
				const m = "hello world"
				const k = crypto.makeSymmetricKey()
				const c = crypto.encrypt(m, k)
				const _ = crypto.decrypt(c, k)
				assert.isTrue(Buffer.isBuffer(c))
			})

			it("key must be type Buffer", function () {
				const m = "hello world"
				const k = crypto.makeSymmetricKey()
				const c = crypto.encrypt(m, k)
				const decrypted = crypto.decrypt(c, k)

				assert.isTrue(Buffer.isBuffer(k))
				assert.isNotNull(decrypted)
			})

			it("key must be length 32", function () {
				const m = "hello world"
				const k = crypto.makeSymmetricKey()
				const c = crypto.encrypt(m, k)
				const tooShortKey = Buffer.alloc(
					31,
					"this is a random key string that is filled into the allocated 31 bytes"
				)
				const tooLongKey = Buffer.alloc(
					33,
					"this is a random key string that is filled into the allocated 33 bytes"
				)

				assert.equal(k.length, 32)
				assert.notEqual(tooShortKey.length, 32)
				assert.notEqual(tooLongKey.length, 32)

				assert.doesNotThrow(() => {
					crypto.decrypt(c, k)
				})
				assert.throws(() => {
					crypto.decrypt(c, tooShortKey)
				})
				assert.throws(() => {
					crypto.decrypt(c, tooLongKey)
				})
			})

			it("returns type Buffer", function () {
				const m = "hello world"
				const k = crypto.makeSymmetricKey()
				const c = crypto.encrypt(m, k)
				const decrypted = crypto.decrypt(c, k)

				assert.isTrue(Buffer.isBuffer(decrypted))
			})
		})

		describe("encryption & decryption", function () {
			it("encrypt then decrypt gives the original plain message", function () {
				const m = "hello world"
				const k = crypto.makeSymmetricKey()
				const c = crypto.encrypt(m, k)
				const decrypted = crypto.decrypt(c, k)
				const mBuffer = Buffer.from(m)
				assert.equal(mBuffer.compare(decrypted), 0) // .compare returns 0 iff the two buffers are equal
			})

			it("decrypting with wrong key returns 'null'", function () {
				const m = "hello world"
				const k1 = crypto.makeSymmetricKey()
				const k2 = crypto.makeSymmetricKey()
				const c = crypto.encrypt(m, k1)
				const decrypted = crypto.decrypt(c, k2)
				assert.isNull(decrypted)
			})
		})
	})

	describe("Symmetric Stream Cryptography", function () {
		describe("#streamXOR(input, nonce, ic, key)", function () {
			it("'input' is Buffer", function () {
				const n = crypto.makeNonce()
				const k = crypto.makeSymmetricKey()
				assert.throws(() => crypto.streamXOR("invalid", n, 0, k))
				assert.doesNotThrow(() =>
					crypto.streamXOR(Buffer.from("valid"), n, 0, k)
				)
			})

			it("nonce is Buffer of size 24", function () {
				const m = Buffer.from("message")
				const n = crypto.makeNonce()
				const nonceTooLong = Buffer.alloc(25, "nonce filling")
				const nonceTooShort = Buffer.alloc(23, "nonce filling")
				const k = crypto.makeSymmetricKey()
				assert.doesNotThrow(() => crypto.streamXOR(m, n, 0, k))
				assert.throws(() => crypto.streamXOR(m, nonceTooShort, 0, k))
				assert.throws(() => crypto.streamXOR(m, nonceTooLong, 0, k))
			})

			it("ic is integer", function () {
				const m = Buffer.from("message")
				const n = crypto.makeNonce()
				const k = crypto.makeSymmetricKey()

				assert.throws(() => crypto.streamXOR(m, n, "1", k))
				assert.doesNotThrow(() => crypto.streamXOR(m, n, 1, k))
			})

			it("key is Buffer of size 32", function () {
				const m = Buffer.from("message")
				const n = crypto.makeNonce()
				const k = crypto.makeSymmetricKey()
				const keyTooShort = Buffer.alloc(31, "key filling")
				const keyTooLong = Buffer.alloc(33, "key filling")

				assert.doesNotThrow(() => crypto.streamXOR(m, n, 1, k))
				assert.throws(() => crypto.streamXOR(m, n, 0, keyTooShort))
				assert.throws(() => crypto.streamXOR(m, n, 0, keyTooLong))
			})

			it("returns Buffer of same length as 'input'", function () {
				const m = Buffer.from("message")
				const n = crypto.makeNonce()
				const k = crypto.makeSymmetricKey()
				const c = crypto.streamXOR(m, n, 0, k)
				assert.isTrue(Buffer.isBuffer(c))
				assert.equal(c.length, m.length)
			})

			it("encryption of cipher decrypts the cipher", function () {
				const m = Buffer.from("message")
				const n = crypto.makeNonce()
				const k = crypto.makeSymmetricKey()
				const c = crypto.streamXOR(m, n, 0, k)
				const decrypted = crypto.streamXOR(c, n, 0, k)
				assert.isFalse(m.compare(c) == 0) // .compare returns 0 when buffers are equal
				assert.isTrue(m.compare(decrypted) == 0) // .compare returns 0 when buffers are equal
			})

			it("allows random-access/independent 64-byte block-decryption", function () {
				// This test encrypts a 128-byte message into a 128-byte cipher (2 blocks)
				// Then it decrypts the cipher block by block and compares the result with the plain message
				const n = crypto.makeNonce()
				const k = crypto.makeSymmetricKey()
				const m = Buffer.alloc(
					128,
					"a very long message that keeps on going on for ever ljghsklfghjldhgk kghbskdfhgajsdhlgkdsjf jkhlb klfgshjdfkl ghjdskl gjsdlf"
				)
				const c = crypto.streamXOR(m, n, 0, k)

				// Split the cipher into 2 64-byte buffers
				const c1 = Buffer.alloc(64)
				const c2 = Buffer.alloc(64)
				c.copy(c1, 0, 0, 64) // copies first 64 bytes into 'c1'
				c.copy(c2, 0, 64, 128) // copies last 64 bytes into 'c2'

				// Decrypt the two blocks independently
				const m1 = crypto.streamXOR(c1, n, 0, k)
				const m2 = crypto.streamXOR(c2, n, 1, k) // Notice that 'ic' is incremented by 1 here

				const combined = Buffer.concat([m1, m2])
				assert.isTrue(Buffer.compare(m, combined) === 0) // Buffer.compare returns 0 when the buffers are equal
			})
		})

		describe("#decryptSlice(cipher, nonce, key, position, length)", function () {
			it("'position' is non-negative integer", function () {
				const m = Buffer.from("message")
				const n = crypto.makeNonce()
				const k = crypto.makeSymmetricKey()
				const c = crypto.streamXOR(m, n, 0, k)

				assert.throws(() => crypto.decryptSlice(c, n, k, -1, 1))
				assert.throws(() => crypto.decryptSlice(c, n, k, "0", 1))
				assert.doesNotThrow(() => crypto.decryptSlice(c, n, k, 0, 1))
			})

			it("'length' is non-negative integer", function () {
				const m = Buffer.from("message")
				const n = crypto.makeNonce()
				const k = crypto.makeSymmetricKey()
				const c = crypto.streamXOR(m, n, 0, k)

				assert.throws(() => crypto.decryptSlice(c, n, k, 0, -1))
				assert.throws(() => crypto.decryptSlice(c, n, k, 0, "0"))
				assert.doesNotThrow(() => crypto.decryptSlice(c, n, k, 0, 1))
			})

			it("slicing message from first block to end of last block", function () {
				const m = Buffer.from(
					"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
				)
				const n = crypto.makeNonce()
				const k = crypto.makeSymmetricKey()
				const c = crypto.streamXOR(m, n, 0, k)

				const decrypted = crypto.decryptSlice(c, n, k, 0, m.length)

				assert.isTrue(Buffer.compare(m, decrypted) == 0) // Buffer.compare returns 0 when the buffers are equal
			})

			it("slicing message from start of non-first block to end of last block", function () {
				const m = Buffer.from(
					"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
				)
				const n = crypto.makeNonce()
				const k = crypto.makeSymmetricKey()
				const c = crypto.streamXOR(m, n, 0, k)

				const startIndexOfBlock3 = 3 * crypto.STREAM_BLOCK_SIZE
				const decrypted = crypto.decryptSlice(
					c,
					n,
					k,
					startIndexOfBlock3,
					m.length
				)
				const sliced = m.slice(startIndexOfBlock3) // slices from 'startIndexOfBlock3' to end of 'm'

				assert.isTrue(Buffer.compare(sliced, decrypted) == 0) // Buffer.compare returns 0 when the buffers are equal
			})

			it("slicing message from non-start of non-first block to end of last block", function () {
				const m = Buffer.from(
					"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
				)
				const n = crypto.makeNonce()
				const k = crypto.makeSymmetricKey()
				const c = crypto.streamXOR(m, n, 0, k)

				const positionSomewhereInBlock3 =
					3 * crypto.STREAM_BLOCK_SIZE + 7
				const decrypted = crypto.decryptSlice(
					c,
					n,
					k,
					positionSomewhereInBlock3,
					m.length
				)
				const sliced = m.slice(positionSomewhereInBlock3) // slices from 'positionSomewhereInBlock3' to end of 'm'

				assert.isTrue(Buffer.compare(sliced, decrypted) == 0) // Buffer.compare returns 0 when the buffers are equal
			})

			it("slicing message from non-start of non-first block to (and including) end of non-last block", function () {
				const m = Buffer.from(
					"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
				)
				const n = crypto.makeNonce()
				const k = crypto.makeSymmetricKey()
				const c = crypto.streamXOR(m, n, 0, k)

				const positionSomewhereInBlock3 =
					3 * crypto.STREAM_BLOCK_SIZE + 7
				const endPositionOfBlock6 =
					6 * crypto.STREAM_BLOCK_SIZE + crypto.STREAM_BLOCK_SIZE - 1
				const length =
					endPositionOfBlock6 - positionSomewhereInBlock3 + 1
				const decrypted = crypto.decryptSlice(
					c,
					n,
					k,
					positionSomewhereInBlock3,
					length
				)
				const sliced = m.slice(
					positionSomewhereInBlock3,
					endPositionOfBlock6 + 1
				) // add 1 to include 'endPositionOfBlock6'

				assert.isTrue(Buffer.compare(sliced, decrypted) == 0) // Buffer.compare returns 0 when the buffers are equal
			})

			it("slicing message from non-start of non-first block to (and including) non-start of non-last block", function () {
				const m = Buffer.from(
					"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
				)
				const n = crypto.makeNonce()
				const k = crypto.makeSymmetricKey()
				const c = crypto.streamXOR(m, n, 0, k)

				const positionSomewhereInBlock3 =
					3 * crypto.STREAM_BLOCK_SIZE + 7
				const positionSomewhereInBlock7 =
					7 * crypto.STREAM_BLOCK_SIZE + 45
				const length =
					positionSomewhereInBlock7 - positionSomewhereInBlock3 + 1
				const decrypted = crypto.decryptSlice(
					c,
					n,
					k,
					positionSomewhereInBlock3,
					length
				)
				const sliced = m.slice(
					positionSomewhereInBlock3,
					positionSomewhereInBlock7 + 1
				) // slices [positionSomewhereInBlock3, positionSomewhereInBlock7]
				assert.isTrue(Buffer.compare(sliced, decrypted) == 0) // Buffer.compare returns 0 when the buffers are equal
			})

			it("requesting to slice longer than the message length returns only the original message", function () {
				const m = Buffer.from(
					"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
				)
				const n = crypto.makeNonce()
				const k = crypto.makeSymmetricKey()
				const c = crypto.streamXOR(m, n, 0, k)

				const positionSomewhereInBlock3 =
					3 * crypto.STREAM_BLOCK_SIZE + 7
				const length = m.length + 100
				const decrypted = crypto.decryptSlice(
					c,
					n,
					k,
					positionSomewhereInBlock3,
					length
				)
				const sliced = m.slice(positionSomewhereInBlock3) // slices from 'positionSomewhereInBlock3' to end of 'm'
				assert.isTrue(Buffer.compare(sliced, decrypted) == 0) // Buffer.compare returns 0 when the buffers are equal
			})

			it("requesting to slice longer than the original message returns only the original message", function () {
				const m = Buffer.from(
					"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
				)
				const n = crypto.makeNonce()
				const k = crypto.makeSymmetricKey()
				const c = crypto.streamXOR(m, n, 0, k)

				const positionSomewhereInBlock3 =
					3 * crypto.STREAM_BLOCK_SIZE + 7
				const length = 400 // '400' is shorter than 'm.length' but 'positionSomewhereInBlock3' + 400 is longer than 'm.length' making it "overflow"
				const decrypted = crypto.decryptSlice(
					c,
					n,
					k,
					positionSomewhereInBlock3,
					length
				)
				const sliced = m.slice(positionSomewhereInBlock3) // slices from 'positionSomewhereInBlock3' to end of 'm'
				assert.isTrue(Buffer.compare(sliced, decrypted) == 0) // Buffer.compare returns 0 when the buffers are equal
			})
		})

		describe("#encryptSlice(cipher, nonce, key, buffer, position, length)", function () {
			it("'buffer' is Buffer with at least 'length' elements", function () {
				const m = Buffer.from("hello world")
				const n = crypto.makeNonce()
				const k = crypto.makeSymmetricKey()
				const c = crypto.streamXOR(m, n, 0, k)

				const b = Buffer.from("buffer")

				assert.doesNotThrow(() =>
					crypto.encryptSlice(c, n, k, b, 0, b.length)
				)
				assert.throws(() =>
					crypto.encryptSlice(c, n, k, "string", 0, "string".length)
				)
			})

			it("'position' is non-negative integer", function () {
				const m = Buffer.from("hello world")
				const n = crypto.makeNonce()
				const k = crypto.makeSymmetricKey()
				const c = crypto.streamXOR(m, n, 0, k)
				const b = Buffer.from("buffer")

				assert.doesNotThrow(() =>
					crypto.encryptSlice(c, n, k, b, 0, b.length)
				)
				assert.throws(() =>
					crypto.encryptSlice(c, n, k, b, -1, b.length)
				)
				assert.throws(() =>
					crypto.encryptSlice(c, n, k, b, "2", b.length)
				)
			})

			it("'position' is at most cipher.length", function () {
				const m = Buffer.from("hello world")
				const n = crypto.makeNonce()
				const k = crypto.makeSymmetricKey()
				const c = crypto.streamXOR(m, n, 0, k)
				const b = Buffer.from("buffer")

				assert.doesNotThrow(() =>
					crypto.encryptSlice(c, n, k, b, c.length - 1, b.length)
				)
				assert.doesNotThrow(() =>
					crypto.encryptSlice(c, n, k, b, c.length, b.length)
				)
				assert.throws(() =>
					crypto.encryptSlice(c, n, k, b, c.length + 1, b.length)
				)
			})

			it("'length is non-negative integer'", function () {
				const m = Buffer.from("hello world")
				const n = crypto.makeNonce()
				const k = crypto.makeSymmetricKey()
				const c = crypto.streamXOR(m, n, 0, k)
				const b = Buffer.from("buffer")

				assert.doesNotThrow(() =>
					crypto.encryptSlice(c, n, k, b, 0, b.length)
				)
				assert.throws(() => crypto.encryptSlice(c, n, k, b, 0, -1))
				assert.throws(() => crypto.encryptSlice(c, n, k, b, 0, "2"))
			})

			it("returns type Buffer", function () {
				const m = Buffer.from("hello world")
				const n = crypto.makeNonce()
				const k = crypto.makeSymmetricKey()
				const c = crypto.streamXOR(m, n, 0, k)
				const b = Buffer.from("buffer")
				const res = crypto.encryptSlice(c, n, k, b, 0, b.length)

				assert.isTrue(Buffer.isBuffer(res))
			})

			it("appending 'buffer' (arbitrary length) to 'cipher' (arbitrary length) yields an extended cipher encrypted using 'key' and 'nonce'", function () {
				// Setup the initial cipher
				const m = Buffer.from(
					"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
				)
				const n = crypto.makeNonce()
				const k = crypto.makeSymmetricKey()
				const c = crypto.streamXOR(m, n, 0, k)

				// Append buffer to cipher. I.e first element of 'buffer' should appear as element right after the last element of the cipher (c.length)
				const buffer = Buffer.from(
					"Contrary to popular belief, Lorem Ipsum is not simply random text. It has roots in a piece of classical Latin literature from 45 BC, making it over 2000 years old. Richard McClintock, a Latin professor at Hampden-Sydney College in Virginia, looked up one of the more obscure Latin words, consectetur, from a Lorem Ipsum passage, and going through the cites of the word in classical literature, discovered the undoubtable source. Lorem Ipsum comes from sections 1.10.32 and 1.10.33 of de Finibus Bonorum et Malorum (The Extremes of Good and Evil) by Cicero, written in 45 BC. This book is a treatise on the theory of ethics, very popular during the Renaissance. The first line of Lorem Ipsum, Lorem ipsum dolor sit amet.., comes from a line in section 1.10.32."
				)
				const updatedCipher = crypto.encryptSlice(
					c,
					n,
					k,
					buffer,
					c.length,
					buffer.length
				)

				// Verify that decrypting 'updatedCipher' yields the original message ('m') appended by the buffer
				const decrypted = crypto.decryptSlice(
					updatedCipher,
					n,
					k,
					0,
					updatedCipher.length
				)
				const combinedPlain = Buffer.concat([m, buffer])
				assert.isTrue(Buffer.compare(decrypted, combinedPlain) === 0) // .compare returns 0 when the two buffers are equal
			})

			it("appending 'buffer' (1 block length) to 'cipher' (1 block length) yields an extended cipher encrypted using 'key' and 'nonce'", function () {
				const m = Buffer.alloc(64, "filling for one block")
				const n = crypto.makeNonce()
				const k = crypto.makeSymmetricKey()
				const c = crypto.streamXOR(m, n, 0, k)

				// Append buffer to cipher. I.e first element of 'buffer' should appear as element right after the last element of the cipher (c.length)
				const buffer = Buffer.alloc(
					64,
					"filling for the next block to be appended"
				)
				const updatedCipher = crypto.encryptSlice(
					c,
					n,
					k,
					buffer,
					c.length,
					buffer.length
				)

				// Verify that decrypting 'updatedCipher' yields the original message ('m') appended by the buffer
				const decrypted = crypto.decryptSlice(
					updatedCipher,
					n,
					k,
					0,
					updatedCipher.length
				)
				const combinedPlain = Buffer.concat([m, buffer])
				assert.isTrue(Buffer.compare(decrypted, combinedPlain) === 0) // .compare returns 0 when the two buffers are equal
			})

			it("appending buffer with arbitrary length into cipher with arbitrary length at arbitrary position", function () {
				const m = Buffer.from(
					"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
				)
				const n = crypto.makeNonce()
				const k = crypto.makeSymmetricKey()
				const c = crypto.streamXOR(m, n, 0, k)

				const position = 473
				// Inject buffer to cipher at arbitrary position.
				const buffer = Buffer.from(
					"Contrary to popular belief, Lorem Ipsum is not simply random text. It has roots in a piece of classical Latin literature from 45 BC, making it over 2000 years old. Richard McClintock, a Latin professor at Hampden-Sydney College in Virginia, looked up one of the more obscure Latin words, consectetur, from a Lorem Ipsum passage, and going through the cites of the word in classical literature, discovered the undoubtable source. Lorem Ipsum comes from sections 1.10.32 and 1.10.33 of de Finibus Bonorum et Malorum (The Extremes of Good and Evil) by Cicero, written in 45 BC. This book is a treatise on the theory of ethics, very popular during the Renaissance. The first line of Lorem Ipsum, Lorem ipsum dolor sit amet.., comes from a line in section 1.10.32."
				)
				const updatedCipher = crypto.encryptSlice(
					c,
					n,
					k,
					buffer,
					position,
					buffer.length
				)

				const decrypted = crypto.decryptSlice(
					updatedCipher,
					n,
					k,
					0,
					updatedCipher.length
				)

				const mPre = m.slice(0, position)
				const mPost = m.slice(position)
				const expected = Buffer.concat([mPre, buffer, mPost])

				assert.isTrue(Buffer.compare(decrypted, expected) === 0) // .compare returns 0 when buffers are equal
			})

			it("prepending buffer test", function () {
				const m = Buffer.from(
					"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
				)
				const n = crypto.makeNonce()
				const k = crypto.makeSymmetricKey()
				const c = crypto.streamXOR(m, n, 0, k)

				const position = 0
				// Inject buffer to cipher at arbitrary position.
				const buffer = Buffer.from(
					"Contrary to popular belief, Lorem Ipsum is not simply random text. It has roots in a piece of classical Latin literature from 45 BC, making it over 2000 years old. Richard McClintock, a Latin professor at Hampden-Sydney College in Virginia, looked up one of the more obscure Latin words, consectetur, from a Lorem Ipsum passage, and going through the cites of the word in classical literature, discovered the undoubtable source. Lorem Ipsum comes from sections 1.10.32 and 1.10.33 of de Finibus Bonorum et Malorum (The Extremes of Good and Evil) by Cicero, written in 45 BC. This book is a treatise on the theory of ethics, very popular during the Renaissance. The first line of Lorem Ipsum, Lorem ipsum dolor sit amet.., comes from a line in section 1.10.32."
				)
				const updatedCipher = crypto.encryptSlice(
					c,
					n,
					k,
					buffer,
					position,
					buffer.length
				)

				const decrypted = crypto.decryptSlice(
					updatedCipher,
					n,
					k,
					0,
					updatedCipher.length
				)

				const mPre = m.slice(0, position)
				const mPost = m.slice(position)
				const expected = Buffer.concat([mPre, buffer, mPost])

				assert.isTrue(Buffer.compare(decrypted, expected) === 0) // .compare returns 0 when buffers are equal
			})

			it("injecting buffer between two blocks in cipher", function () {
				const m = Buffer.from(
					"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
				)
				const n = crypto.makeNonce()
				const k = crypto.makeSymmetricKey()
				const c = crypto.streamXOR(m, n, 0, k)

				const position = 64
				// Inject buffer to cipher at arbitrary position.
				const buffer = Buffer.from(
					"Contrary to popular belief, Lorem Ipsum is not simply random text. It has roots in a piece of classical Latin literature from 45 BC, making it over 2000 years old. Richard McClintock, a Latin professor at Hampden-Sydney College in Virginia, looked up one of the more obscure Latin words, consectetur, from a Lorem Ipsum passage, and going through the cites of the word in classical literature, discovered the undoubtable source. Lorem Ipsum comes from sections 1.10.32 and 1.10.33 of de Finibus Bonorum et Malorum (The Extremes of Good and Evil) by Cicero, written in 45 BC. This book is a treatise on the theory of ethics, very popular during the Renaissance. The first line of Lorem Ipsum, Lorem ipsum dolor sit amet.., comes from a line in section 1.10.32."
				)
				const updatedCipher = crypto.encryptSlice(
					c,
					n,
					k,
					buffer,
					position,
					buffer.length
				)

				const decrypted = crypto.decryptSlice(
					updatedCipher,
					n,
					k,
					0,
					updatedCipher.length
				)

				const mPre = m.slice(0, position)
				const mPost = m.slice(position)
				const expected = Buffer.concat([mPre, buffer, mPost])

				assert.isTrue(Buffer.compare(decrypted, expected) === 0) // .compare returns 0 when buffers are equal
			})

			it("injecting part of buffer in cipher at arbitrary position", function () {
				const m = Buffer.from(
					"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
				)
				const n = crypto.makeNonce()
				const k = crypto.makeSymmetricKey()
				const c = crypto.streamXOR(m, n, 0, k)

				const position = 203
				const length = 199
				// Inject arbitrary prefix of buffer to cipher at arbitrary position
				const buffer = Buffer.from(
					"Contrary to popular belief, Lorem Ipsum is not simply random text. It has roots in a piece of classical Latin literature from 45 BC, making it over 2000 years old. Richard McClintock, a Latin professor at Hampden-Sydney College in Virginia, looked up one of the more obscure Latin words, consectetur, from a Lorem Ipsum passage, and going through the cites of the word in classical literature, discovered the undoubtable source. Lorem Ipsum comes from sections 1.10.32 and 1.10.33 of de Finibus Bonorum et Malorum (The Extremes of Good and Evil) by Cicero, written in 45 BC. This book is a treatise on the theory of ethics, very popular during the Renaissance. The first line of Lorem Ipsum, Lorem ipsum dolor sit amet.., comes from a line in section 1.10.32."
				)
				const updatedCipher = crypto.encryptSlice(
					c,
					n,
					k,
					buffer,
					position,
					length
				)

				const decrypted = crypto.decryptSlice(
					updatedCipher,
					n,
					k,
					0,
					updatedCipher.length
				)

				const mPre = m.slice(0, position)
				const mPost = m.slice(position)
				const expected = Buffer.concat([
					mPre,
					buffer.slice(0, length),
					mPost,
				])

				assert.isTrue(Buffer.compare(decrypted, expected) === 0) // .compare returns 0 when buffers are equal
			})
		})
	})

	describe("Assymmetric Cryptography", function () {
		describe("#makeSigningKeyPair()", function () {
			it("returns { sk, pk } of type { Buffer, Buffer } with sizes { 64, 32 }", function () {
				const { sk, pk } = crypto.makeSigningKeyPair()
				assert.isTrue(Buffer.isBuffer(sk))
				assert.isTrue(Buffer.isBuffer(pk))
				assert.equal(sk.length, 64)
				assert.equal(pk.length, 32)
			})

			it("returns a fresh key pair at each function-call", function () {
				const pair1 = crypto.makeSigningKeyPair()
				const pair2 = crypto.makeSigningKeyPair()
				assert.notEqual(pair1.sk, pair2.sk)
				assert.notEqual(pair1.pk, pair2.pk)
			})
		})

		describe("#signDetached(message, sk)", function () {
			it("message must be type Buffer", function () {
				const m1 = Buffer.from("hello world")
				const m2 = "hello world"
				const { sk, _ } = crypto.makeSigningKeyPair()

				assert.isTrue(Buffer.isBuffer(m1))
				assert.doesNotThrow(() => {
					crypto.signDetached(m1, sk)
				})
				assert.throws(() => {
					crypto.signDetached(m2, sk)
				})
			})

			it("key must be type Buffer of size 64", function () {
				const m = Buffer.from("hello world")
				const { sk, _ } = crypto.makeSigningKeyPair()
				const tooShortSignKey = Buffer.alloc(63, "filling")
				const tooLongSignKey = Buffer.alloc(65, "filling")

				assert.isTrue(Buffer.isBuffer(sk))
				assert.equal(sk.length, 64)
				assert.notEqual(tooShortSignKey, 64)
				assert.notEqual(tooLongSignKey, 64)

				assert.doesNotThrow(() => {
					crypto.signDetached(m, sk)
				})
				assert.throws(() => {
					crypto.signDetached(m, tooShortSignKey)
				})
				assert.throws(() => {
					crypto.signDetached(m, tooLongSignKey)
				})
			})

			it("returns type Buffer of size 64", function () {
				const m = Buffer.from("hello world")
				const { sk, _ } = crypto.makeSigningKeyPair()
				const signature = crypto.signDetached(m, sk)
				assert.isTrue(Buffer.isBuffer(signature))
				assert.equal(signature.length, 64)
			})
		})

		describe("#verifyDetached(signature, pk)", function () {
			it("signature must be buffer of size 64", function () {
				const m = Buffer.from("hello world")
				const { sk, pk } = crypto.makeSigningKeyPair()
				const sig = crypto.signDetached(m, sk)
				const fakeSig = "sig"

				assert.doesNotThrow(() => {
					crypto.verifyDetached(sig, m, pk)
				})
				assert.throws(() => {
					crypto.verifyDetached(fakeSig, m, pk)
				})
			})

			it("pk must be Buffer of size 64", function () {
				const m = Buffer.from("hello world")
				const { sk, pk } = crypto.makeSigningKeyPair()
				const pkTooShort = Buffer.alloc(31, "pk")
				const pkTooLong = Buffer.alloc(33, "pk")

				const sig = crypto.signDetached(m, sk)

				assert.doesNotThrow(() => {
					crypto.verifyDetached(sig, m, pk)
				})
				assert.throws(() => {
					crypto.verifyDetached(sig, m, pkTooShort)
				})
				assert.throws(() => {
					crypto.verifyDetached(sig, m, pkTooLong)
				})
			})

			it("returns true iff signature is issued with corresponding secret key for passed public key", function () {
				const m = Buffer.from("hello world")
				const { sk, pk } = crypto.makeSigningKeyPair()
				const sig = crypto.signDetached(m, sk)

				const result = crypto.verifyDetached(sig, m, pk)
				assert.isTrue(result)
			})

			it("returns false iff signature is issued with other secret key than passed public key", function () {
				const m = Buffer.from("hello world")
				const { sk, _ } = crypto.makeSigningKeyPair()
				const otherPair = crypto.makeSigningKeyPair()
				const sig = crypto.signDetached(m, sk)

				const result = crypto.verifyDetached(sig, m, otherPair.pk)
				assert.isFalse(result)
			})
		})
	})
})
