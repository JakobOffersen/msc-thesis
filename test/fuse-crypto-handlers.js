const assert = require('chai').assert
const handlers = require('../fuse-crypto-handlers')
const path = require('path').join(__dirname, "/tmp/write-read-file.txt")
const fs = require('fs')
const crypto = require('../crypto')

describe("fuse-crypto-handlers.js", function() {
    beforeEach('setup test-file', function(done) {
        // this also overwrites the (potentially) existing test-file
        fs.open(path, 'w+', (err, _) => {
            done(err) // fails if err is truthy
        })
    })

    afterEach('teardown test-file', function(done) {
        fs.rm(path, (err) => {
            done(err) // fails if err is truthy
        })
    })

    it("writing small file and then reading same file", function(done) {
        const content = Buffer.from("hello world")
        handlers.write(path, "fd", content, content.length, 0, (err, length) => {
            console.log("Test received length: ", length, " and expected: ", content.length)
            assert.isTrue(length === content.length)

            const readBuffer = Buffer.alloc(content.length)

            handlers.read(path, "fd", readBuffer, content.length, 0, (length) => {
                assert.isTrue(length === content.length)
                assert.isTrue(Buffer.compare(content, readBuffer) === 0)
                done()
            })
        })
    })

    it('Writing file encrypts it', function(done) {
        const content = Buffer.from("hello world")

        handlers.write(path, "fd", content, content.length, 0, (err, length) => {
            assert.isTrue(length === content.length)

            // compare 'content' with what was written to 'path'
            fs.readFile(path, (err, data) => {
                if (err) return done(err)
                assert.isFalse(Buffer.compare(content, data) === 0) // '.compare' returns 0 when the two buffers are equal
                assert.isFalse(Buffer.compare(content, data.slice(crypto.NONCE_LENGTH)) === 0) // verify that the bytes after the nonce are differnet from 'content
                done()
            })
        })
    })

    it('Appending to existing file and then reading it', function(done) {
        const content1 = Buffer.from("hello world")
        const content2 = Buffer.from("many times!")
        const combined = Buffer.concat([content1, content2])

        handlers.write(path, "fd", content1, content1.length, 0, (err, length) => {
            assert.isTrue(length === content1.length)

            const endOfFirstWrite = content1.length
            handlers.write(path, "fd", content2, content2.length, endOfFirstWrite, (err, length) => {
                assert.isTrue(length === content2.length)

                const readBuffer = Buffer.alloc(content1.length + content2.length)
                handlers.read(path, "fd", readBuffer, readBuffer.length, 0, (length) => {
                    assert.isTrue(readBuffer.length === length)

                    assert.isTrue(Buffer.compare(combined, readBuffer) === 0) // .compare returns 0 when the two buffers are equal
                    done()
                })
            })
        })
    })

    it("Writing to arbitrary position in existing file and then reading it", function(done) {
        const initialContent = Buffer.from("Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum.")
        const contentToBeWritten = Buffer.from("Contrary to popular belief, Lorem Ipsum is not simply random text. It has roots in a piece of classical Latin literature from 45 BC, making it over 2000 years old. Richard McClintock, a Latin professor at Hampden-Sydney College in Virginia, looked up one of the more obscure Latin words, consectetur, from a Lorem Ipsum passage, and going through the cites of the word in classical literature, discovered the undoubtable source. Lorem Ipsum comes from sections 1.10.32 and 1.10.33 of de Finibus Bonorum et Malorum (The Extremes of Good and Evil) by Cicero, written in 45 BC. This book is a treatise on the theory of ethics, very popular during the Renaissance. The first line of Lorem Ipsum, Lorem ipsum dolor sit amet.., comes from a line in section 1.10.32.")
        const position = 87
        // write the initial content
        handlers.write(path, "fd", initialContent, initialContent.length, 0, (err, length) => {
            assert.isTrue(length === initialContent.length)

            handlers.write(path, "fd", contentToBeWritten, contentToBeWritten.length, position, (err, length) => {
                assert.isTrue(length === contentToBeWritten.length)

                const readBuffer = Buffer.alloc(initialContent.length + contentToBeWritten.length)
                handlers.read(path, "fd", readBuffer, readBuffer.length, 0, (length) => {
                    assert.isTrue(readBuffer.length === length)

                    // compute the expected result
                    const initialContentHeadSlice = initialContent.slice(0, position)
                    const initialContentTailSlice = initialContent.slice(position)
                    const expected = Buffer.concat([initialContentHeadSlice, contentToBeWritten, initialContentTailSlice])

                    assert.isTrue(Buffer.compare(expected, readBuffer) === 0) // .compare returns 0 when the two buffers are equal
                    done()
                })
            })
        })
    })

    it("Writing to arbitrary position in existing file and then reading arbitrary slice of it", function(done) {
        const initialContent = Buffer.from("Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum.")
        const contentToBeWritten = Buffer.from("Contrary to popular belief, Lorem Ipsum is not simply random text. It has roots in a piece of classical Latin literature from 45 BC, making it over 2000 years old. Richard McClintock, a Latin professor at Hampden-Sydney College in Virginia, looked up one of the more obscure Latin words, consectetur, from a Lorem Ipsum passage, and going through the cites of the word in classical literature, discovered the undoubtable source. Lorem Ipsum comes from sections 1.10.32 and 1.10.33 of de Finibus Bonorum et Malorum (The Extremes of Good and Evil) by Cicero, written in 45 BC. This book is a treatise on the theory of ethics, very popular during the Renaissance. The first line of Lorem Ipsum, Lorem ipsum dolor sit amet.., comes from a line in section 1.10.32.")
        const writePosition = 93
        const readPosition = 77
        const readLength = 496

        // write the initial content
        handlers.write(path, "fd", initialContent, initialContent.length, 0, (err, length) => {
            assert.isTrue(length === initialContent.length)

            handlers.write(path, "fd", contentToBeWritten, contentToBeWritten.length, writePosition, (err, length) => {
                assert.isTrue(length === contentToBeWritten.length)

                const readBuffer = Buffer.alloc(readLength)
                handlers.read(path, "fd", readBuffer, readBuffer.length, readPosition, (length) => {
                    assert.isTrue(readBuffer.length === length)

                    // compute the expected result
                    const initialContentHeadSlice = initialContent.slice(0, writePosition)
                    const initialContentTailSlice = initialContent.slice(writePosition)
                    const expectedFileContent =  Buffer.concat([initialContentHeadSlice, contentToBeWritten, initialContentTailSlice])
                    const expectedRead = expectedFileContent.slice(readPosition, readPosition + length)

                    assert.isTrue(Buffer.compare(expectedRead, readBuffer) === 0) // .compare returns 0 when the two buffers are equal
                    done()
                })
            })
        })
    })
})