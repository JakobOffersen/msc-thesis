// This snippet shows how Dropbox revisions work.
// What the snippet does:
//  1) Creates 3 revisions of a file
//  2) Prints all 3 revisions
//  3) Restores the file back to its second revisions
//  3) Prints the file content, which is the second revision
//  4) Prints all 4 revisions.
//     This step shows that restoring a file also prepends a unique ID to the revision log.

const { Dropbox } = require("dropbox")
const dbx = new Dropbox({ accessToken: "your-access-token-here" })
const remoteFilePath = "/test-file.txt"

;(async () => {
    // writes "r1", then "r2" then "r3" to the remote file to create 3 revisions of the file
    for (const version of ["r1", "r2", "r3"]) {
        await dbx.filesUpload({ path: remoteFilePath, mode: "overwrite", contents: version })
    }
    // downloads and prints the 3 revisions
    const entries1 = (await dbx.filesListRevisions({ path: remoteFilePath, mode: "path" })).result.entries
    console.log(entries1.map(entry => entry.rev)) // ['015d70627251361...', '015d706271a07ac...', '015d706270b981f...']

    // Restore the file back to "r2"
    await dbx.filesRestore({ path: remoteFilePath, rev: entries1[1].rev })

    // downloads the current file and prints it
    const response = await dbx.filesDownload({ path: remoteFilePath })
    console.log(response.result.fileBinary.toString()) // "r2"

    // downloads and prints the 4 revisions
    const entries2 = (await dbx.filesListRevisions({ path: remoteFilePath, mode: "path" })).result.entries
    console.log(entries2.map(entry => entry.rev)) // ['015d70627910d41...', '015d70627251361...', '015d706271a07ac...', '015d706270b981f...']
})()
