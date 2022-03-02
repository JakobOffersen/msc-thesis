// This snippet shows that it is possible to restore a revision for a file
// that has more than 100 newer revisions to it.
// According to Dropbox API doc https://www.dropbox.com/developers/documentation/http/documentation#files-list_revisions
// it is at most possible to list the 100 newest revisions

const { Dropbox } = require("dropbox")
const { FSP_ACCESS_TOKEN } = require("../constants")

const dbx = new Dropbox({ accessToken: FSP_ACCESS_TOKEN })
const path = "/test-revisions.txt"
;(async () => {

    // Write to a remote file: 0, 1, then 2 ... up to 9.
    for (let i = 0; i < 10; i++) {
        await dbx.filesUpload({ path, mode: "overwrite", contents: i })
        console.log(i)
    }

    // Fetch the revisions for the 10 writes and save the oldest.
    const resp1 = await dbx.filesListRevisions({ path: path, limit: 10 })
    const revs = resp1.result.entries
    console.log("revs count:", revs.length)
    const firstRev = revs[revs.length - 1]

    console.log(`first rev: ${firstRev.rev}`)

    // Make 100 more writes to the remote path: 10, then 11, then 12 ... up to 110
    for (let i = 10; i <= 110; i++) {
        await dbx.filesUpload({ path, mode: "overwrite", contents: i })
        console.log(i)
    }

    // Request FSP to restore the first of the 110 writes.
    console.log("try restore to first rev...")
    await dbx.filesRestore({ path: path, rev: firstRev.rev })

    // Download the current revision. We expect this to contain "0"
    console.log("try download current revision...")
    const resp3 = await dbx.filesDownload({ path: path })

    console.log(resp3.result.fileBinary.toString()) // is "0"

})()
