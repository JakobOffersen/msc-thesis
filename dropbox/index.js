const { Dropbox } = require('dropbox')
const config = require("./config")
const path = require('path')
const accessToken = config['dropbox-app']['access-token']
const fs = require('fs')

const dbx = new Dropbox({ accessToken: accessToken })

// Reading a file from its shared link
const sharedLink = "https://www.dropbox.com/s/uhyec4gz64ljs7t/1.txt?dl=0"
const downloadFileFromSharedLink = (sharedLink) => {
    dbx.sharingGetSharedLinkFile({ url: sharedLink })
        .then((response) => {
            const result = response.result
            const path = "content/" + result.name
            fs.writeFile(path, result.fileBinary, 'binary', (err) => {
                if (err) { throw err }
                console.log(`File: ${result.name} saved as ${path}.`)
            })
        })
        .catch((err) => {
            console.log(err)
            throw err
        })
}

const filename = "/index.js"
const uploadFile = (filename) => {
    // Writing 'index.js' file to root of dropbox
    fs.readFile(path.join(__dirname, filename), (err, contents) => {
        if (err) { throw err }

        dbx.filesUpload({ path: filename, mode: "overwrite", contents })
            .then((response) => {
                console.log(response)
            })
            .catch((uploadErr) => {
                console.log(uploadErr)
            })
    })
}

// empty string denotes root-folder
const listFolder = (path) => {
    dbx.filesListFolder({ path: path })
        .then((response) => {
            console.log("cursor:", response.result.cursor)
            console.log("has_more:", response.result.has_more)
            console.log(`Folder '${path}' content:`)
            for (const entry of response.result.entries) {
                console.log(`> ${entry.name}`)
            }
        })
        .catch((err) => {
            console.log(err);
        });
}

const listFolderContinue = (cursor) => {
    console.log("list folder continue")
    dbx.filesListFolderContinue({ cursor: cursor })
        .then((response) => {
            console.log(response)
        })
        .catch((err) => console.log(err))
}

// 'path' can also point to a now deleted folder/file
const listFileRevisions = (path) => {
    dbx.filesListRevisions({ path: path })
        .then((response) => {
            console.log(`File '${path}' revisions:`)
            for (const entry of response.result.entries) {
                console.log("------")
                console.dir(entry)
            }
        })
        .catch((err) => {
            console.log(err)
        })
}

const downloadRevisionedFile = (revisionID) => {
    dbx.filesDownload({ path: "rev:" + revisionID })
        .then((response) => {
            console.log(response)
        })
        .catch((err) => {
            console.log(err)
        })
}

const downloadFileByPath = (path) => {
    dbx.filesDownload({ path: path })
        .then((response) => {
            console.log(response)
        })
        .catch((err) => {
            console.log(err)
        })
}

const deleteFileByPath = (path) => {
    dbx.filesDeleteV2({ path: path })
        .then((response) => {
            console.log(response)
        })
        .catch(err => console.log(err))
}

const longPoll = (cursor) => {
    console.log("long-polling...")
    dbx.filesListFolderLongpoll({ cursor: cursor })
        .then((response) => {
            console.log("Updates available")
            console.log(response)
            listFolderContinue(cursor)
        })
        .catch(err => console.log(err))
}

//downloadFileByPath("rev:015cd1ef70755cf00000002530d00f0")
//downloadFileByPath("/index.js")
// listFileRevisions("/index.js")
//uploadFile("/index.js")

// 015cd21315dea1200000002530d00f0
// 015cd1ef70755cf00000002530d00f0
const cursor = "AAFW5X5PVMHoMkjRoB5ajcw7IXGxmI_vs2Bh8s2RXe3hlrUaA8PFQ1Jy_xboMoz-sTxi7YMsSRBgDLVwhFLNCW2CAoQp0qLiSIR44lO294x5nS-2zc26k4q1B9MhYFAxbvZ3LLlFCSfV6H_kkUgq-7Dc3bpbD0j1h2alemmQInCjGJ_agZDfMLZPXN4kpxx5gqM"
longPoll(cursor)