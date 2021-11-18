const fs = require('fs/promises')
const path = require('path')

function inversePromise() {
	var resolve, reject
	const promise = new Promise((_resolve, _reject) => {
		resolve = _resolve
		reject = _reject
	})

	return { promise, resolve, reject }
}

async function setupLocalAndRemoteTestFolder(dirname, testFolderName, fsp) {
	// setup local test-dir if needed
	try {
		await fs.access(path.join(dirname, testFolderName))
	} catch {
		await fs.mkdir(path.join(dirname, testFolderName))
	}

	try {
		// Create FSP test-directory if it does not already exist
		await fsp.createDirectory(testFolderName)
	} catch (err) {
		// if 409 is returned, it means the folder already exist.
		if (err.status !== 409) {
			throw err
		}
	}
}

async function clearLocalAndRemoteTestFolderIfNecessary(dirname, testFolderName, fsp) {
    // Clear remote folder by deleting it and creating it again
    await fsp.deleteDirectory(testFolderName)
    await fsp.createDirectory(testFolderName)

    // clear local folder by removing it and creating it again
    const localTestPath = path.join(dirname, testFolderName)
    await fs.rm(localTestPath, { recursive: true, force: true })
    await fs.mkdir(localTestPath)
}

async function teardownLocalAndRemoteTestFolder(dirname, testFolderName, fsp) {
    // tear-down fsp test-directory
	await fsp.deleteDirectory(testFolderName)

	// tear-down local test directory
	await fs.rm(path.join(dirname, testFolderName), {
		recursive: true,
		force: true,
	})
}

module.exports = {
	inversePromise,
    setupLocalAndRemoteTestFolder,
    clearLocalAndRemoteTestFolderIfNecessary,
    teardownLocalAndRemoteTestFolder
}
