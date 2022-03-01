function inversePromise() {
    var resolve, reject
    const promise = new Promise((_resolve, _reject) => {
        resolve = _resolve
        reject = _reject
    })

    return { promise, resolve, reject }
}

module.exports = {
    inversePromise
}
