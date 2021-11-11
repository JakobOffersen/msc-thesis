function inversePromise() {
	var promiseResolve, promiseReject
	const promise = new Promise((resolve, reject) => {
		promiseResolve = resolve
		promiseReject = reject
	})

	return { promise, promiseResolve, promiseReject }
}

module.exports = {
	inversePromise,
}
