const { isAsyncFunction } = require("util/types")

function callbackify(fn) {
    const SUCCESS = 0
    const fnLength = fn.length

    return function () {
        const args = [].slice.call(arguments)
        const ctx = this
        if (args.length === fnLength + 1 && typeof args[fnLength] === "function") {
            // callback mode
            const cb = args.pop()
            fn.apply(this, args)
                .then(function (val) {
                    cb.call(ctx, SUCCESS, val)
                })
                .catch(function (error) {
                    let code = error.errno || error.code || -999
                    if (code === -999) console.error(error)
                    cb.call(ctx, code)
                })
            return
        }
        // promise mode
        return fn.apply(ctx, arguments)
    }
}

function callbackifyHandlers(handlers) {
    const exlcuded = ["constructor"]
    const methods = Object.getOwnPropertyNames(Object.getPrototypeOf(handlers))
    const obj = {}

    // Callbackify async handlers
    for (let key of methods) {
        if (exlcuded.includes(key)) continue

        const fn = handlers[key]
        if (isAsyncFunction(fn)) {
            obj[key] = callbackify(fn).bind(handlers)
        }
    }

    return obj
}

async function sleep(duration) {
    return new Promise((resolve, _) => {
        setTimeout(resolve, duration)
    })
}

/**
 *
 * @param {*} fn - function to be retried
 * @param {*} until - function that determines if invocation was successful
 * @param {*} retries - number of times to retry before giving up
 * @returns
 */
async function retry(fn, until, retries = 10) {
    if (retries === 0) throw new Error(`Retry of fn ${fn.name ?? fn} failed`)
    try {
        const res = await fn()
        if (until(res)) return res
        throw new Error("is caught below")
    } catch (error) {
        await sleep(1000)
        return await retry(fn, until, retries - 1)
    }
}

function beforeShutdown(handler) {
    SHUTDOWN_HANDLERS.push(handler)
}

const SHUTDOWN_HANDLERS = []
const SHUTDOWN_SIGNALS = ["SIGINT", "SIGTERM", "uncaughtException"]
const exitHandler = async signal => {
    console.warn(`Shutting down: received ${signal}`)
    console.error(signal)

    for (let handler of SHUTDOWN_HANDLERS) {
        try {
            await handler()
        } catch (error) {
            console.error(error)
        }
    }

    return process.exit(0)
}

SHUTDOWN_SIGNALS.forEach(signal => process.once(signal, exitHandler))

module.exports = {
    callbackify,
    callbackifyHandlers,
    sleep,
    retry,
    beforeShutdown
}
