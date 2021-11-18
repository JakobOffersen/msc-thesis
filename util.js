const { isAsyncFunction } = require("util/types")

class FSError extends Error {
    static operationNotSupported = new FSError(-100)

    constructor(code) {
        super()
        this.code = code
    }
}

function callbackify(fn) {
    const SUCCESS = 0
    const fnLength = fn.length
    
    return function () {
        const args = [].slice.call(arguments)
        const ctx = this
        if (args.length === fnLength + 1 &&
            typeof args[fnLength] === "function") {
            // callback mode
            const cb = args.pop()
            fn.apply(this, args)
                .then(function (val) {
                    cb.call(ctx, SUCCESS, val)
                })
                .catch(function (err) {
                    let code = -1
                    if (err instanceof FSError) {
                        code = err.code
                    }
                    console.error(err)

                    cb.call(ctx, code)
                })
            return
        }
        // promise mode
        return fn.apply(ctx, arguments)
    }
}

function callbackifyHandlers(handlers) {
    // Callbackify async handlers
    for (let key of Object.keys(handlers)) {
        const fn = handlers[key]
        if (isAsyncFunction(fn)) {
            handlers[key] = callbackify(fn)
        }
    }
}



function beforeShutdown(handler) {
    SHUTDOWN_HANDLERS.push(handler)
}

const SHUTDOWN_HANDLERS = []
const SHUTDOWN_SIGNALS = ["SIGINT", "SIGTERM", "uncaughtException"]
const exitHandler = async (signal) => {
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
    FSError,
    callbackify,
    callbackifyHandlers,
    beforeShutdown
}