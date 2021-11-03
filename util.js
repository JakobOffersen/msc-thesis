const { isAsyncFunction } = require("util/types")

function callbackify(fn) {
    const SUCCESS = 0
    var fnLength = fn.length
    return function () {
        var args = [].slice.call(arguments)
        var ctx = this
        if (args.length === fnLength + 1 &&
            typeof args[fnLength] === 'function') {
            // callback mode
            var cb = args.pop()
            fn.apply(this, args)
                .then(function (val) {
                    cb.call(ctx, SUCCESS, val)
                })
                .catch(function (err) {
                    let code = -1
                    if (err instanceof FSError) {
                        code = err.code
                    }

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

module.exports = {
    callbackify,
    callbackifyHandlers
}