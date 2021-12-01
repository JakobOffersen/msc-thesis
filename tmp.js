const queue = require('async/queue')

const q = queue(async (task) => {
    console.log("processing task", task)
    return await new Promise((resolve, reject) => {
        setTimeout(() => {
            if (task === "test") reject("no test allowed")
            else resolve("completed")
        }, 3000)
    })
})

q.drain(() => {
    console.log("drained")
})

q.error((error, task) => {
    console.log("error", error, task)
})

q.push("hello world", (err, result) => {
    if (err) console.log("err", err)
    else console.log("push", result)
})

q.push("test", (err, result) => {
    if (err) console.log("err", err)
    else console.log("push", result)
})