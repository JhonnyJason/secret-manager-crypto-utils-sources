Object.defineProperty(exports, "__esModule", { value: true })

if typeof window == "object"
    browser = require("./browser")
    Object.assign(exports, browser)
else
    node = require("./node")
    Object.assign(exports, node)
