Object.defineProperty(exports, "__esModule", { value: true })

if typeof window == "object"
    browser = require("./cryptoutilsbrowser")
    Object.assign(exports, browser)
else
    node = require("./cryptoutilsnode")
    Object.assign(exports, node)
