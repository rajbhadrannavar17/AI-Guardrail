const fs = require("node:fs");
const vm = require("node:vm");
const assert = require("node:assert/strict");

const source = fs.readFileSync(`${__dirname}/scanner.js`, "utf8");
const context = { window: {} };
vm.createContext(context);
vm.runInContext(source, context);

const scanner = context.window.AIGuardrailScanner;

assert.equal(scanner.inspectText("Explain phishing in simple terms").action, "allow");
assert.equal(scanner.inspectText("my api key is 6788").action, "block");
assert.equal(scanner.inspectText("my password is test1234").action, "block");
assert.equal(scanner.inspectText("admin password is xxx").action, "block");
assert.equal(scanner.inspectText("admin password as xxx").action, "block");
assert.equal(scanner.inspectText("prod bearer token is abc").action, "block");
assert.equal(scanner.inspectText("OPENAI_API_KEY=sk-example-value-for-demo-only").action, "block");

console.log("extension scanner checks passed");
