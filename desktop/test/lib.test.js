const assert = require("node:assert/strict");
const { test } = require("node:test");
const { normalizeServer, classifyLoginResponse, networkMessage, VERCEL_WALL } = require("../lib");

test("normalizeServer accepts https addresses and keeps only the origin", () => {
  assert.deepEqual(normalizeServer("https://my-app.vercel.app"), { server: "https://my-app.vercel.app" });
  assert.deepEqual(normalizeServer("  https://my-app.vercel.app/some/path?x=1  "), { server: "https://my-app.vercel.app" });
});

test("normalizeServer adds https to a bare host", () => {
  assert.deepEqual(normalizeServer("my-app.vercel.app"), { server: "https://my-app.vercel.app" });
});

test("normalizeServer allows http only for this computer", () => {
  assert.deepEqual(normalizeServer("http://localhost:8000"), { server: "http://localhost:8000" });
  assert.deepEqual(normalizeServer("localhost:8000"), { server: "http://localhost:8000" });
  assert.deepEqual(normalizeServer("127.0.0.1:8000"), { server: "http://127.0.0.1:8000" });
  assert.match(normalizeServer("http://example.com").error, /https/);
});

test("normalizeServer rejects empty and invalid input", () => {
  assert.match(normalizeServer("").error, /Enter the address/);
  assert.match(normalizeServer(null).error, /Enter the address/);
  assert.match(normalizeServer("ftp://example.com").error, /https/);
  assert.ok(normalizeServer("https://").error);
});

test("classifyLoginResponse maps the API's answers", () => {
  const json = "application/json";
  assert.equal(classifyLoginResponse({ status: 401, contentType: json }), "Wrong username or password.");
  assert.equal(classifyLoginResponse({ status: 429, contentType: json, detail: "Too many failed attempts. Try again in 5 minutes." }), "Too many failed attempts. Try again in 5 minutes.");
  assert.match(classifyLoginResponse({ status: 429, contentType: json }), /Too many/);
  assert.match(classifyLoginResponse({ status: 503, contentType: json, detail: "Login is not configured on this server." }), /not configured/);
  assert.match(classifyLoginResponse({ status: 404, contentType: "text/html" }), /does not look like/);
  assert.match(classifyLoginResponse({ status: 502, contentType: "text/html" }), /problem/);
});

test("a web page instead of JSON on 401 or 403 is reported as Vercel's sign-in wall", () => {
  assert.equal(classifyLoginResponse({ status: 401, contentType: "text/html; charset=utf-8" }), VERCEL_WALL);
  assert.equal(classifyLoginResponse({ status: 403, contentType: "" }), VERCEL_WALL);
  assert.match(VERCEL_WALL, /Vercel Authentication/);
});

test("networkMessage names the host and the likely cause", () => {
  const dns = Object.assign(new TypeError("fetch failed"), { cause: new Error("net::ERR_NAME_NOT_RESOLVED") });
  assert.match(networkMessage(dns, "https://nope.example.com"), /Could not find nope\.example\.com/);
  assert.match(networkMessage(new Error("net::ERR_CONNECTION_REFUSED"), "http://localhost:8000"), /refused/);
  assert.match(networkMessage(new Error("net::ERR_CERT_AUTHORITY_INVALID"), "https://x.test"), /certificate/);
  assert.match(networkMessage(Object.assign(new Error("The operation was aborted due to timeout"), { name: "TimeoutError" }), "https://x.test"), /too long/);
  assert.match(networkMessage(new Error("boom"), "https://x.test"), /Could not reach x\.test/);
  assert.match(networkMessage(new Error("boom"), "not a url"), /Could not reach the server/);
});
