"use strict";
// Pure helpers for the desktop shell (no Electron imports, so they can be unit tested with `npm test`).

const LOCAL_HOSTS = ["localhost", "127.0.0.1", "[::1]"];

const VERCEL_WALL =
  "This address is behind Vercel's own sign-in, so the app cannot reach your site. " +
  "In Vercel, open the project's Settings, then Deployment Protection, and turn off Vercel Authentication.";

// Accept https:// addresses, or http:// only for a server on this computer.
// A bare host such as "my-app.vercel.app" is treated as https.
function normalizeServer(input) {
  let text = String(input == null ? "" : input).trim();
  if (!text) return { error: "Enter the address of your server, for example https://your-app.vercel.app" };
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(text)) {
    const bare = text.toLowerCase();
    const isLocal = LOCAL_HOSTS.some((h) => bare === h || bare.startsWith(h + ":") || bare.startsWith(h + "/"));
    text = (isLocal ? "http://" : "https://") + text;
  }
  let url;
  try { url = new URL(text); } catch { return { error: "That is not a valid address. Example: https://your-app.vercel.app" }; }
  const local = LOCAL_HOSTS.includes(url.hostname);
  if (url.protocol !== "https:" && !(url.protocol === "http:" && local)) {
    return { error: "Use an https:// address. Plain http:// is only allowed for localhost." };
  }
  return { server: url.origin };
}

// Turn the server's answer to POST /api/login into a message for the person.
// `contentType` matters: the app's own API always answers in JSON, so a web page
// instead means something else (for example Vercel's sign-in wall) replied.
function classifyLoginResponse({ status, contentType, detail }) {
  const isJson = /json/i.test(contentType || "");
  if (!isJson && (status === 401 || status === 403)) return VERCEL_WALL;
  if (status === 401) return "Wrong username or password.";
  if (status === 429) return detail || "Too many attempts. Wait a few minutes and try again.";
  if (status === 503) return detail || "The server is not ready yet. Try again shortly.";
  if (status === 404 || status === 405) return "That address does not look like a Log Anomaly Detector server.";
  if (status >= 500) return "The server had a problem. Try again shortly.";
  return detail || `Sign-in failed (status ${status}).`;
}

// Turn a failed network request into a message for the person.
function networkMessage(error, server) {
  let host = "the server";
  try { host = new URL(server).host; } catch { /* keep the default */ }
  const text = String((error && ((error.cause && error.cause.message) || error.message)) || error || "");
  if (/ERR_NAME_NOT_RESOLVED/.test(text)) return `Could not find ${host}. Check the address.`;
  if (/ERR_CONNECTION_REFUSED/.test(text)) return `${host} refused the connection. Is the server running?`;
  if (/ERR_CERT|certificate/i.test(text)) return `The security certificate for ${host} was not accepted.`;
  if (/ERR_INTERNET_DISCONNECTED|ERR_NETWORK_CHANGED/.test(text)) return "No internet connection.";
  if (/abort|timeout|ERR_TIMED_OUT/i.test(text)) return `${host} took too long to answer. Try again.`;
  return `Could not reach ${host}. Check the address and your connection.`;
}

module.exports = { normalizeServer, classifyLoginResponse, networkMessage, VERCEL_WALL };
