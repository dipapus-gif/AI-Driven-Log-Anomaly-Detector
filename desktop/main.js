// Desktop shell for the Log Anomaly Detector web platform.
//
// Flow: a native space-themed sign-in screen (login.html) signs in with the same username and
// password as the website (POST /api/login), keeps the session cookie, and then opens the site's
// dashboard in this window with a space theme layered on top. The app stays on the configured
// server and sends every other link to the system browser.
const { app, BrowserWindow, Menu, ipcMain, shell, session } = require("electron");
const fs = require("fs");
const path = require("path");
const { normalizeServer, classifyLoginResponse, networkMessage } = require("./lib");

const LOGIN_PAGE = path.join(__dirname, "login.html");
const configFile = () => path.join(app.getPath("userData"), "config.json");
let win = null;

// ---- settings (server address and last username; never the password) -----------------------

function readConfig() {
  try {
    const c = JSON.parse(fs.readFileSync(configFile(), "utf8"));
    return { server: typeof c.server === "string" ? c.server : "", username: typeof c.username === "string" ? c.username : "" };
  } catch { return { server: "", username: "" }; }
}
function writeConfig(patch) {
  fs.mkdirSync(path.dirname(configFile()), { recursive: true });
  fs.writeFileSync(configFile(), JSON.stringify({ ...readConfig(), ...patch }));
}
const readServer = () => readConfig().server;

// ---- talking to the server -------------------------------------------------------------------

// Uses the window's own cookie jar, so the session cookie from /api/login is what the dashboard sees.
function api(server, route, init = {}) {
  return session.defaultSession.fetch(server + route, { credentials: "include", signal: AbortSignal.timeout(15000), ...init });
}

async function login(server, username, password) {
  let res;
  try {
    res = await api(server, "/api/login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
  } catch (error) { return { error: networkMessage(error, server) }; }

  const contentType = res.headers.get("content-type") || "";
  let body = null;
  if (/json/i.test(contentType)) { try { body = await res.json(); } catch { body = null; } }
  if (!res.ok) {
    return { error: classifyLoginResponse({ status: res.status, contentType, detail: body && typeof body.detail === "string" ? body.detail : "" }) };
  }
  if (!body || typeof body.user !== "string") return { error: "That address does not look like a Log Anomaly Detector server." };
  return { ok: true };
}

// ---- windows and pages --------------------------------------------------------------------------

function showLogin(query = {}) { return win.loadFile(LOGIN_PAGE, { query }); }
function openSite(server) { return win.loadURL(server); }

async function start() {
  const server = readServer();
  if (!server) return showLogin();
  try {
    const res = await api(server, "/api/session");
    if (res.ok) return openSite(server);   // still signed in from last time
    return showLogin();
  } catch { return showLogin({ failed: "1" }); }
}

async function signOut() {
  const server = readServer();
  if (server) {
    try { await api(server, "/api/logout", { method: "POST" }); } catch { /* offline: just clear locally */ }
    try { await session.defaultSession.clearStorageData({ origin: server, storages: ["cookies"] }); } catch { /* ignore */ }
  }
  return showLogin();
}

// Layer the space look over the website: starfield canvas behind the page plus recolored panels.
const THEME_CSS = fs.readFileSync(path.join(__dirname, "space-theme.css"), "utf8");
const SPACE_JS = fs.readFileSync(path.join(__dirname, "space.js"), "utf8");
const THEME_JS = `${SPACE_JS}
;(function () {
  if (document.getElementById("space-bg")) return;
  var canvas = document.createElement("canvas");
  canvas.id = "space-bg"; canvas.setAttribute("aria-hidden", "true");
  document.body.insertBefore(canvas, document.body.firstChild);
  document.documentElement.setAttribute("data-theme", "dark");
  window.SpaceBackdrop.mount(canvas, { mode: "ambient" });
})();`;

function themeSite() {
  const server = readServer();
  const url = win && win.webContents.getURL();
  if (!server || !url || !url.startsWith(server)) return;
  win.webContents.insertCSS(THEME_CSS).catch(() => {});
  win.webContents.executeJavaScript(THEME_JS).catch(() => {});
}

function createWindow() {
  win = new BrowserWindow({
    width: 1360, height: 880, minWidth: 900, minHeight: 600, title: "Log Anomaly Detector",
    backgroundColor: "#05030d", show: false,
    webPreferences: { preload: path.join(__dirname, "preload.js"), contextIsolation: true, nodeIntegration: false, sandbox: true },
  });
  win.once("ready-to-show", () => win.show());

  // Stay on the configured server (or the local sign-in page); everything else opens in the browser.
  win.webContents.on("will-navigate", (event, target) => {
    const allowed = readServer();
    if (target.startsWith("file://")) return;
    if (allowed && new URL(target).origin === allowed) return;
    event.preventDefault();
    if (/^https?:/.test(target)) shell.openExternal(target);
  });
  win.webContents.setWindowOpenHandler(({ url }) => {
    if (/^https?:/.test(url)) shell.openExternal(url);
    return { action: "deny" };
  });
  win.webContents.on("did-finish-load", themeSite);
  win.webContents.on("did-fail-load", (_event, code, _description, url, isMainFrame) => {
    if (!isMainFrame || code === -3 || String(url).startsWith("file:")) return;   // -3 means the load was cancelled
    showLogin({ failed: "1" });
  });
  start();
}

// ---- messages from the sign-in page --------------------------------------------------------

// Only the local sign-in page may use these; the website never can.
function fromSignInPage(event) {
  try {
    const url = new URL(event.senderFrame.url);
    return url.protocol === "file:" && path.basename(decodeURIComponent(url.pathname)) === "login.html";
  } catch { return false; }
}

ipcMain.handle("get-config", (event) => (fromSignInPage(event) ? readConfig() : { server: "", username: "" }));

ipcMain.handle("login", async (event, credentials) => {
  if (!fromSignInPage(event)) return { error: "Not allowed." };
  const { server: input, username, password } = credentials || {};
  const checked = normalizeServer(input);
  if (checked.error) return checked;
  const name = String(username || "").trim();
  if (!name || !password) return { error: "Enter your username and password." };
  const result = await login(checked.server, name, String(password));
  if (!result.ok) return result;
  writeConfig({ server: checked.server, username: name });
  openSite(checked.server);
  return { ok: true };
});

// "Create an account or reset password": the website's own pages handle those.
ipcMain.handle("open-site", (event, input) => {
  if (!fromSignInPage(event)) return { error: "Not allowed." };
  const checked = normalizeServer(input);
  if (checked.error) return checked;
  writeConfig({ server: checked.server });
  openSite(checked.server);
  return { ok: true };
});

// ---- menu and app lifecycle ----------------------------------------------------------------

function buildMenu() {
  Menu.setApplicationMenu(Menu.buildFromTemplate([
    { label: "App", submenu: [
      { label: "Sign out", click: () => win && signOut() },
      { label: "Server settings…", click: () => win && showLogin({ server: "1" }) },
      { label: "Reload", accelerator: "CmdOrCtrl+R", click: () => win && win.reload() },
      { type: "separator" }, { role: "quit" } ] },
    { role: "editMenu" },
    { label: "View", submenu: [{ role: "resetZoom" }, { role: "zoomIn" }, { role: "zoomOut" }, { role: "togglefullscreen" }] },
  ]));
}

if (!app.requestSingleInstanceLock()) {
  app.quit();
} else {
  app.on("second-instance", () => { if (win) { if (win.isMinimized()) win.restore(); win.focus(); } });
  app.whenReady().then(() => {
    // The dashboard needs no camera, microphone, location or notifications.
    session.defaultSession.setPermissionRequestHandler((_wc, _permission, callback) => callback(false));
    buildMenu();
    createWindow();
    app.on("activate", () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
  });
  app.on("window-all-closed", () => { if (process.platform !== "darwin") app.quit(); });
}
