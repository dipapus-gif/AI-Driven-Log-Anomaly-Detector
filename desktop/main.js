// Desktop shell for the Log Anomaly Detector web platform.
// It loads the same web app (and talks to the same backend) in its own window, remembers which
// server to use, and refuses to navigate anywhere else.
const { app, BrowserWindow, Menu, ipcMain, shell, session } = require("electron");
const fs = require("fs");
const path = require("path");

const configFile = () => path.join(app.getPath("userData"), "config.json");
let win = null;

function readServer() {
  try { return JSON.parse(fs.readFileSync(configFile(), "utf8")).server || ""; } catch { return ""; }
}
function writeServer(server) {
  fs.mkdirSync(path.dirname(configFile()), { recursive: true });
  fs.writeFileSync(configFile(), JSON.stringify({ server }));
}

// Accept https:// addresses, or http:// only for a server on this computer.
function normalizeServer(input) {
  let url;
  try { url = new URL(String(input).trim()); } catch { return { error: "That is not a valid address. Example: https://your-app.vercel.app" }; }
  const local = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
  if (url.protocol !== "https:" && !(url.protocol === "http:" && local)) {
    return { error: "Use an https:// address. Plain http:// is only allowed for localhost." };
  }
  return { server: url.origin };
}

function load() {
  const server = readServer();
  if (server) win.loadURL(server).catch(() => win.loadFile(path.join(__dirname, "connect.html"), { query: { failed: "1" } }));
  else win.loadFile(path.join(__dirname, "connect.html"));
}

function createWindow() {
  win = new BrowserWindow({
    width: 1360, height: 880, minWidth: 900, minHeight: 600, title: "Log Anomaly Detector",
    backgroundColor: "#0d1a2b",
    webPreferences: { preload: path.join(__dirname, "preload.js"), contextIsolation: true, nodeIntegration: false, sandbox: true },
  });
  // Stay on the configured server (or the local connect page); everything else opens in the browser.
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
  load();
}

ipcMain.handle("set-server", (_event, input) => {
  const result = normalizeServer(input);
  if (result.error) return result;
  writeServer(result.server);
  load();
  return { ok: true };
});
ipcMain.handle("get-server", () => readServer());

function buildMenu() {
  Menu.setApplicationMenu(Menu.buildFromTemplate([
    { label: "App", submenu: [
      { label: "Change server…", click: () => win && win.loadFile(path.join(__dirname, "connect.html")) },
      { label: "Reload", accelerator: "CmdOrCtrl+R", click: () => win && win.reload() },
      { type: "separator" }, { role: "quit" } ] },
    { role: "editMenu" },
    { label: "View", submenu: [{ role: "resetZoom" }, { role: "zoomIn" }, { role: "zoomOut" }, { role: "togglefullscreen" }] },
  ]));
}

app.whenReady().then(() => {
  // The dashboard needs no camera, microphone, location or notifications.
  session.defaultSession.setPermissionRequestHandler((_wc, _permission, callback) => callback(false));
  buildMenu();
  createWindow();
  app.on("activate", () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
});
app.on("window-all-closed", () => { if (process.platform !== "darwin") app.quit(); });
