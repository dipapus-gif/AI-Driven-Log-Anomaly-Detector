// Exposes a small, fixed API to the local sign-in page only. The dashboard (the remote site) gets nothing.
const { contextBridge, ipcRenderer } = require("electron");

if (location.protocol === "file:") {
  contextBridge.exposeInMainWorld("desktop", {
    getConfig: () => ipcRenderer.invoke("get-config"),
    login: (credentials) => ipcRenderer.invoke("login", credentials),
    openSite: (server) => ipcRenderer.invoke("open-site", server),
  });
}
