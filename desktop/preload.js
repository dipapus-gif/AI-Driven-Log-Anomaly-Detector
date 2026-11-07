const { contextBridge, ipcRenderer } = require("electron");
contextBridge.exposeInMainWorld("desktop", {
  setServer: (address) => ipcRenderer.invoke("set-server", address),
  getServer: () => ipcRenderer.invoke("get-server"),
});
