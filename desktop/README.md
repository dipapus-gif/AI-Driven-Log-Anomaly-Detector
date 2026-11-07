# Desktop app

An Electron wrapper around the web platform. It opens your deployed site in its own window, remembers the server address, blocks navigation to other sites, and denies camera, microphone and location requests. Accounts, data and the AI analyst all stay on the server.

## Run it

```bash
cd desktop
npm install
npm start          # first launch asks for your server address, e.g. https://your-app.vercel.app
```

## Build installers

```bash
npm run dist       # Windows (.exe), macOS (.dmg) or Linux (AppImage, deb), for the OS you run it on
```

Installers appear in `desktop/dist/`. Build on each target OS (or use CI) because Electron packaging is per platform. The build is unsigned, so Windows SmartScreen and macOS Gatekeeper will warn on first run; code signing needs your own certificates.

To point it at a local server instead: `http://localhost:8000` is accepted. Other `http://` addresses are refused.
