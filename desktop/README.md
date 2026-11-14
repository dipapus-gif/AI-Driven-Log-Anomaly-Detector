# Desktop app (Windows, macOS, Linux)

A native window around your deployed Log Anomaly Detector. On first launch it asks for your server address
(for example `https://your-app.vercel.app`), remembers it, and refuses to navigate anywhere else.

## Get the installers (no Windows or Mac needed)

GitHub builds them on its own Windows and Mac machines.

1. Push a version tag from this repo: `git tag v1.1.0 && git push origin v1.1.0`
   (or open the **Actions** tab, choose **Desktop app**, and press **Run workflow**).
2. When the run finishes (about 5 to 10 minutes), download from the repo's **Releases** page (tag builds)
   or from the run's **Artifacts** (manual builds):
   - Windows: `Log-Anomaly-Detector-<version>-win-x64.exe` (installer) and a portable `.exe`
   - macOS: `.dmg` for Apple Silicon (`arm64`) and Intel (`x64`), plus `.zip` versions

## First launch on an unsigned build

The installers are not code-signed (that needs paid developer certificates), so the operating system warns once.

- **Windows:** SmartScreen shows "Windows protected your PC". Click **More info**, then **Run anyway**.
- **macOS:** Control-click (right-click) the app, choose **Open**, then **Open** again. If macOS says the app is
  damaged, run `xattr -dr com.apple.quarantine "/Applications/Log Anomaly Detector.app"` once.

## Build on your own machine

```
cd desktop
npm install
npm start          # run it
npm run dist:win   # on Windows
npm run dist:mac   # on a Mac (macOS builds only work on a Mac)
npm run dist       # for the current system
```

Output goes to `desktop/dist/`. Icons come from `build/icon.png`.
