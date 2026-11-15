# Desktop app (Windows, macOS, Ubuntu/Linux)

A native window around your deployed Log Anomaly Detector, with a space-themed sign-in.

1. **Sign in.** The app opens on a sign-in screen. Use the same username and password as the website.
   The first time, open **Change** under the form and enter your server address (for example
   `https://your-app.vercel.app`). The app remembers the address and your username, never your password.
2. **Dashboard.** After sign-in your dashboard opens in the same window, with a starfield and nebula behind it.
   It is the website's own dashboard, so everything there works the same.
3. **Sign out** from the **App** menu (or the Sign out button in the dashboard). **App > Server settings...**
   changes the server. **Create an account or reset password** on the sign-in screen opens the website's own pages.

The app only talks to the server you set; every other link opens in your normal browser.

## If sign-in says the address is behind Vercel's sign-in

Vercel can put its own login in front of a site. If your Vercel project has **Vercel Authentication** switched on
for its `vercel.app` address, the app cannot reach your site's login. In Vercel, open the project, then
**Settings > Deployment Protection**, and turn off Vercel Authentication for production. Your site's own accounts
still protect the dashboard.

## Run it

```
cd desktop
npm install
npm start
npm test           # unit tests for the helper code
```

## Get the installers (no Windows or Mac needed)

GitHub builds them on its own Windows, Mac and Ubuntu machines.

1. Push a version tag from this repo: `git tag v1.2.0 && git push origin v1.2.0`
   (or open the **Actions** tab, choose **Desktop app**, and press **Run workflow**).
2. When the run finishes (about 5 to 10 minutes), download from the repo's **Releases** page (tag builds)
   or from the run's **Artifacts** (manual builds):
   - Windows: `Log-Anomaly-Detector-<version>-win-x64.exe` (installer) and a portable `.exe`
   - Ubuntu/Debian: `Log-Anomaly-Detector-<version>-linux-amd64.deb` and an `.AppImage`
   - macOS: `.dmg` for Apple Silicon (`arm64`) and Intel (`x64`), plus `.zip` versions

## First launch on an unsigned build

The installers are not code-signed (that needs paid developer certificates), so the operating system warns once.

- **Windows:** SmartScreen shows "Windows protected your PC". Click **More info**, then **Run anyway**.
- **macOS:** Control-click (right-click) the app, choose **Open**, then **Open** again. If macOS says the app is
  damaged, run `xattr -dr com.apple.quarantine "/Applications/Log Anomaly Detector.app"` once.

## Ubuntu

- Recommended: `sudo apt install ./Log-Anomaly-Detector-*-linux-amd64.deb`, then open it from the app menu.
- AppImage: `chmod +x Log-Anomaly-Detector-*.AppImage && ./Log-Anomaly-Detector-*.AppImage`. On Ubuntu 22.04 and later
  it needs `sudo apt install libfuse2`. On Ubuntu 24.04 its sandbox can be blocked by AppArmor; if it won't start, use the
  `.deb`, or add `--no-sandbox` as a last resort.

## Build on your own machine

```
cd desktop
npm install
npm run dist:win   # on Windows
npm run dist:mac   # on a Mac (macOS builds only work on a Mac)
npm run dist:linux # on Ubuntu or another Linux
npm run dist       # for the current system
```

Output goes to `desktop/dist/`. Icons come from `build/icon.png`.

## How it is built

| File | Role |
|---|---|
| `main.js` | Window, sign-in call to `/api/login`, session check, sign out, theme injection |
| `preload.js` | Gives the local sign-in page a small fixed API; the website gets none |
| `login.html` | The sign-in screen |
| `space.js` | The animated backdrop: stars, nebula, ringed planet, moon, shooting stars, rocket |
| `space-theme.css` | Recolors the website's dashboard and adds the starfield behind it |
| `lib.js` | Address checking and error messages (unit tested in `test/`) |

The password is sent once, over https, to your server's `/api/login`, and is never stored. The app keeps only the
session cookie your server sets. Animations pause when the window is hidden and stop if your system asks for reduced motion.
