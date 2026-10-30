# apidl — HLS Stream Proxy API + AppX-style Player

Single-file Node.js API. CDN (classx.co.in / Akamai) ke required headers automatically lagata hai,
plus Parmar Academy / AppX platform jaisa web player built-in.

## Endpoints

| Purpose | URL |
|---|---|
| API status | `/` |
| Stream (any player) | `/apidl?url=<m3u8-url>` |
| MP4 download | `/apidl?url=<m3u8-url>&dl=1` |
| Segment proxy | `/apidl?u=<segment-url>` |
| Custom headers | add `&ref=<referer>&ua=<user-agent>` |
| **Player (AppX-style)** | `/player?url=<m3u8>&name=<title>&wm=<watermark>` |
| Player + quality list | `/player?url=<default>&urls=[{"name":"720p","url":"..."},...]` |
| **Link decryptor** | `/aes?data=<base64ct:base64iv>` |
| Bulk decrypt | `POST /aes {"all": <fetchVideoDetailsById data>}` |

## Player features (Parmar Academy / AppX jaisa)

- hls.js playback, sab requests proxy se (headers auto)
- **Select Quality** modal pehle khulta hai (Auto / 720p HD / 480p SD / 360p SD / 240p LOW / 144p LOW)
- Quality switch karte waqt **position preserve** hoti hai
- **Watermark** har 8 sec corners me float karta hai (`&wm=email%0Aphone`)
- **Resume**: localStorage `VIDEO_PROGRESS` (AppX jaisa hi key) — 5 sec me save, reload pe resume toast
- Speed menu (0.5x–2x), time format `MM:SS/HH:MM:SS`
- Snapshot button (PNG download), header bar (checkbox + title + close)
- `controlsList=nodownload`, `disablePictureInPicture` — AppX jaisa
- Keyboard: space/k, ← →, ↑ ↓, m, f, 0–9
- Auto-hide controls (3 sec), buffered indicator, error overlay + retry

## AES decryptor ("incept")

AppX/classx apps video links AES-128-CBC se encrypt karte hain: `base64(ct):base64(iv)`,
key hardcoded `638udh3829162018`, IV often `fedcba9876543210`.

```
GET  /aes?data=m7hcRs...==:ZmVkY2JhOTg3NjU0MzIxMA==
POST /aes  {"all": { ...fetchVideoDetailsById data... }}   # saare qualities decrypt + player link
```

## Run

```bash
npm install
npm start   # port 3000 (ya PORT env)
```
