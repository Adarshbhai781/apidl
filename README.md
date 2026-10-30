# apidl — HLS Stream Proxy API

Single-file Node.js API. CDN (classx.co.in / Akamai) ke required headers automatically lagata hai.

## Endpoints

| Purpose | URL |
|---|---|
| Stream (any player) | `/apidl?url=<m3u8-url>` |
| MP4 download | `/apidl?url=<m3u8-url>&dl=1` |
| Segment proxy | `/apidl?u=<segment-url>` |
| Custom headers | add `&ref=<referer>&ua=<user-agent>` |

## Run

```bash
npm install
npm start   # port 3000 (ya PORT env)
```

## Example

```
curl "https://<your-host>/apidl?url=https%3A%2F%2Fexample.com%2Fvideo.m3u8"
```
