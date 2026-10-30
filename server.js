/*
 * apidl — HLS Stream Proxy API + AppX-style Player (single-file Node.js server)
 * -----------------------------------------------------------------------------
 * GET  /                                     -> API status JSON
 * GET  /apidl?url=<m3u8-url>                 -> playable playlist (headers auto-attached)
 * GET  /apidl?url=<m3u8-url>&dl=1            -> single MP4 download stream (ffmpeg, no re-encode)
 * GET  /apidl?u=<segment-or-key-url>         -> segment/key stream proxy (Range passthrough)
 * GET  /apidl?url=...&ref=<referer>&ua=<ua>  -> custom header overrides
 * GET  /player?url=<m3u8>&name=<title>&wm=<watermark>&urls=<json>
 *                                            -> AppX-style web player (hls.js, quality, watermark,
 *                                               resume, speed, snapshot, fullscreen)
 * GET  /aes?data=<base64ct:base64iv>[&key=]  -> decrypt AppX encrypted video link ("incept")
 * POST /aes  {"data"|"all": ..., "key": ...} -> bulk decrypt fetchVideoDetailsById payload
 *
 * Zero framework. Node 18+ (built-in fetch + crypto). ffmpeg only needed for dl=1.
 */

const http = require("http");
const { Readable } = require("stream");
const { spawn } = require("child_process");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const PORT = process.env.PORT || 3000;

// ---- Headers without which the CDN returns 403/404 ----
const DEFAULT_HEADERS = {
  Referer: "https://player-strict.akamai.net.in/",
  "User-Agent":
    "Dalvik/2.1.0 (Linux; U; Android 16; RMX5110 Build/BP2A.250605.015)",
};

// Default AES key/IV used by AppX / classx platforms to encrypt video links
const DEFAULT_AES_KEY = "638udh3829162018";
const DEFAULT_AES_IV = "fedcba9876543210";

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "*",
};

// ---- ffmpeg resolution: ./ffmpeg (BtbN static) -> ffmpeg-static -> system ----
let FFMPEG = path.join(__dirname, "ffmpeg");
if (!fs.existsSync(FFMPEG)) {
  try {
    const st = require("ffmpeg-static");
    if (st && fs.existsSync(st)) FFMPEG = st;
    else FFMPEG = "ffmpeg";
  } catch {
    FFMPEG = "ffmpeg";
  }
}

// ---------------- helpers ----------------

function buildUpstreamHeaders(ref, ua) {
  const h = { ...DEFAULT_HEADERS };
  if (ref) h.Referer = ref;
  if (ua) h["User-Agent"] = ua;
  return h;
}

function proxify(uri, baseUrl, params) {
  let abs;
  try {
    abs = new URL(uri, baseUrl).href;
  } catch {
    return uri;
  }
  const p = new URLSearchParams(params);
  p.delete("u");
  p.delete("url");
  p.delete("dl");
  p.set("u", abs);
  return `/apidl?${p.toString()}`;
}

const URI_ATTR_RE = /URI="([^"]+)"/g;

function rewritePlaylist(text, playlistUrl, params) {
  const out = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line) {
      out.push("");
    } else if (line.startsWith("#")) {
      out.push(
        line.replace(URI_ATTR_RE, (_m, uri) => `URI="${proxify(uri, playlistUrl, params)}"`)
      );
    } else {
      out.push(proxify(line, playlistUrl, params));
    }
  }
  return out.join("\n");
}

function isPlaylistUrl(u) {
  try {
    const p = new URL(u).pathname.toLowerCase();
    return p.endsWith(".m3u8") || p.endsWith(".m3u");
  } catch {
    return false;
  }
}

function contentTypeFor(u) {
  try {
    const p = new URL(u).pathname.toLowerCase();
    if (p.endsWith(".ts")) return "video/mp2t";
    if (p.endsWith(".m4s")) return "video/iso.segment";
    if (p.endsWith(".mp4")) return "video/mp4";
    if (p.endsWith(".aac")) return "audio/aac";
  } catch {
    /* noop */
  }
  return "application/octet-stream";
}

function fileNameFor(u) {
  try {
    const base = new URL(u).pathname.split("/").filter(Boolean).pop() || "video";
    return base.replace(/\.[a-z0-9]+$/i, "").replace(/[^a-zA-Z0-9_-]+/g, "_").slice(0, 80) || "video";
  } catch {
    return "video";
  }
}

function sendJson(res, status, obj) {
  const body = JSON.stringify(obj, null, 2);
  res.writeHead(status, { "Content-Type": "application/json", ...CORS });
  res.end(body);
}

function sendError(res, status, msg) {
  sendJson(res, status, {
    error: msg,
    usage: "/apidl?url=<m3u8-url>&dl=1&ref=<referer>&ua=<user-agent>",
  });
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on("data", (c) => {
      size += c.length;
      if (size > 2 * 1024 * 1024) {
        reject(new Error("Body too large"));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

// ---------------- AES decryptor ("incept") ----------------
//
// AppX/classx platforms encrypt every video link as  AES-128-CBC( key, iv )
// then ship it as  base64(ciphertext) ":" base64(iv)  — e.g.:
//   "ODW2lUgMPeC0w+MR...:ZmVkY2JhOTg3NjU0MzIxMA=="
// base64-decoding the second part gives the IV (often "fedcba9876543210").
// The key is hardcoded in the app: 638udh3829162018

function pkcs7Unpad(buf) {
  const pad = buf[buf.length - 1];
  if (pad < 1 || pad > 16) return buf; // not padded / wrong key
  return buf.subarray(0, buf.length - pad);
}

function aesDecryptUrl(encString, keyStr, ivStr) {
  let ctB64 = encString;
  let ivB64 = null;
  const idx = encString.lastIndexOf(":");
  if (idx > 8 && /^[A-Za-z0-9+/=]+$/.test(encString.slice(idx + 1))) {
    ctB64 = encString.slice(0, idx);
    ivB64 = encString.slice(idx + 1);
  }
  let iv;
  if (ivB64) {
    const decoded = Buffer.from(ivB64, "base64").toString("utf8").trim();
    // IV may itself be base64 (iv_string style is double encoded)
    if (/^[A-Za-z0-9+/=]+$/.test(decoded) && decoded.endsWith("==") && decoded.length === 24) {
      const raw = Buffer.from(decoded, "base64");
      iv = raw.length === 16 ? raw : Buffer.from(decoded, "utf8").subarray(0, 16);
    } else {
      iv = Buffer.from(decoded, "utf8").subarray(0, 16);
    }
  } else if (ivStr) {
    iv = Buffer.from(ivStr, "utf8").subarray(0, 16);
  } else {
    iv = Buffer.from(DEFAULT_AES_IV, "utf8");
  }
  if (iv.length < 16) throw new Error("IV must be 16 bytes");
  const key = Buffer.from((keyStr || DEFAULT_AES_KEY), "utf8").subarray(0, 16);
  const decipher = crypto.createDecipheriv("aes-128-cbc", key, iv);
  const out = Buffer.concat([decipher.update(Buffer.from(ctB64, "base64")), decipher.final()]);
  return pkcs7Unpad(out).toString("utf8").replace(/[\x00-\x1f]+$/g, "");
}

function looksEncrypted(s) {
  return typeof s === "string" && s.length > 24 && /^[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+$/.test(s);
}

function bulkDecrypt(payload, keyStr) {
  // Accepts the `data` object of /get/fetchVideoDetailsById (or a list item of
  // /get/livecourseclassbycoursesubtopconceptapiv3) and decrypts every link field.
  const result = { title: payload.Title || payload.title || "", qualities: [], other: {} };
  const put = (k, v) => {
    if (typeof v !== "string" || !v) return;
    try {
      const dec = aesDecryptUrl(v, keyStr);
      if (/^https?:\/\//.test(dec)) result.other[k] = dec;
    } catch {
      /* leave undecryptable fields out */
    }
  };
  if (looksEncrypted(payload.file_link || "")) {
    try {
      result.file_url = aesDecryptUrl(payload.file_link, keyStr);
    } catch {}
  }
  const links = payload.encrypted_links || [];
  for (const el of links) {
    const enc = el.path || el.url || "";
    if (!enc) continue;
    try {
      const dec = aesDecryptUrl(enc, keyStr);
      if (/^https?:\/\//.test(dec)) {
        result.qualities.push({
          name: el.quality || String(result.qualities.length),
          url: dec,
        });
      }
    } catch {}
  }
  [
    "download_url_higher_version",
    "download_url_lower_version",
    "download_link2",
    "video_player_url",
    "video_player_lower_url",
  ].forEach((k) => put(k, payload[k]));
  result.qualities.sort((a, b) => parseInt(b.name) - parseInt(a.name));
  return result;
}

// ---------------- MP4 download (dl=1) ----------------

function mp4Download(target, headers, req, res) {
  const headerStr =
    Object.entries(headers)
      .map(([k, v]) => `${k}: ${v}`)
      .join("\r\n") + "\r\n";

  const proc = spawn(
    FFMPEG,
    [
      "-hide_banner",
      "-loglevel", "error",
      "-headers", headerStr,
      "-i", target,
      "-c", "copy",
      "-bsf:a", "aac_adtstoasc",
      "-movflags", "frag_keyframe+empty_moov+default_base_moof",
      "-f", "mp4",
      "pipe:1",
    ],
    { stdio: ["ignore", "pipe", "pipe"] }
  );

  let stderr = "";
  proc.stderr.on("data", (d) => (stderr = (stderr + d).slice(-4000)));
  proc.on("error", (e) => {
    console.error("[apidl] ffmpeg spawn error:", e.message);
    if (!res.headersSent) sendError(res, 500, "ffmpeg not available for dl=1");
  });
  proc.on("close", (code, sig) => {
    console.log(`[apidl] ffmpeg closed code=${code} sig=${sig} stderr=${stderr.slice(-300)}`);
    if (!res.writableEnded) res.end();
  });

  req.on("aborted", () => {
    try {
      proc.kill("SIGKILL");
    } catch {}
  });

  res.writeHead(200, {
    "Content-Type": "video/mp4",
    "Content-Disposition": `attachment; filename="${fileNameFor(target)}.mp4"`,
    "Cache-Control": "no-store",
    ...CORS,
  });
  proc.stdout.pipe(res);
}

// ---------------- main /apidl handler ----------------

async function handleApidl(req, res, searchParams) {
  const target = searchParams.get("u") || searchParams.get("url");
  const dl = searchParams.get("dl") === "1";
  const ref = searchParams.get("ref");
  const ua = searchParams.get("ua");

  if (!target) return sendError(res, 400, "Missing ?url= parameter");

  let parsed;
  try {
    parsed = new URL(target);
  } catch {
    return sendError(res, 400, "Invalid URL");
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return sendError(res, 400, "Only http/https allowed");
  }

  const headers = buildUpstreamHeaders(ref, ua);
  const controller = new AbortController();
  req.on("aborted", () => controller.abort());

  // dl=1 must be checked FIRST (before playlist mode)
  if (dl) return mp4Download(target, headers, req, res);

  try {
    // ---------- playlist mode ----------
    if (isPlaylistUrl(target)) {
      const upstream = await fetch(target, {
        headers,
        redirect: "follow",
        signal: controller.signal,
      });
      if (!upstream.ok) {
        return sendError(res, 502, `Upstream ${upstream.status} ${upstream.statusText}`);
      }
      const text = await upstream.text();
      if (!text.includes("#EXTM3U")) {
        res.writeHead(upstream.status, {
          "Content-Type": contentTypeFor(target),
          ...CORS,
        });
        return res.end(text);
      }
      const rewritten = rewritePlaylist(text, upstream.url || target, searchParams);
      res.writeHead(200, {
        "Content-Type": "application/vnd.apple.mpegurl",
        "Cache-Control": "no-store",
        ...CORS,
      });
      return res.end(rewritten);
    }

    // ---------- segment / key mode ----------
    const fwd = { ...headers };
    const range = req.headers.range;
    if (range) fwd.Range = range;

    const upstream = await fetch(target, {
      headers: fwd,
      redirect: "follow",
      signal: controller.signal,
    });
    if (!upstream.ok && upstream.status !== 206) {
      return sendError(res, 502, `Upstream ${upstream.status} ${upstream.statusText}`);
    }

    const out = {
      "Content-Type": upstream.headers.get("content-type") || contentTypeFor(target),
      "Cache-Control": "no-store",
      "Accept-Ranges": "bytes",
      ...CORS,
    };
    const cl = upstream.headers.get("content-length");
    if (cl) out["Content-Length"] = cl;
    const cr = upstream.headers.get("content-range");
    if (cr) out["Content-Range"] = cr;

    res.writeHead(upstream.status, out);
    if (!upstream.body) return res.end();

    const nodeStream = Readable.fromWeb(upstream.body);
    nodeStream.pipe(res);
    nodeStream.on("error", () => {
      if (!res.writableEnded) res.end();
    });
  } catch (e) {
    if (e && e.name === "AbortError") {
      if (!res.writableEnded) res.end();
      return;
    }
    if (!res.headersSent) {
      sendError(res, 502, `Fetch failed: ${(e && e.message) || "unknown"}`);
    } else if (!res.writableEnded) {
      res.end();
    }
  }
}

// ---------------- player page ----------------

const HLS_JS_CDN = "https://cdn.jsdelivr.net/npm/hls.js@1.5.20/dist/hls.min.js";

function esc(s) {
  return String(s == null ? "" : s)
    .replace(/&/g, "&amp;")
    .replace(/"/g, "&quot;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function playerPage(q) {
  const url = q.get("url") || "";
  const name = q.get("name") || "Video";
  const wm = q.get("wm") || "";
  const ref = q.get("ref") || "";
  const ua = q.get("ua") || "";
  const urlsRaw = q.get("urls") || "";
  const t0 = parseFloat(q.get("t") || "0") || 0;
  // proxy src for the chosen url — headers ride along automatically
  const src = url
    ? "/apidl?url=" + encodeURIComponent(url) +
      (ref ? "&ref=" + encodeURIComponent(ref) : "") +
      (ua ? "&ua=" + encodeURIComponent(ua) : "")
    : "";
  // optional pre-decrypted quality list  [{"name":"720p","url":"..."},...]
  let urlsJson = "[]";
  try {
    const arr = JSON.parse(urlsRaw || "[]");
    if (Array.isArray(arr)) {
      urlsJson = JSON.stringify(
        arr
          .filter((x) => x && x.url)
          .map((x) => ({
            name: String(x.name || "quality"),
            url:
              "/apidl?url=" + encodeURIComponent(x.url) +
              (ref ? "&ref=" + encodeURIComponent(ref) : "") +
              (ua ? "&ua=" + encodeURIComponent(ua) : ""),
          }))
      );
    }
  } catch {}
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>${esc(name)}</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; -webkit-tap-highlight-color: transparent; }
  html, body { height: 100%; background: #000; overflow: hidden;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif; }
  #stage { position: fixed; inset: 0; display: flex; flex-direction: column; }
  /* ---- header bar (AppX modal style) ---- */
  #headbar { display: none; align-items: center; gap: 10px; background: #fff;
    padding: 10px 14px; z-index: 30; }
  #headbar.on { display: flex; }
  #headbar input[type=checkbox] { width: 16px; height: 16px; accent-color: #e91e63; cursor: pointer; }
  #vtitle { flex: 1; font-size: 15px; font-weight: 700; color: #212121;
    white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  #headclose { border: 0; background: #eee; color: #555; width: 26px; height: 26px;
    border-radius: 50%; font-size: 13px; cursor: pointer; line-height: 1; }
  /* ---- video ---- */
  #vwrap { position: relative; flex: 1; background: #000; overflow: hidden; }
  video { width: 100%; height: 100%; object-fit: contain; background: #000; display: block; }
  /* ---- watermark (AppX style floating user tag) ---- */
  #wm { position: absolute; z-index: 5; color: rgba(255,255,255,.38); font-size: 14px;
    line-height: 1.35; text-align: center; white-space: pre-line; pointer-events: none;
    text-shadow: 0 1px 3px rgba(0,0,0,.8); transition: all 1.2s ease; user-select: none; }
  /* ---- center overlay buttons ---- */
  #centerctl { position: absolute; inset: 0; display: flex; align-items: center;
    justify-content: center; gap: 34px; z-index: 8; opacity: 0; transition: opacity .25s;
    pointer-events: none; }
  #centerctl.show { opacity: 1; pointer-events: auto; }
  .cbtn { width: 58px; height: 58px; border-radius: 50%; border: 0; cursor: pointer;
    background: rgba(255,255,255,.18); backdrop-filter: blur(4px); color: #fff;
    display: flex; align-items: center; justify-content: center; }
  .cbtn:active { transform: scale(.92); }
  .cbtn svg { width: 26px; height: 26px; fill: #fff; }
  /* ---- spinner ---- */
  #spin { position: absolute; inset: 0; display: none; align-items: center;
    justify-content: center; z-index: 7; pointer-events: none; }
  #spin.show { display: flex; }
  #spin .ring { width: 52px; height: 52px; border: 4px solid rgba(255,255,255,.25);
    border-top-color: #fff; border-radius: 50%; animation: sp 1s linear infinite; }
  @keyframes sp { to { transform: rotate(360deg); } }
  /* ---- error overlay ---- */
  #errbox { position: absolute; inset: 0; display: none; flex-direction: column; gap: 14px;
    align-items: center; justify-content: center; z-index: 9; background: rgba(0,0,0,.85);
    color: #ff6b6b; font-size: 15px; text-align: center; padding: 20px; }
  #errbox button { background: #e91e63; color: #fff; border: 0; padding: 9px 22px;
    border-radius: 6px; font-size: 14px; cursor: pointer; }
  /* ---- control bar ---- */
  #ctl { position: absolute; left: 0; right: 0; bottom: 0; z-index: 10;
    background: linear-gradient(transparent, rgba(0,0,0,.85) 40%);
    padding: 26px 12px 10px; transition: opacity .3s, transform .3s; }
  #ctl.hide { opacity: 0; transform: translateY(8px); pointer-events: none; }
  #seek { position: relative; height: 14px; cursor: pointer; }
  #seek .rail { position: absolute; top: 6px; left: 0; right: 0; height: 3px;
    background: rgba(255,255,255,.3); border-radius: 2px; }
  #seek .buf { position: absolute; top: 6px; left: 0; height: 3px; width: 0;
    background: rgba(255,255,255,.55); border-radius: 2px; }
  #seek .play { position: absolute; top: 6px; left: 0; height: 3px; width: 0;
    background: #2196f3; border-radius: 2px; }
  #seek .knob { position: absolute; top: 2.5px; width: 11px; height: 11px;
    border-radius: 50%; background: #2196f3; margin-left: -5px; left: 0;
    box-shadow: 0 1px 4px rgba(0,0,0,.6); }
  #bar { display: flex; align-items: center; gap: 4px; margin-top: 6px; }
  .bbtn { border: 0; background: transparent; color: #fff; width: 38px; height: 38px;
    border-radius: 6px; cursor: pointer; display: flex; align-items: center; justify-content: center; }
  .bbtn:hover { background: rgba(255,255,255,.12); }
  .bbtn svg { width: 21px; height: 21px; fill: #fff; pointer-events: none; }
  #time { color: #fff; font-size: 13.5px; font-variant-numeric: tabular-nums;
    margin: 0 8px; letter-spacing: .3px; }
  #vol { -webkit-appearance: none; appearance: none; width: 86px; height: 3px;
    background: rgba(255,255,255,.4); border-radius: 2px; outline: 0; cursor: pointer; }
  #vol::-webkit-slider-thumb { -webkit-appearance: none; width: 11px; height: 11px;
    border-radius: 50%; background: #2196f3; }
  #vol::-moz-range-thumb { width: 11px; height: 11px; border: 0; border-radius: 50%; background: #2196f3; }
  .spacer { flex: 1; }
  /* ---- popup menus (settings / speed) ---- */
  .menu { position: absolute; right: 10px; bottom: 56px; z-index: 20; display: none;
    background: rgba(20,20,20,.96); border: 1px solid rgba(255,255,255,.14);
    border-radius: 10px; padding: 6px; min-width: 200px; max-height: 62vh; overflow: auto;
    box-shadow: 0 8px 30px rgba(0,0,0,.6); }
  .menu.open { display: block; }
  .menu h4 { color: rgba(255,255,255,.55); font-size: 11px; text-transform: uppercase;
    letter-spacing: 1px; padding: 8px 12px 4px; }
  .mi { display: flex; align-items: center; justify-content: space-between; gap: 12px;
    color: #eee; font-size: 14px; padding: 9px 12px; border-radius: 6px; cursor: pointer; }
  .mi:hover { background: rgba(255,255,255,.09); }
  .mi .tick { color: #4fc3f7; font-weight: 700; }
  .msep { height: 1px; background: rgba(255,255,255,.12); margin: 6px 4px; }
  /* ---- select quality modal (AppX style) ---- */
  #qmodal { position: absolute; inset: 0; z-index: 40; display: none;
    align-items: center; justify-content: center; background: rgba(0,0,0,.55); }
  #qmodal.open { display: flex; }
  #qcard { background: #fff; border-radius: 14px; width: min(420px, 88vw);
    max-height: 80vh; overflow: auto; padding: 18px 0 10px; }
  #qcard .qhead { display: flex; align-items: center; justify-content: space-between;
    padding: 0 20px 12px; }
  #qcard h3 { font-size: 18px; color: #1a1a1a; font-weight: 700; }
  #qclose { border: 0; background: #f1f1f1; width: 28px; height: 28px; border-radius: 50%;
    font-size: 13px; color: #666; cursor: pointer; }
  .qitem { display: flex; align-items: center; justify-content: space-between;
    padding: 13px 20px; margin: 4px 12px; border: 1px solid #eee; border-radius: 9px;
    font-size: 15.5px; color: #222; cursor: pointer; font-weight: 600; }
  .qitem:hover { background: #fdf2f6; border-color: #f8bbd0; }
  .qitem .qtag { font-size: 11.5px; color: #e91e63; background: #fce4ec;
    padding: 2px 8px; border-radius: 20px; font-weight: 700; }
  /* ---- resume toast ---- */
  #toast { position: absolute; top: 16px; left: 50%; transform: translateX(-50%);
    z-index: 35; background: rgba(20,20,20,.92); color: #fff; font-size: 13.5px;
    padding: 9px 16px; border-radius: 22px; display: none; align-items: center; gap: 10px; }
  #toast button { border: 0; background: #e91e63; color: #fff; border-radius: 14px;
    padding: 3px 10px; font-size: 12px; cursor: pointer; }
  @media (max-width: 640px) {
    #time { font-size: 12px; margin: 0 4px; }
    #vol { display: none; }
    .cbtn { width: 48px; height: 48px; }
  }
</style>
</head>
<body>
<div id="stage">
  <div id="headbar" class="on">
    <input type="checkbox" id="doneChk" title="Mark as complete">
    <div id="vtitle">${esc(name)}</div>
    <button id="headclose" title="Hide bar">✕</button>
  </div>
  <div id="vwrap">
    <video id="v" playsinline autoplay preload="auto"
      controlsList="nodownload" disablePictureInPicture ${src ? 'src="' + esc(src) + '"' : ""}></video>
    <div id="wm"></div>
    <div id="centerctl">
      <button class="cbtn" id="cPrev" title="-10s"><svg viewBox="0 0 24 24"><path d="M6 6h2v12H6zm3.5 6 8.5 6V6z"/></svg></button>
      <button class="cbtn" id="cPlay" title="Play/Pause"><svg viewBox="0 0 24 24"><path d="M8 5v14l11-7z"/></svg></button>
      <button class="cbtn" id="cNext" title="+10s"><svg viewBox="0 0 24 24"><path d="M16 6h2v12h-2zM6 18l8.5-6L6 6z"/></svg></button>
    </div>
    <div id="spin"><div class="ring"></div></div>
    <div id="errbox"><div id="errmsg"></div><button onclick="location.reload()">Retry</button></div>
    <div id="toast"><span id="toastmsg"></span><button id="toastbtn">Start over</button></div>

    <div class="menu" id="menuSettings">
      <h4>Quality</h4><div id="qList"></div>
      <div class="msep"></div>
      <h4>Speed</h4><div id="sList"></div>
    </div>

    <div id="qmodal">
      <div id="qcard">
        <div class="qhead"><h3>Select Quality</h3><button id="qclose">✕</button></div>
        <div id="qmodalList"></div>
      </div>
    </div>

    <div id="ctl">
      <div id="seek">
        <div class="rail"></div><div class="buf" id="buf"></div>
        <div class="play" id="played"></div><div class="knob" id="knob"></div>
      </div>
      <div id="bar">
        <button class="bbtn" id="bPlay" title="Play (k)"><svg viewBox="0 0 24 24"><path d="M8 5v14l11-7z"/></svg></button>
        <button class="bbtn" id="bPrev" title="Back 10s (←)"><svg viewBox="0 0 24 24"><path d="M11 18V6l-8.5 6 8.5 6zm.5-6 8.5 6V6l-8.5 6z"/></svg></button>
        <button class="bbtn" id="bNext" title="Forward 10s (→)"><svg viewBox="0 0 24 24"><path d="M13 6v12l8.5-6L13 6zM11 6l-8.5 6L11 18V6z"/></svg></button>
        <button class="bbtn" id="bMute" title="Mute (m)"><svg viewBox="0 0 24 24"><path d="M3 9v6h4l5 5V4L7 9H3z"/></svg></button>
        <input type="range" id="vol" min="0" max="1" step="0.02" value="1">
        <span id="time">00:00/00:00</span>
        <div class="spacer"></div>
        <button class="bbtn" id="bSpeed" title="Playback speed"><svg viewBox="0 0 24 24"><path d="M12 4a9 9 0 1 0 9 9h-2a7 7 0 1 1-7-7V4zm.7 5.3L17 5.6A8.96 8.96 0 0 0 12.7 3.4v5.9zM14 2.3v2A7 7 0 0 1 19.7 10h2A9 9 0 0 0 14 2.3z"/><circle cx="12" cy="13" r="1.6"/></svg></button>
        <button class="bbtn" id="bSnap" title="Snapshot"><svg viewBox="0 0 24 24"><path d="M9 3 7.2 5H4a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2V7a2 2 0 0 0-2-2h-3.2L15 3H9zm3 5a5 5 0 1 1 0 10 5 5 0 0 1 0-10zm0 2a3 3 0 1 0 0 6 3 3 0 0 0 0-6z"/></svg></button>
        <button class="bbtn" id="bGear" title="Settings"><svg viewBox="0 0 24 24"><path d="m19.4 13 .1-1-.1-1 2.1-1.7-2-3.5-2.6 1a7 7 0 0 0-1.7-1L14.8 3h-4l-.4 2.8a7 7 0 0 0-1.7 1l-2.6-1-2 3.5L6.2 11l-.1 1 .1 1-2.1 1.7 2 3.5 2.6-1a7 7 0 0 0 1.7 1l.4 2.8h4l.4-2.8a7 7 0 0 0 1.7-1l2.6 1 2-3.5-2.1-1.7zM12.8 15.5a3.5 3.5 0 1 1 0-7 3.5 3.5 0 0 1 0 7z" transform="translate(-.8)"/></svg></button>
        <button class="bbtn" id="bFull" title="Fullscreen (f)"><svg viewBox="0 0 24 24"><path d="M7 14H5v5h5v-2H7v-3zm-2-4h2V7h3V5H5v5zm12 7h-3v2h5v-5h-2v3zM14 5v2h3v3h2V5h-5z"/></svg></button>
      </div>
    </div>
  </div>
</div>
<script src="${HLS_JS_CDN}"><\/script>
<script>
(function () {
  "use strict";
  var CFG = {
    src: ${JSON.stringify(src)},
    urls: ${urlsJson},
    wm: ${JSON.stringify(wm)},
    t0: ${JSON.stringify(t0)},
    key: "apx_" + location.search.length + "_" + ${JSON.stringify(String(name).slice(0, 40))}
  };
  var v = document.getElementById("v");
  var hls = null, nativeHls = false;
  var ctl = document.getElementById("ctl");
  var centerctl = document.getElementById("centerctl");
  var spin = document.getElementById("spin");
  var errbox = document.getElementById("errbox");
  var errmsg = document.getElementById("errmsg");
  var toast = document.getElementById("toast");
  var toastmsg = document.getElementById("toastmsg");
  var menuSettings = document.getElementById("menuSettings");
  var qmodal = document.getElementById("qmodal");
  var levels = [];          // [{name, fn}]
  var curLevel = -2;        // -2 auto, -1 native single
  var uiTimer = null, wmTimer = null, saveTimer = null;
  var userSeeking = false;

  // ---------- utils ----------
  function $(id) { return document.getElementById(id); }
  function fmt(s) {
    if (!isFinite(s) || s < 0) s = 0;
    s = Math.floor(s);
    var h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), x = s % 60;
    var two = function (n) { return (n < 10 ? "0" : "") + n; };
    return h > 0 ? two(h) + ":" + two(m) + ":" + two(x) : two(m) + ":" + two(x);
  }
  function fmtPair(cur, dur) { // AppX style: strips hours from current if duration has none
    var dH = Math.floor(dur / 3600);
    var c = fmt(cur), d = fmt(dur);
    if (!dH) { c = c.split(":").length === 3 ? c.slice(3) : c; }
    return c + "/" + d;
  }
  function hash(s) { var h = 0, i; for (i = 0; i < s.length; i++) { h = ((h << 5) - h + s.charCodeAt(i)) | 0; } return String(h); }

  // ---------- progress resume (localStorage VIDEO_PROGRESS, AppX-style) ----------
  var storeKey = "VIDEO_PROGRESS";
  function loadMap() { try { return JSON.parse(localStorage.getItem(storeKey) || "{}"); } catch (e) { return {}; } }
  function savedPos() { var m = loadMap(); var x = parseFloat(m[CFG.key]); return isFinite(x) ? x : 0; }
  function savePos() {
    if (!v.duration || !isFinite(v.duration)) return;
    var m = loadMap();
    if (v.currentTime > 5 && v.currentTime < v.duration - 10) m[CFG.key] = v.currentTime;
    else delete m[CFG.key];
    try { localStorage.setItem(storeKey, JSON.stringify(m)); } catch (e) {}
  }

  // ---------- watermark ----------
  var wmEl = $("wm");
  function placeWm() {
    if (!CFG.wm) { wmEl.style.display = "none"; return; }
    var spots = [[14, 12], [null, 12], [14, null], [null, null], [14, 40]];
    var i = Math.floor(Date.now() / 8000) % spots.length;
    wmEl.style.left = spots[i][0] === null ? "" : spots[i][0] + "px";
    wmEl.style.right = spots[i][0] === null ? "14px" : "";
    wmEl.style.top = spots[i][1] === null ? "" : spots[i][1] + "%";
    wmEl.style.bottom = spots[i][1] === null ? "64px" : "";
  }
  if (CFG.wm) { wmEl.textContent = CFG.wm.replace(/\\n/g, "\\n"); setInterval(placeWm, 8000); placeWm(); }

  // ---------- UI show/hide ----------
  function showUi() {
    ctl.classList.remove("hide");
    centerctl.classList.add("show");
    clearTimeout(uiTimer);
    uiTimer = setTimeout(function () {
      if (!v.paused && !menuSettings.classList.contains("open") && !qmodal.classList.contains("open")) {
        ctl.classList.add("hide");
        centerctl.classList.remove("show");
      }
    }, 3000);
  }
  document.addEventListener("mousemove", showUi);
  document.addEventListener("touchstart", showUi, { passive: true });

  // ---------- play / pause icons ----------
  var ICON_PLAY = '<svg viewBox="0 0 24 24"><path d="M8 5v14l11-7z"/></svg>';
  var ICON_PAUSE = '<svg viewBox="0 0 24 24"><path d="M6 5h4v14H6zm8 0h4v14h-4z"/></svg>';
  function setPlayIcons() {
    var svg = v.paused ? ICON_PLAY : ICON_PAUSE;
    $("bPlay").innerHTML = svg;
    $("cPlay").innerHTML = svg;
  }

  // ---------- seek / time ----------
  function updateBar() {
    if (!v.duration || !isFinite(v.duration)) return;
    var p = (v.currentTime / v.duration) * 100;
    if (!userSeeking) {
      $("played").style.width = p + "%";
      $("knob").style.left = p + "%";
    }
    try {
      if (v.buffered.length) {
        var b = (v.buffered.end(v.buffered.length - 1) / v.duration) * 100;
        $("buf").style.width = Math.min(b, 100) + "%";
      }
    } catch (e) {}
    $("time").textContent = fmtPair(v.currentTime, v.duration);
  }
  function seekFrac(e) {
    var r = $("seek").getBoundingClientRect();
    var x = (e.touches ? e.touches[0].clientX : e.clientX) - r.left;
    return Math.max(0, Math.min(1, x / r.width));
  }
  $("seek").addEventListener("mousedown", function (e) { userSeeking = true; doSeek(e); });
  $("seek").addEventListener("mousemove", function (e) { if (userSeeking) doSeek(e); });
  document.addEventListener("mouseup", function () {
    if (userSeeking) { userSeeking = false; savePos(); }
  });
  $("seek").addEventListener("touchstart", function (e) { userSeeking = true; doSeek(e); }, { passive: true });
  $("seek").addEventListener("touchmove", function (e) { if (userSeeking) doSeek(e); }, { passive: true });
  document.addEventListener("touchend", function () { if (userSeeking) { userSeeking = false; savePos(); } });
  function doSeek(e) {
    var f = seekFrac(e);
    if (v.duration && isFinite(v.duration)) {
      $("played").style.width = (f * 100) + "%";
      $("knob").style.left = (f * 100) + "%";
      v.currentTime = f * v.duration;
      updateBar();
    }
  }

  // ---------- level / speed menus ----------
  function renderMenu() {
    var ql = $("qList"); ql.innerHTML = "";
    var mk = function (label, active, fn) {
      var d = document.createElement("div");
      d.className = "mi";
      var a = document.createElement("span"); a.textContent = label;
      var b = document.createElement("span"); b.className = "tick"; b.textContent = active ? "✓" : "";
      d.appendChild(a); d.appendChild(b);
      d.addEventListener("click", function () { fn(); renderMenu(); });
      ql.appendChild(d);
    };
    if (levels.length > 1) {
      mk("Auto", curLevel === -2, function () { setLevel(-2); });
      for (var i = 0; i < levels.length; i++) {
        (function (idx) {
          mk(levels[idx].name, curLevel === idx, function () { setLevel(idx); });
        })(i);
      }
    } else if (levels.length === 1) {
      mk(levels[0].name + " (only)", true, function () {});
    } else {
      mk("Auto", true, function () {});
    }
    var sl = $("sList"); sl.innerHTML = "";
    [0.5, 0.75, 1, 1.25, 1.5, 1.75, 2].forEach(function (r) {
      mk(r === 1 ? "1x (normal)" : r + "x", Math.abs(v.playbackRate - r) < 0.01, function () {
        v.playbackRate = r; renderMenu();
      });
    });
  }
  function setLevel(i) {
    if (i === -2 && levels.some(function (L) { return L.external; })) {
      // Auto with external per-quality list: back to default src, keep position
      curLevel = -2;
      switchSource(null, true);
      return;
    }
    if (i >= 0 && levels[i] && levels[i].external) {
      // per-quality external source (AppX style): swap stream, keep position
      curLevel = i;
      switchSource(levels[i], true);
      return;
    }
    curLevel = i;
    if (hls) hls.currentLevel = i === -2 ? -1 : i;
    else if (nativeHls && i >= 0 && levels[i] && levels[i].src) switchSource(levels[i], true);
  }

  // ---------- quality sources ----------
  // urls = pre-decrypted per-quality proxied sources (AppX INIT_PLAYER style)
  function setupUrlsList() {
    if (CFG.urls && CFG.urls.length > 1) {
      levels = CFG.urls.map(function (u) {
        return { name: u.name, src: u.url, external: true };
      });
    }
  }
  function switchSource(level, keepPos) {
    var at = keepPos ? v.currentTime : 0;
    var wasPlaying = !v.paused || v.autoplay;
    if (hls) { hls.destroy(); hls = null; }
    v.removeAttribute("src");
    if (level && level.external) {
      // external per-quality source: native fetch through proxy
      nativeHls = true;
      attachNative(level.src, at, wasPlaying);
    } else {
      loadMain(at, wasPlaying, level && level.hlsIndex !== undefined ? function (h) { h.currentLevel = level.hlsIndex; } : null);
    }
  }
  function attachNative(srcUrl, at, autoplay) {
    v.src = srcUrl;
    var onMeta = function () {
      v.removeEventListener("loadedmetadata", onMeta);
      if (at > 0 && at < v.duration - 10) v.currentTime = at;
      if (autoplay) v.play().catch(function () {});
    };
    v.addEventListener("loadedmetadata", onMeta);
  }

  // ---------- main loader ----------
  function loadMain(at, autoplay, afterLoad) {
    spin.classList.add("show");
    errbox.style.display = "none";
    if (window.Hls && Hls.isSupported()) {
      hls = new Hls({
        enableWorker: true,
        lowLatencyMode: true,
        backBufferLength: 90,
        maxBufferLength: 40,
        manifestLoadingTimeOut: 20000,
        fragLoadingTimeOut: 30000
      });
      hls.loadSource(CFG.src);
      hls.attachMedia(v);
      hls.on(Hls.Events.MANIFEST_PARSED, function (_e, data) {
        spin.classList.remove("show");
        if (CFG.urls && CFG.urls.length > 1) {
          // pre-decrypted per-quality sources provided (AppX INIT_PLAYER style):
          // keep those as the quality list, switch by swapping source at position
          levels = CFG.urls.map(function (u) { return { name: u.name, src: u.url, external: true }; });
        } else {
          levels = data.levels.map(function (L, i) {
            var nm = (L.height ? L.height + "p" : (L.bitrate ? Math.round(L.bitrate / 1000) + " kbps" : "level " + i));
            if (L.height && data.levels.length > 1 && i === data.levels.length - 1) nm += "  (HD)";
            return { name: nm, hlsIndex: i };
          });
        }
        if (!levels.length) levels = [];
        curLevel = -2;
        renderMenu();
        buildQualityModal();
        if (afterLoad) afterLoad(hls);
        if (autoplay) v.play().catch(function () {});
      });
      hls.on(Hls.Events.LEVEL_SWITCHED, function (_e, d) {
        if (curLevel === -2) renderMenu();
      });
      hls.on(Hls.Events.ERROR, function (_e, d) {
        if (!d.fatal) return;
        spin.classList.remove("show");
        if (d.type === Hls.ErrorTypes.NETWORK_ERROR && d.details === "manifestLoadError") {
          errmsg.textContent = "Stream unreachable (CDN token may have expired). Get a fresh link.";
        } else {
          errmsg.textContent = "Player error: " + d.details;
        }
        errbox.style.display = "flex";
      });
    } else if (v.canPlayType("application/vnd.apple.mpegurl")) {
      nativeHls = true;
      attachNative(CFG.src, at || 0, autoplay);
      spin.classList.remove("show");
      buildQualityModal();
    } else {
      spin.classList.remove("show");
      errmsg.textContent = "HLS is not supported in this browser.";
      errbox.style.display = "flex";
    }
  }

  // ---------- select quality modal (AppX style) ----------
  function buildQualityModal() {
    var list = $("qmodalList");
    list.innerHTML = "";
    var options = levels.map(function (L) { return { name: L.name, go: function () { setLevel(L.hlsIndex); } }; });
    if (options.length > 1) {
      options.unshift({ name: "Auto (recommended)", go: function () { setLevel(-2); } });
      var tag = { "720p": "HD", "1080p": "FULL HD", "480p": "SD", "360p": "SD", "240p": "LOW", "144p": "LOW" };
      options.forEach(function (o) {
        var d = document.createElement("div");
        d.className = "qitem";
        var a = document.createElement("span"); a.textContent = o.name;
        d.appendChild(a);
        if (tag[o.name.split(" ")[0]]) {
          var t = document.createElement("span"); t.className = "qtag"; t.textContent = tag[o.name.split(" ")[0]];
          d.appendChild(t);
        }
        d.addEventListener("click", function () { o.go(); qmodal.classList.remove("open"); });
        list.appendChild(d);
      });
      // AppX site always opens this modal before playback
      if (v.paused) qmodal.classList.add("open");
    }
  }

  // ---------- controls wiring ----------
  function togglePlay() { if (v.paused) v.play().catch(function () {}); else v.pause(); }
  $("bPlay").addEventListener("click", togglePlay);
  $("cPlay").addEventListener("click", togglePlay);
  v.addEventListener("click", togglePlay);
  v.addEventListener("dblclick", function () { toggleFs(); });
  $("bPrev").addEventListener("click", function () { v.currentTime = Math.max(0, v.currentTime - 10); });
  $("cPrev").addEventListener("click", function () { v.currentTime = Math.max(0, v.currentTime - 10); });
  $("bNext").addEventListener("click", function () { v.currentTime = Math.min(v.duration || 1e9, v.currentTime + 10); });
  $("cNext").addEventListener("click", function () { v.currentTime = Math.min(v.duration || 1e9, v.currentTime + 10); });
  $("bMute").addEventListener("click", function () { v.muted = !v.muted; });
  $("vol").addEventListener("input", function () { v.volume = parseFloat(this.value); v.muted = false; });
  $("bGear").addEventListener("click", function (e) { e.stopPropagation(); menuSettings.classList.toggle("open"); renderMenu(); });
  document.addEventListener("click", function (e) {
    if (!menuSettings.contains(e.target) && e.target !== $("bGear")) menuSettings.classList.remove("open");
  });
  $("bSpeed").addEventListener("click", function (e) {
    e.stopPropagation(); menuSettings.classList.add("open"); renderMenu();
  });
  function toggleFs() {
    var el = document.getElementById("vwrap");
    if (document.fullscreenElement) document.exitFullscreen();
    else if (el.requestFullscreen) el.requestFullscreen();
    else if (el.webkitRequestFullscreen) el.webkitRequestFullscreen();
  }
  $("bFull").addEventListener("click", toggleFs);

  // ---------- snapshot ----------
  $("bSnap").addEventListener("click", function () {
    try {
      var c = document.createElement("canvas");
      c.width = v.videoWidth; c.height = v.videoHeight;
      c.getContext("2d").drawImage(v, 0, 0);
      var a = document.createElement("a");
      a.href = c.toDataURL("image/png");
      a.download = "snapshot_" + fmt(v.currentTime).replace(/:/g, "-") + ".png";
      a.click();
    } catch (e) { alert("Snapshot failed: " + e.message); }
  });

  // ---------- header ----------
  $("headclose").addEventListener("click", function () { $("headbar").classList.remove("on"); });
  $("doneChk").addEventListener("change", function () {
    if (this.checked && v.duration) v.currentTime = Math.max(0, v.duration - 15);
  });

  // ---------- toast / resume ----------
  function showToast(msg) {
    toastmsg.textContent = msg;
    toast.style.display = "flex";
    setTimeout(function () { toast.style.display = "none"; }, 6000);
  }
  $("toastbtn").addEventListener("click", function () {
    v.currentTime = 0; savePos(); toast.style.display = "none";
  });

  // ---------- video events ----------
  v.addEventListener("play", setPlayIcons);
  v.addEventListener("pause", function () { setPlayIcons(); savePos(); showUi(); });
  v.addEventListener("timeupdate", updateBar);
  v.addEventListener("progress", updateBar);
  v.addEventListener("durationchange", updateBar);
  v.addEventListener("loadedmetadata", function () {
    var sp = CFG.t0 || savedPos();
    if (sp > 10 && v.duration && sp < v.duration - 30) {
      v.currentTime = sp;
      showToast("Resumed from " + fmt(sp));
      $("doneChk").checked = false;
    } else if (sp >= 30 && v.duration && sp >= v.duration - 30) {
      showToast("You already watched this video");
    }
    updateBar();
  });
  v.addEventListener("waiting", function () { spin.classList.add("show"); });
  v.addEventListener("playing", function () { spin.classList.remove("show"); qmodal.classList.remove("open"); setPlayIcons(); });
  v.addEventListener("canplay", function () { spin.classList.remove("show"); });
  v.addEventListener("volumechange", function () {
    $("vol").value = v.muted ? 0 : v.volume;
    $("bMute").innerHTML = (v.muted || v.volume === 0)
      ? '<svg viewBox="0 0 24 24"><path d="M16.5 12A4.5 4.5 0 0 0 14 8v2.2l2.5 2.5v-.7zM19 12a7 7 0 0 1-1 3.6l1.5 1.5A9 9 0 0 0 21 12c0-3-1.9-5.5-4.5-6.6v2.1c1.5.9 2.5 2.5 2.5 4.5zM4.3 3 3 4.3 7.7 9H3v6h4l5 5v-6.7l4.3 4.3a7 7 0 0 1-2.3 1.4v2.1a9 9 0 0 0 3.7-2.1L19.7 21 21 19.7l-9-9L4.3 3zM12 4 9.9 6.1 12 8.2V4z"/></svg>'
      : '<svg viewBox="0 0 24 24"><path d="M3 9v6h4l5 5V4L7 9H3z"/></svg>';
  });
  window.addEventListener("beforeunload", savePos);
  document.addEventListener("keydown", function (e) {
    if (e.target.tagName === "INPUT") return;
    switch (e.key) {
      case " ": case "k": e.preventDefault(); togglePlay(); break;
      case "ArrowLeft": v.currentTime = Math.max(0, v.currentTime - 10); break;
      case "ArrowRight": v.currentTime = Math.min(v.duration || 1e9, v.currentTime + 10); break;
      case "ArrowUp": e.preventDefault(); v.volume = Math.min(1, v.volume + 0.1); break;
      case "ArrowDown": e.preventDefault(); v.volume = Math.max(0, v.volume - 0.1); break;
      case "m": v.muted = !v.muted; break;
      case "f": toggleFs(); break;
      default:
        if (/^[0-9]$/.test(e.key) && v.duration) v.currentTime = (parseInt(e.key, 10) / 10) * v.duration;
    }
    showUi();
  });

  // ---------- boot ----------
  setupUrlsList();
  setPlayIcons();
  if (!CFG.src) {
    errmsg.textContent = "Missing ?url= parameter.  Example: /player?url=<m3u8>";
    errbox.style.display = "flex";
  } else {
    loadMain(CFG.t0 || savedPos(), true, null);
    saveTimer = setInterval(savePos, 5000);
  }
})();
<\/script>
</body>
</html>`;
}

// ---------------- /aes handler ----------------

function handleAes(req, res, q, bodyText) {
  const key = q.get("key") || (bodyText && JSON.parse(bodyText || "{}").key) || undefined;
  let payload = null;
  try {
    payload = bodyText ? JSON.parse(bodyText) : null;
  } catch {
    return sendJson(res, 400, { error: "Invalid JSON body" });
  }

  // bulk mode: all=<json of fetchVideoDetailsById data> (GET) or {all:{...}} (POST)
  let allRaw = q.get("all") || (payload && (payload.all ? JSON.stringify(payload.all) : null));
  if (allRaw) {
    try {
      const obj = typeof allRaw === "string" ? JSON.parse(allRaw) : allRaw;
      const list = Array.isArray(obj) ? obj : [obj];
      const out = list.map((item) => {
        const dec = bulkDecrypt(item || {}, key);
        const qmap = {};
        dec.qualities.forEach((x) => (qmap[x.name] = x.url));
        const best = dec.qualities[0];
        let player = null;
        if (best) {
          const p = new URLSearchParams();
          p.set("url", best.url);
          if (dec.title) p.set("name", dec.title);
          if (qmap["480p"] && qmap["480p"] !== best.url) {
            p.set(
              "urls",
              JSON.stringify(dec.qualities.map((x) => ({ name: x.name, url: x.url })))
            );
          }
          player = "/player?" + p.toString();
        }
        return { title: dec.title, file_url: dec.file_url || null, qualities: dec.qualities, other: dec.other, player };
      });
      return sendJson(res, 200, { ok: true, results: Array.isArray(obj) ? out : out[0] });
    } catch (e) {
      return sendJson(res, 400, { error: "all= parse failed: " + e.message });
    }
  }

  const data = q.get("data") || (payload && payload.data);
  if (!data) {
    // tiny HTML helper page
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", ...CORS });
    return res.end(
      "<!DOCTYPE html><html><head><meta charset='utf-8'><title>apidl /aes — link decryptor</title>" +
      "<style>body{font-family:system-ui;background:#0f1115;color:#eee;max-width:760px;margin:40px auto;padding:0 16px}" +
      "textarea,input,button{width:100%;box-sizing:border-box;padding:10px;margin:6px 0;border-radius:8px;border:1px solid #333;background:#191c24;color:#eee;font-size:14px}" +
      "button{background:#e91e63;border:0;font-weight:700;cursor:pointer}" +
      "pre{background:#191c24;padding:12px;border-radius:8px;overflow:auto;font-size:12.5px}</style></head><body>" +
      "<h2>🔐 AppX link decryptor</h2><p>Paste an encrypted link (<code>base64ct:base64iv</code>) or the whole " +
      "<code>data</code> JSON of <code>fetchVideoDetailsById</code>.</p>" +
      "<textarea id='d' rows='6' placeholder='m7hcRsBTJp5eNY5...:ZmVkY2JhOTg3NjU0MzIxMA=='></textarea>" +
      "<input id='k' placeholder='key (default 638udh3829162018)'>" +
      "<button onclick='go()'>Decrypt</button><pre id='o'>result…</pre>" +
      "<script>function go(){var d=document.getElementById('d').value.trim();var k=document.getElementById('k').value.trim();" +
      "var o=document.getElementById('o');o.textContent='decrypting…';" +
      "try{var j;if(d.startsWith('{')){j={all:JSON.parse(d)};}else{j={data:d};}" +
      "if(k)j.key=k;fetch('/aes',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(j)})" +
      ".then(r=>r.json()).then(x=>o.textContent=JSON.stringify(x,null,2)).catch(e=>o.textContent=''+e);}" +
      "catch(e){o.textContent='parse error: '+e;}}<\/script></body></html>"
    );
  }
  try {
    const dec = aesDecryptUrl(data, key);
    return sendJson(res, 200, { ok: true, url: dec });
  } catch (e) {
    return sendJson(res, 400, { ok: false, error: e.message });
  }
}

// ---------------- server ----------------

const server = http.createServer((req, res) => {
  const u = new URL(req.url, `http://${req.headers.host || "localhost"}`);

  if (req.method === "OPTIONS") {
    res.writeHead(204, CORS);
    return res.end();
  }

  if (u.pathname === "/aes") {
    if (req.method === "POST") {
      return readBody(req)
        .then((body) => handleAes(req, res, u.searchParams, body))
        .catch((e) => sendJson(res, 400, { error: e.message }));
    }
    if (req.method === "GET") return handleAes(req, res, u.searchParams, null);
    return sendError(res, 405, "Use GET or POST");
  }

  if (req.method !== "GET" && req.method !== "HEAD") {
    return sendError(res, 405, "Only GET allowed");
  }

  if (u.pathname === "/apidl") {
    return handleApidl(req, res, u.searchParams).catch((e) => {
      console.error("[apidl] unhandled:", e);
      if (!res.headersSent) sendError(res, 500, "Internal error");
    });
  }

  if (u.pathname === "/player") {
    const html = playerPage(u.searchParams);
    res.writeHead(200, {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
      ...CORS,
    });
    return res.end(html);
  }

  if (u.pathname === "/" || u.pathname === "/health") {
    return sendJson(res, 200, {
      status: "ok",
      api: "apidl HLS proxy + AppX-style player",
      endpoints: {
        stream: "/apidl?url=<m3u8-url>",
        download: "/apidl?url=<m3u8-url>&dl=1",
        overrides: "&ref=<referer>&ua=<user-agent>",
        player: "/player?url=<m3u8-url>&name=<title>&wm=<watermark>&urls=<[{name,url}]>",
        decrypt: "/aes?data=<b64ct:b64iv>  |  POST {\"all\":<fetchVideoDetailsById data>}",
      },
    });
  }

  sendError(res, 404, "Not found. Use /apidl?url=<m3u8-url> or /player?url=<m3u8-url>");
});

server.listen(PORT, () => {
  let ffmpegInfo = FFMPEG;
  try {
    const v = require("child_process")
      .execSync(`"${FFMPEG}" -version 2>&1 | head -1`, { timeout: 10000 })
      .toString()
      .trim();
    ffmpegInfo = `${FFMPEG} | ${v}`;
  } catch (e) {
    ffmpegInfo = `${FFMPEG} | VERSION CHECK FAILED: ${e.message}`;
  }
  console.log(`[apidl] listening on ${PORT} | ffmpeg: ${ffmpegInfo}`);
});
