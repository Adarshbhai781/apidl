/*
 * apidl — HLS Stream Proxy API (single-file Node.js server)
 * ---------------------------------------------------------
 * GET /apidl?url=<m3u8-url>              -> playable playlist (headers auto-attached)
 * GET /apidl?url=<m3u8-url>&dl=1         -> single MP4 download stream (ffmpeg, no re-encode)
 * GET /apidl?u=<segment-or-key-url>      -> segment/key stream proxy (Range passthrough)
 * GET /apidl?url=...&ref=<referer>&ua=<user-agent>  -> custom header overrides
 * GET /                                  -> API status JSON
 *
 * Zero framework. Node 18+ (built-in fetch). ffmpeg only needed for dl=1
 * (auto-detected: ffmpeg-static npm binary or system ffmpeg).
 */

const http = require("http");
const { Readable } = require("stream");
const { spawn } = require("child_process");

const PORT = process.env.PORT || 3000;

// ---- Headers without which the CDN returns 403/404 ----
const DEFAULT_HEADERS = {
  Referer: "https://player-strict.akamai.net.in/",
  "User-Agent":
    "Dalvik/2.1.0 (Linux; U; Android 16; RMX5110 Build/BP2A.250605.015)",
};

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, OPTIONS",
  "Access-Control-Allow-Headers": "*",
};

let FFMPEG = "ffmpeg";
try {
  FFMPEG = require("ffmpeg-static") || "ffmpeg";
} catch {
  /* system ffmpeg fallback */
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
  proc.on("close", (code) => {
    if (code && code !== 255) console.error("[apidl] ffmpeg exited", code, stderr);
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

// ---------------- main handler ----------------

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

// ---------------- server ----------------

const server = http.createServer((req, res) => {
  const u = new URL(req.url, `http://${req.headers.host || "localhost"}`);

  if (req.method === "OPTIONS") {
    res.writeHead(204, CORS);
    return res.end();
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

  if (u.pathname === "/" || u.pathname === "/health") {
    return sendJson(res, 200, {
      status: "ok",
      api: "apidl HLS proxy",
      endpoints: {
        stream: "/apidl?url=<m3u8-url>",
        download: "/apidl?url=<m3u8-url>&dl=1",
        overrides: "&ref=<referer>&ua=<user-agent>",
      },
    });
  }

  sendError(res, 404, "Not found. Use /apidl?url=<m3u8-url>");
});

server.listen(PORT, () => {
  console.log(`[apidl] HLS proxy API listening on port ${PORT} (ffmpeg: ${FFMPEG !== "ffmpeg" ? "bundled" : "system"})`);
});
