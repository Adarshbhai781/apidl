/**
 * Downloads a fully static ffmpeg build (BtbN GitHub releases) to ./ffmpeg
 * Falls back to ffmpeg-static's binary if BtbN download fails.
 * Runs on npm install (postinstall) — i.e., during Render build.
 */
const { execSync } = require("child_process");
const fs = require("fs");

if (fs.existsSync("./ffmpeg")) {
  console.log("[setup-ffmpeg] ./ffmpeg already present, skipping");
  process.exit(0);
}

try {
  execSync(
    "curl -sL --retry 3 --max-time 300 -o /tmp/ff.tar.xz " +
      "https://github.com/BtbN/FFmpeg-Builds/releases/latest/download/ffmpeg-master-latest-linux64-gpl.tar.xz " +
      "&& tar -xf /tmp/ff.tar.xz -C /tmp " +
      "&& cp /tmp/ffmpeg-master-latest-linux64-gpl/bin/ffmpeg ./ffmpeg " +
      "&& chmod +x ./ffmpeg",
    { stdio: "inherit" }
  );
  console.log("[setup-ffmpeg] BtbN static ffmpeg installed to ./ffmpeg");
} catch (e) {
  console.log("[setup-ffmpeg] BtbN download failed:", e.message);
  try {
    execSync("node node_modules/ffmpeg-static/install.js", { stdio: "inherit" });
    console.log("[setup-ffmpeg] fell back to ffmpeg-static");
  } catch (e2) {
    console.log("[setup-ffmpeg] ffmpeg-static install also failed:", e2.message);
  }
}
