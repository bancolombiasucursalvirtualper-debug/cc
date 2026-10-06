const http = require("http");
const { spawn } = require("child_process");

const ALLOWED = {
  winsport: "http://138.121.15.230:9002/WIN-SPORT/index.m3u8",
  local1:   "http://15.204.146.163:8002/play/a00h/index.m3u8",
  local2:   "http://181.78.12.119:16123/play/ch18/index.m3u8",
};

const CORS = {
  "access-control-allow-origin": "*",
  "cache-control": "no-store",
};

const PORT = process.env.PORT || 3000;

http.createServer((req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);

  if (url.pathname !== "/proxy") {
    res.writeHead(200);
    res.end("Proxy activo con FFmpeg ✓");
    return;
  }

  const id = url.searchParams.get("id");
  const target = ALLOWED[id];

  if (!target) {
    res.writeHead(404, CORS);
    res.end("Canal no encontrado. Usa ?id=winsport, ?id=local1 o ?id=local2");
    return;
  }

  console.log(`[proxy] Iniciando stream: ${id} → ${target}`);

  res.writeHead(200, {
    ...CORS,
    "content-type": "video/mp4",
    "transfer-encoding": "chunked",
  });

  const ff = spawn("ffmpeg", [
    "-re",
    "-i", target,
    "-user_agent", "VLC/3.0.20 LibVLC/3.0.20",
    "-vcodec", "libx264",
    "-preset", "ultrafast",
    "-tune", "zerolatency",
    "-b:v", "1000k",
    "-acodec", "aac",
    "-b:a", "128k",
    "-f", "mp4",
    "-movflags", "frag_keyframe+empty_moov+faststart",
    "-loglevel", "warning",
    "-",
  ]);

  ff.stdout.pipe(res);

  ff.stderr.on("data", (d) => console.error("[ffmpeg]", d.toString().trim()));

  ff.on("error", (e) => {
    console.error("[ffmpeg error]", e.message);
    try { res.end(); } catch {}
  });

  ff.on("close", (code) => {
    console.log(`[ffmpeg] cerrado con código ${code}`);
    try { res.end(); } catch {}
  });

  req.on("close", () => {
    console.log(`[proxy] cliente desconectado, matando ffmpeg`);
    ff.kill("SIGKILL");
  });

}).listen(PORT, () => console.log(`Proxy con FFmpeg corriendo en puerto ${PORT}`));
