const http = require("http");
const { spawn } = require("child_process");
const { randomUUID } = require("crypto");
const fs = require("fs");
const path = require("path");
const os = require("os");

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
const TMPDIR = os.tmpdir();
const KEY = process.env.RELAY_KEY || "";
const UA = "VLC/3.0.20 LibVLC/3.0.20";

// Sesiones activas: id → { dir, ffmpeg, lastAccess }
const sessions = new Map();

function cleanup(sid) {
  const s = sessions.get(sid);
  if (!s) return;
  try { s.ffmpeg.kill("SIGKILL"); } catch {}
  try { fs.rmSync(s.dir, { recursive: true, force: true }); } catch {}
  sessions.delete(sid);
  console.log(`[cleanup] sesión ${sid} eliminada`);
}

// Limpiar sesiones sin acceso por más de 30s
setInterval(() => {
  const now = Date.now();
  for (const [sid, s] of sessions) {
    if (now - s.lastAccess > 30000) cleanup(sid);
  }
}, 10000);

function startSession(id) {
  const target = ALLOWED[id];
  if (!target) return null;

  const sid = randomUUID();
  const dir = path.join(TMPDIR, `hls_${sid}`);
  fs.mkdirSync(dir, { recursive: true });

  const outPath = path.join(dir, "live.m3u8");

  const ff = spawn("ffmpeg", [
    "-re",
    "-i", target,
    "-user_agent", "VLC/3.0.20 LibVLC/3.0.20",
    "-vcodec", "libx264",
    "-preset", "ultrafast",
    "-tune", "zerolatency",
    "-b:v", "800k",
    "-acodec", "aac",
    "-b:a", "128k",
    "-f", "hls",
    "-hls_time", "2",
    "-hls_list_size", "5",
    "-hls_flags", "delete_segments+append_list",
    "-hls_segment_filename", path.join(dir, "seg%03d.ts"),
    outPath,
  ]);

  ff.stderr.on("data", d => process.stdout.write(`[ffmpeg:${sid.slice(0,6)}] ${d}`));
  ff.on("error", e => console.error(`[ffmpeg error] ${e.message}`));
  ff.on("close", code => {
    console.log(`[ffmpeg] sesión ${sid} cerrada con código ${code}`);
    sessions.delete(sid);
  });

  sessions.set(sid, { dir, ffmpeg: ff, lastAccess: Date.now() });
  console.log(`[session] iniciada ${sid} para ${id}`);
  return sid;
}

function waitForFile(filePath, timeout = 15000) {
  return new Promise((resolve, reject) => {
    const start = Date.now();
    const check = () => {
      if (fs.existsSync(filePath) && fs.statSync(filePath).size > 0) {
        resolve();
      } else if (Date.now() - start > timeout) {
        reject(new Error("timeout esperando archivo"));
      } else {
        setTimeout(check, 300);
      }
    };
    check();
  });
}

// Relé genérico: abre cualquier señal http/https (IPs, puertos raros) y la
// reenvía tal cual, como haría VLC. GET /fetch?u=<url>&k=<RELAY_KEY>
async function relayFetch(req, res, url) {
  if (KEY && url.searchParams.get("k") !== KEY) {
    res.writeHead(403, CORS);
    res.end("Prohibido");
    return;
  }
  const target = url.searchParams.get("u") || "";
  if (!/^https?:\/\//i.test(target)) {
    res.writeHead(400, CORS);
    res.end("Falta u=");
    return;
  }
  const ac = new AbortController();
  req.on("close", () => ac.abort());
  try {
    const r = await fetch(target, {
      headers: { "user-agent": UA, accept: "*/*" },
      redirect: "follow",
      signal: ac.signal,
    });
    res.writeHead(r.status, {
      ...CORS,
      "content-type": r.headers.get("content-type") || "application/octet-stream",
      "x-final-url": r.url,
    });
    if (!r.body) { res.end(); return; }
    for await (const chunk of r.body) {
      if (!res.write(chunk)) await new Promise((ok) => res.once("drain", ok));
    }
    res.end();
  } catch {
    if (!res.headersSent) res.writeHead(502, CORS);
    res.end();
  }
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);

  // Health check
  if (url.pathname === "/" || url.pathname === "") {
    res.writeHead(200);
    res.end("Proxy HLS activo ✓");
    return;
  }

  // Relé genérico: GET /fetch?u=<url>&k=<RELAY_KEY>
  if (url.pathname === "/fetch") {
    await relayFetch(req, res, url);
    return;
  }

  // Iniciar sesión: GET /start?id=local1
  if (url.pathname === "/start") {
    const id = url.searchParams.get("id");
    if (!ALLOWED[id]) {
      res.writeHead(404, CORS);
      res.end(JSON.stringify({ error: "Canal no encontrado" }));
      return;
    }
    const sid = startSession(id);
    res.writeHead(200, { ...CORS, "content-type": "application/json" });
    res.end(JSON.stringify({ sid, playlist: `/hls/${sid}/live.m3u8` }));
    return;
  }

  // Servir archivos HLS: GET /hls/:sid/live.m3u8 o /hls/:sid/seg000.ts
  const hlsMatch = url.pathname.match(/^\/hls\/([^/]+)\/(.+)$/);
  if (hlsMatch) {
    const sid = hlsMatch[1];
    const file = hlsMatch[2];
    const s = sessions.get(sid);

    if (!s) {
      res.writeHead(404, CORS);
      res.end("Sesión no encontrada");
      return;
    }

    s.lastAccess = Date.now();
    const filePath = path.join(s.dir, file);

    try {
      await waitForFile(filePath, 15000);
      const data = fs.readFileSync(filePath);
      const ct = file.endsWith(".m3u8")
        ? "application/vnd.apple.mpegurl"
        : "video/mp2t";
      res.writeHead(200, { ...CORS, "content-type": ct });
      res.end(data);
    } catch (e) {
      res.writeHead(502, CORS);
      res.end("Archivo no disponible aún");
    }
    return;
  }

  res.writeHead(400, CORS);
  res.end("Usa /start?id=winsport, /start?id=local1 o /start?id=local2");
});

server.listen(PORT, () => console.log(`Proxy HLS corriendo en puerto ${PORT}`));
