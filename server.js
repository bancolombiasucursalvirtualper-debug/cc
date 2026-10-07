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

// Sesiones activas: sid → { dir, ffmpeg, lastAccess, target }
const sessions = new Map();
const byTarget = new Map(); // url → sid (un solo ffmpeg por canal, lo comparten todos)
const IDLE_MS = Number(process.env.IDLE_MS || 120000); // 2 min sin espectadores

function cleanup(sid) {
  const s = sessions.get(sid);
  if (!s) return;
  s.closed = true;
  try { s.ffmpeg.kill("SIGKILL"); } catch {}
  try { fs.rmSync(s.dir, { recursive: true, force: true }); } catch {}
  sessions.delete(sid);
  if (byTarget.get(s.target) === sid) byTarget.delete(s.target);
  console.log(`[cleanup] sesión ${sid} eliminada`);
}

setInterval(() => {
  const now = Date.now();
  for (const [sid, s] of sessions) if (now - s.lastAccess > IDLE_MS) cleanup(sid);
}, 10000);

function spawnFf(sid) {
  const s = sessions.get(sid);
  if (!s || s.closed) return;
  const outPath = path.join(s.dir, "live.m3u8");
  // Igual que VLC: se presenta como VLC, reconecta solo y convierte cualquier
  // códec (MPEG-2, HEVC, AC3...) a H.264/AAC que el navegador sí entiende.
  const ff = spawn("ffmpeg", [
    "-hide_banner", "-loglevel", "warning",
    "-user_agent", UA,
    "-reconnect", "1", "-reconnect_streamed", "1",
    "-reconnect_delay_max", "5",
    "-fflags", "+genpts+discardcorrupt",
    "-i", s.target,
    "-map", "0:v:0?", "-map", "0:a:0?",
    "-c:v", "libx264", "-preset", "ultrafast", "-tune", "zerolatency",
    "-vf", "scale=-2:'min(720,ih)'", "-b:v", "1200k", "-maxrate", "1500k", "-bufsize", "3000k",
    "-g", "50", "-sc_threshold", "0",
    "-c:a", "aac", "-b:a", "128k", "-ac", "2",
    "-f", "hls", "-hls_time", "2", "-hls_list_size", "6",
    "-hls_flags", "delete_segments+append_list+omit_endlist",
    "-hls_segment_filename", path.join(s.dir, "seg%05d.ts"),
    outPath,
  ]);
  s.ffmpeg = ff;
  ff.stderr.on("data", d => {
    s.log = ((s.log || "") + d).slice(-3000);
    process.stdout.write(`[ffmpeg:${sid.slice(0,6)}] ${d}`);
  });
  ff.on("error", e => { s.log = "ffmpeg no instalado o falló: " + e.message; console.error(`[ffmpeg error] ${e.message}`); });
  ff.on("close", code => {
    // Se cayó la señal: si alguien sigue mirando, la volvemos a prender.
    if (s.closed) return;
    if (Date.now() - s.lastAccess < IDLE_MS) {
      s.restarts = (s.restarts || 0) + 1;
      console.log(`[ffmpeg] ${sid} cayó (${code}), reintento #${s.restarts}`);
      setTimeout(() => spawnFf(sid), Math.min(10000, 1000 * s.restarts));
    } else cleanup(sid);
  });
}

function startSession(target) {
  const existing = byTarget.get(target);
  if (existing && sessions.has(existing)) {
    sessions.get(existing).lastAccess = Date.now();
    return existing;
  }
  const sid = randomUUID();
  const dir = path.join(TMPDIR, `hls_${sid}`);
  fs.mkdirSync(dir, { recursive: true });
  sessions.set(sid, { dir, target, lastAccess: Date.now(), closed: false });
  byTarget.set(target, sid);
  spawnFf(sid);
  console.log(`[session] iniciada ${sid} para ${target}`);
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

  // Para VLC: GET /play/local1.m3u8 -> arranca el canal y entrega la lista directa
  const play = url.pathname.match(/^\/play\/([a-z0-9]+)(\.m3u8)?$/i);
  if (play) {
    const target = ALLOWED[play[1]];
    if (!target) { res.writeHead(404, CORS); res.end("Canal no encontrado"); return; }
    const sid = startSession(target);
    try {
      await waitForFile(path.join(sessions.get(sid).dir, "live.m3u8"), 25000);
      res.writeHead(302, { ...CORS, location: `/hls/${sid}/live.m3u8` });
      res.end();
    } catch {
      res.writeHead(502, CORS);
      res.end("El canal no arrancó. Revisa /status");
    }
    return;
  }

  // Diagnóstico: GET /status
  if (url.pathname === "/status") {
    const out = [...sessions].map(([sid, x]) => ({ sid, target: x.target, restarts: x.restarts || 0, log: x.log || "" }));
    res.writeHead(200, { ...CORS, "content-type": "application/json" });
    res.end(JSON.stringify(out, null, 2));
    return;
  }

  // Relé genérico: GET /fetch?u=<url>&k=<RELAY_KEY>
  if (url.pathname === "/fetch") {
    await relayFetch(req, res, url);
    return;
  }

  // Iniciar sesión: GET /start?id=local1  ó  /start?u=<url>&k=<RELAY_KEY>
  if (url.pathname === "/start") {
    const id = url.searchParams.get("id");
    let target = id ? ALLOWED[id] : null;
    const u = url.searchParams.get("u");
    if (!target && u) {
      if (KEY && url.searchParams.get("k") !== KEY) { res.writeHead(403, CORS); res.end("Prohibido"); return; }
      if (/^https?:\/\//i.test(u)) target = u;
    }
    if (!target) {
      res.writeHead(404, CORS);
      res.end(JSON.stringify({ error: "Canal no encontrado" }));
      return;
    }
    const sid = startSession(target);
    res.writeHead(200, { ...CORS, "content-type": "application/json" });
    res.end(JSON.stringify({ sid, playlist: `/hls/${sid}/live.m3u8` }));
    return;
  }

  // Mantener prendido sin reproducir: GET /ping/:sid
  const ping = url.pathname.match(/^\/ping\/([^/]+)$/);
  if (ping) {
    const s = sessions.get(ping[1]);
    if (s) s.lastAccess = Date.now();
    res.writeHead(s ? 204 : 404, CORS); res.end(); return;
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
    if (file.includes("..") || file.includes("/")) { res.writeHead(400, CORS); res.end(); return; }
    const filePath = path.join(s.dir, file);

    try {
      await waitForFile(filePath, 15000);
      const data = fs.readFileSync(filePath);
      const ct = file.endsWith(".m3u8")
        ? "application/vnd.apple.mpegurl"
        : "video/mp2t";
      res.writeHead(200, { ...CORS, "content-type": ct, "access-control-expose-headers": "*" });
      res.end(data);
    } catch (e) {
      res.writeHead(502, CORS);
      res.end("Archivo no disponible aún");
    }
    return;
  }

  res.writeHead(400, CORS);
  res.end("Usa /play/winsport.m3u8, /play/local1.m3u8 o /play/local2.m3u8");
});

server.listen(PORT, () => console.log(`Proxy HLS corriendo en puerto ${PORT}`));
