const http = require("node:http");
const https = require("node:https");
const { Readable } = require("node:stream");
const { spawn } = require("child_process");
const { randomBytes, randomUUID, timingSafeEqual } = require("crypto");
const fs = require("fs");
const path = require("path");
const os = require("os");
const dns = require("node:dns/promises");
const net = require("node:net");

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
const PREVIOUS_KEY = process.env.RELAY_KEY_PREVIOUS || "";
const UA = "VLC/3.0.20 LibVLC/3.0.20";

function safeEqual(candidate, expected) {
  if (typeof candidate !== "string" || !expected) return false;
  const a = Buffer.from(candidate);
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}

// Protected endpoints require Authorization: Bearer; query-string credentials are rejected.
function hasRelayAuth(req) {
  const keys = [KEY, PREVIOUS_KEY].filter(Boolean);
  if (!keys.length) return false;
  const match = /^Bearer\s+(.+)$/i.exec(req.headers.authorization || "");
  return Boolean(match && keys.some((key) => safeEqual(match[1], key)));
}

function requireRelayAuth(req, res) {
  if (!KEY && !PREVIOUS_KEY) {
    res.writeHead(503, CORS);
    res.end("Relay sin RELAY_KEY configurada");
    return false;
  }
  if (!hasRelayAuth(req)) {
    res.writeHead(403, CORS);
    res.end("Prohibido");
    return false;
  }
  return true;
}

async function readJsonBody(req, maxBytes = 65536) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > maxBytes) {
      const error = new Error("Cuerpo demasiado grande");
      error.statusCode = 413;
      throw error;
    }
    chunks.push(chunk);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    const error = new Error("JSON inválido");
    error.statusCode = 400;
    throw error;
  }
}

function ipv4IsPublic(address) {
  const parts = address.split(".").map(Number);
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return false;
  const [a, b, c] = parts;
  return !(a === 0 || a === 10 || a === 127 || a >= 224 ||
    (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) || (a === 192 && (b === 0 || b === 168)) ||
    (a === 192 && b === 88 && c === 99) ||
    (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) ||
    (a === 203 && b === 0 && c === 113));
}

function ipv6ToBigInt(address) {
  let normalized = address.toLowerCase().split("%")[0] || "";
  if (normalized.includes(".")) {
    const lastColon = normalized.lastIndexOf(":");
    const ipv4 = normalized.slice(lastColon + 1).split(".").map(Number);
    if (ipv4.length !== 4 || ipv4.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return null;
    const high = ((ipv4[0] << 8) | ipv4[1]).toString(16);
    const low = ((ipv4[2] << 8) | ipv4[3]).toString(16);
    normalized = normalized.slice(0, lastColon + 1) + high + ":" + low;
  }
  const sections = normalized.split("::");
  if (sections.length > 2) return null;
  const left = sections[0] ? sections[0].split(":").filter(Boolean) : [];
  const right = sections.length === 2 && sections[1] ? sections[1].split(":").filter(Boolean) : [];
  const missing = 8 - left.length - right.length;
  if (missing < 0 || (sections.length === 1 && missing !== 0)) return null;
  const words = [...left, ...Array(missing).fill("0"), ...right];
  if (words.length !== 8 || words.some((word) => !/^[0-9a-f]{1,4}$/.test(word))) return null;
  return words.reduce((value, word) => (value << 16n) | BigInt(parseInt(word, 16)), 0n);
}

function isPublicAddress(address, family = net.isIP(address)) {
  if (family === 4) return ipv4IsPublic(address);
  if (family !== 6) return false;
  const value = ipv6ToBigInt(address);
  if (value === null || ((value >> 125n) & 0x7n) !== 0x1n) return false;
  if ((value >> 96n) === 0x20010db8n) return false;
  if ((value >> 80n) === 0x200100020000n) return false;
  return true;
}

async function resolvePublicTarget(value) {
  let parsed;
  try { parsed = new URL(value); } catch { throw new Error("URL de origen inválida"); }
  if (!["http:", "https:"].includes(parsed.protocol) || parsed.username || parsed.password) throw new Error("URL de origen no permitida");
  const hostname = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (!hostname || hostname === "localhost" || hostname.endsWith(".localhost") || hostname.endsWith(".local") || hostname.endsWith(".internal")) throw new Error("Host local no permitido");
  const family = net.isIP(hostname);
  const records = family ? [{ address: hostname, family }] : await dns.lookup(hostname, { all: true, verbatim: true });
  if (!records.length || records.some((record) => !isPublicAddress(record.address, record.family))) throw new Error("El host de origen resuelve a una dirección no pública");
  const address = records.find((record) => record.family === 4) || records[0];
  return { url: parsed, address };
}

async function validatePublicTarget(value) {
  const resolved = await resolvePublicTarget(value);
  return resolved.url.href;
}
function pinnedLookupFor(address) {
  return (_hostname, options, callback) => {
    if (typeof options === "function") { callback = options; options = {}; }
    if (options && options.all) callback(null, [{ address: address.address, family: address.family }]);
    else callback(null, address.address, address.family);
  };
}

function forwardedHeaders(source) {
  const result = new Headers();
  const hopByHop = new Set(["connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade"]);
  for (const [name, raw] of Object.entries(source)) {
    if (raw === undefined || hopByHop.has(name.toLowerCase())) continue;
    if (Array.isArray(raw)) {
      if (name.toLowerCase() === "set-cookie") raw.forEach((value) => result.append(name, value));
      else result.set(name, raw.join(", "));
    } else result.set(name, String(raw));
  }
  return result;
}

// One upstream HTTP(S) request. DNS is resolved/checked here and the socket uses exactly that answer.
async function pinnedHttpFetch(value, init = {}) {
  const resolved = await resolvePublicTarget(value);
  const target = resolved.url;
  const address = resolved.address;
  const method = init.method || "GET";
  if (method !== "GET" && method !== "HEAD") throw new Error("Método de salida no permitido");
  const client = target.protocol === "https:" ? https : http;
  const headers = {};
  new Headers(init.headers).forEach((headerValue, name) => { headers[name] = headerValue; });
  delete headers["proxy-authorization"];
  delete headers["proxy-connection"];
  if (!headers.host) headers.host = target.host;
  return new Promise((resolve, reject) => {
    const request = client.request({
      protocol: target.protocol,
      hostname: target.hostname.startsWith("[") && target.hostname.endsWith("]") ? target.hostname.slice(1, -1) : target.hostname,
      port: target.port ? Number(target.port) : undefined,
      method,
      path: target.pathname + target.search,
      headers,
      agent: false,
      lookup: pinnedLookupFor(address),
      signal: init.signal || undefined,
    }, (upstream) => {
      const status = upstream.statusCode || 502;
      if (status < 200) { upstream.destroy(); reject(new Error("Respuesta de origen no válida")); return; }
      const body = method === "HEAD" || [204, 205, 304].includes(status) ? null : Readable.toWeb(upstream);
      resolve({
        response: new Response(body, { status, statusText: upstream.statusMessage, headers: forwardedHeaders(upstream.headers) }),
        finalUrl: target.href,
      });
    });
    request.on("error", reject);
    request.setTimeout(20000, () => request.destroy(new Error("Tiempo de espera de origen agotado")));
    request.end();
  });
}

const OUTBOUND_PROXY_USER = "mitube-relay";
const OUTBOUND_PROXY_PASSWORD = randomBytes(32).toString("hex");
let OUTBOUND_PROXY_URL = "";
function expectedProxyAuthorization() {
  return "Basic " + Buffer.from(`${OUTBOUND_PROXY_USER}:${OUTBOUND_PROXY_PASSWORD}`).toString("base64");
}
function hasOutboundProxyAuth(req) {
  return safeEqual(req.headers["proxy-authorization"], expectedProxyAuthorization());
}
function writeConnectError(socket, status, reason) {
  if (socket.destroyed) return;
  socket.end(`HTTP/1.1 ${status} ${reason}\r\nConnection: close\r\n\r\n`);
}

// Loopback-only authenticated proxy used by FFmpeg. HTTP requests and HTTPS CONNECT tunnels
// resolve and validate every destination; HTTPS TLS/SNI remains end-to-end inside the tunnel.
const outboundProxyServer = http.createServer(async (req, res) => {
  if (!hasOutboundProxyAuth(req)) {
    res.writeHead(407, { "proxy-authenticate": 'Basic realm="MiTube relay"', connection: "close" });
    res.end();
    return;
  }
  if (req.method !== "GET" && req.method !== "HEAD") { res.writeHead(405, { connection: "close" }); res.end(); return; }
  let target;
  try {
    const raw = req.url || "/";
    target = raw.startsWith("http://") || raw.startsWith("https://")
      ? new URL(raw)
      : new URL(raw, `http://${req.headers.host || ""}`);
  } catch { res.writeHead(400, { connection: "close" }); res.end(); return; }
  if (target.protocol !== "http:") { res.writeHead(400, { connection: "close" }); res.end(); return; }
  try {
    const cleanHeaders = {};
    for (const [name, value] of Object.entries(req.headers)) {
      if (["proxy-authorization", "proxy-connection", "connection", "keep-alive", "transfer-encoding", "upgrade", "te", "trailer"].includes(name.toLowerCase()) || value === undefined) continue;
      cleanHeaders[name] = value;
    }
    cleanHeaders.host = target.host;
    const pinned = await pinnedHttpFetch(target.href, { method: req.method, headers: cleanHeaders });
    res.writeHead(pinned.response.status, Object.fromEntries(pinned.response.headers.entries()));
    if (!pinned.response.body) { res.end(); return; }
    for await (const chunk of pinned.response.body) {
      if (!res.write(Buffer.from(chunk))) await new Promise((resolve) => res.once("drain", resolve));
    }
    res.end();
  } catch {
    if (!res.headersSent) res.writeHead(502, { connection: "close" });
    res.end();
  }
});

outboundProxyServer.on("connect", async (req, clientSocket, head) => {
  if (!hasOutboundProxyAuth(req)) { writeConnectError(clientSocket, 407, "Proxy Authentication Required"); return; }
  let target;
  try { target = new URL(`https://${req.url || ""}`); }
  catch { writeConnectError(clientSocket, 400, "Bad Request"); return; }
  if (target.pathname !== "/" || target.search || target.hash || target.username || target.password) { writeConnectError(clientSocket, 400, "Bad Request"); return; }
  const port = target.port ? Number(target.port) : 443;
  if (!Number.isInteger(port) || port < 1 || port > 65535) { writeConnectError(clientSocket, 400, "Bad Request"); return; }
  try {
    const resolved = await resolvePublicTarget(target.href);
    const upstream = net.connect({ host: resolved.address.address, port, family: resolved.address.family });
    let connected = false;
    const timer = setTimeout(() => upstream.destroy(new Error("Tiempo de espera de origen agotado")), 15000);
    upstream.once("connect", () => {
      connected = true;
      clearTimeout(timer);
      clientSocket.write("HTTP/1.1 200 Connection Established\r\nProxy-Agent: MiTube-Relay\r\n\r\n");
      if (head && head.length) upstream.write(head);
      clientSocket.pipe(upstream);
      upstream.pipe(clientSocket);
    });
    upstream.on("error", () => {
      clearTimeout(timer);
      if (!connected) writeConnectError(clientSocket, 502, "Bad Gateway");
      clientSocket.destroy();
    });
    clientSocket.on("error", () => upstream.destroy());
    clientSocket.on("close", () => upstream.destroy());
  } catch { writeConnectError(clientSocket, 403, "Forbidden"); }
});
outboundProxyServer.on("clientError", (_error, socket) => writeConnectError(socket, 400, "Bad Request"));

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
    "-http_proxy", OUTBOUND_PROXY_URL,
    "-protocol_whitelist", "http,https,tcp,tls,crypto,data",
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
    // Do not echo FFmpeg output: upstream URLs may contain private tokens.
    const message = d.toString().toLowerCase();
    if (/error|failed|invalid|unable/.test(message)) {
      s.lastError = "FFmpeg reportó un error; detalle oculto por seguridad";
    }
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
  let host = "origen desconocido";
  try { host = new URL(target).hostname; } catch {}
  console.log(`[session] iniciada ${sid} para ${host}`);
  return sid;
}

function waitForFile(filePath, timeout = 15000) {
  return new Promise((resolve, reject) => {
    const start = Date.now();
    const check = () => {
      try {
        if (fs.existsSync(filePath) && fs.statSync(filePath).size > 0) return resolve();
      } catch {}
      if (Date.now() - start > timeout) return reject(new Error("timeout esperando archivo"));
      setTimeout(check, 300);
    };
    check();
  });
}

// No anunciar HLS listo solo porque FFmpeg creó el archivo: puede estar vacío,
// truncado o todavía no tener segmentos. Esperar una lista completa y al menos
// un segmento real evita devolver manifiestos que el reproductor no puede usar.
function waitForPlaylist(filePath, timeout = 30000) {
  return new Promise((resolve, reject) => {
    const start = Date.now();
    const dir = path.dirname(filePath);
    const check = () => {
      try {
        if (fs.existsSync(filePath)) {
          const manifest = fs.readFileSync(filePath, "utf8");
          const lines = manifest.split(/\r?\n/).map((line) => line.trim());
          const hasHeader = lines[0] === "#EXTM3U";
          const hasSegments = lines.some((line) => line.startsWith("#EXTINF:"));
          const segmentNames = lines.filter((line) => line && !line.startsWith("#"));
          const hasWrittenSegment = segmentNames.some((name) => {
            if (name.includes("/") || name.includes("\\") || name === "." || name === "..") return false;
            const segmentPath = path.resolve(dir, name);
            if (!segmentPath.startsWith(path.resolve(dir) + path.sep)) return false;
            try { return fs.statSync(segmentPath).isFile() && fs.statSync(segmentPath).size > 0; }
            catch { return false; }
          });
          if (hasHeader && hasSegments && segmentNames.length > 0 && hasWrittenSegment) return resolve();
        }
      } catch {}
      if (Date.now() - start > timeout) return reject(new Error("timeout esperando lista HLS válida y segmento"));
      setTimeout(check, 350);
    };
    check();
  });
}

// Relé genérico: abre cualquier señal http/https (IPs, puertos raros) y la
// reenvía tal cual, como haría VLC. GET /fetch?u=<url> + Authorization: Bearer <RELAY_KEY>
async function relayFetch(req, res, url) {
  if (!requireRelayAuth(req, res)) return;
  const target = url.searchParams.get("u") || "";
  if (!/^https?:\/\//i.test(target)) {
    res.writeHead(400, CORS);
    res.end("Falta u=");
    return;
  }
  const ac = new AbortController();
  req.on("close", () => ac.abort());
  try {
    let current = target;
    let r = null;
    for (let redirects = 0; redirects <= 4; redirects++) {
      const fetched = await pinnedHttpFetch(current, {
        headers: { "user-agent": UA, accept: "*/*" },
        signal: ac.signal,
      });
      r = fetched.response;
      current = fetched.finalUrl;
      if (r.status < 300 || r.status >= 400) break;
      const location = r.headers.get("location");
      if (!location || redirects === 4) {
        try { await r.body?.cancel(); } catch {}
        throw new Error("Redirección de origen no válida");
      }
      const next = new URL(location, current);
      if (new URL(current).protocol === "https:" && next.protocol !== "https:") {
        try { await r.body?.cancel(); } catch {}
        throw new Error("Redirección HTTPS a HTTP bloqueada");
      }
      try { await r.body?.cancel(); } catch {}
      current = next.href;
    }
    if (!r) throw new Error("No hubo respuesta del origen");
    res.writeHead(r.status, {
      ...CORS,
      "content-type": r.headers.get("content-type") || "application/octet-stream",
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
    if (!requireRelayAuth(req, res)) return;
    const target = ALLOWED[play[1]];
    if (!target) { res.writeHead(404, CORS); res.end("Canal no encontrado"); return; }
    let safeTarget;
    try { safeTarget = await validatePublicTarget(target); }
    catch { res.writeHead(400, CORS); res.end("Destino de origen no permitido"); return; }
    const sid = startSession(safeTarget);
    try {
      await waitForPlaylist(path.join(sessions.get(sid).dir, "live.m3u8"), 35000);
      res.writeHead(302, { ...CORS, location: `/hls/${sid}/live.m3u8` });
      res.end();
    } catch {
      res.writeHead(502, CORS);
      res.end("El canal no arrancó. Revisa /status");
    }
    return;
  }

  // Protected diagnostics: Authorization: Bearer <RELAY_KEY>
  if (url.pathname === "/status") {
    if (!requireRelayAuth(req, res)) return;
    const out = [...sessions].map(([sid, x]) => {
      let upstreamHost = "unknown";
      try { upstreamHost = new URL(x.target).hostname; } catch {}
      return { sid, upstreamHost, restarts: x.restarts || 0, error: x.lastError || null };
    });
    res.writeHead(200, { ...CORS, "content-type": "application/json" });
    res.end(JSON.stringify(out, null, 2));
    return;
  }

  // Relé genérico: GET /fetch?u=<url> requires Authorization: Bearer
  if (url.pathname === "/fetch") {
    await relayFetch(req, res, url);
    return;
  }

  // Prefer POST /start + Bearer + JSON {"u":"https://..."} for arbitrary sources.
  // GET /start?id=local1 remains available for preapproved channels.
  if (url.pathname === "/start") {
    if (!requireRelayAuth(req, res)) return;
    if (req.method === "POST") {
      let body;
      try {
        body = await readJsonBody(req);
      } catch (error) {
        res.writeHead(error.statusCode || 400, CORS);
        res.end(error.statusCode === 413 ? "Cuerpo demasiado grande" : "JSON inválido");
        return;
      }
      const u = body && typeof body.u === "string" ? body.u : "";
      let parsed;
      try { parsed = new URL(u); } catch {}
      if (!parsed || !["http:", "https:"].includes(parsed.protocol)) {
        res.writeHead(400, CORS);
        res.end(JSON.stringify({ error: "URL http/https requerida" }));
        return;
      }
      let safeTarget;
      try { safeTarget = await validatePublicTarget(parsed.href); }
      catch { res.writeHead(400, { ...CORS, "content-type": "application/json" }); res.end(JSON.stringify({ error: "Destino de origen no permitido" })); return; }
      const sid = startSession(safeTarget);
      const session = sessions.get(sid);
      if (!session) {
        res.writeHead(502, { ...CORS, "content-type": "application/json" });
        res.end(JSON.stringify({ error: "No se pudo crear la sesión HLS" }));
        return;
      }
      try {
        await waitForPlaylist(path.join(session.dir, "live.m3u8"), 35000);
      } catch {
        res.writeHead(502, { ...CORS, "content-type": "application/json" });
        res.end(JSON.stringify({ error: "La fuente no entregó una lista HLS con segmentos reproducibles" }));
        return;
      }
      res.writeHead(200, { ...CORS, "content-type": "application/json" });
      res.end(JSON.stringify({ sid, playlist: `/hls/${sid}/live.m3u8` }));
      return;
    }

    if (req.method !== "GET") {
      res.writeHead(405, { ...CORS, allow: "GET, POST" });
      res.end("Método no permitido");
      return;
    }

    const id = url.searchParams.get("id");
    let target = id ? ALLOWED[id] : null;
    const u = url.searchParams.get("u");
    if (!target && u) {
      let parsed;
      try { parsed = new URL(u); } catch {}
      if (parsed && ["http:", "https:"].includes(parsed.protocol)) target = parsed.href;
    }
    if (!target) {
      res.writeHead(404, CORS);
      res.end(JSON.stringify({ error: "Canal no encontrado" }));
      return;
    }
    let safeTarget;
    try { safeTarget = await validatePublicTarget(target); }
    catch { res.writeHead(400, { ...CORS, "content-type": "application/json" }); res.end(JSON.stringify({ error: "Destino de origen no permitido" })); return; }
    const sid = startSession(safeTarget);
    res.writeHead(200, { ...CORS, "content-type": "application/json" });
    res.end(JSON.stringify({ sid, playlist: `/hls/${sid}/live.m3u8` }));
    return;
  }
  // Mantener prendido sin reproducir: GET /ping/:sid
  const ping = url.pathname.match(/^\/ping\/([^/]+)$/);
  if (ping) {
    if (!requireRelayAuth(req, res)) return;
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
      if (file.endsWith(".m3u8")) await waitForPlaylist(filePath, 20000);
      else await waitForFile(filePath, 15000);
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

outboundProxyServer.listen(0, "127.0.0.1", () => {
  const address = outboundProxyServer.address();
  if (!address || typeof address === "string") {
    console.error("No se pudo iniciar el proxy de salida");
    process.exit(1);
    return;
  }
  OUTBOUND_PROXY_URL = `http://${OUTBOUND_PROXY_USER}:${OUTBOUND_PROXY_PASSWORD}@127.0.0.1:${address.port}`;
  server.listen(PORT, () => console.log(`Proxy HLS corriendo en puerto ${PORT}`));
});
