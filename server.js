const http = require("http");

const ALLOWED = {
  winsport: "http://138.121.15.230:9002/WIN-SPORT/index.m3u8",
  local1:   "http://15.204.146.163:8002/play/a00h/index.m3u8",
  local2:   "http://181.78.12.119:16123/play/ch18/index.m3u8",
};

const CORS = {
  "access-control-allow-origin": "*",
  "cache-control": "no-store",
};

async function proxyM3U8(targetUrl, proxyBase, res) {
  try {
    const r = await fetch(targetUrl, {
      headers: { "user-agent": "VLC/3.0.20 LibVLC/3.0.20" },
      signal: AbortSignal.timeout(15000),
    });
    if (!r.ok) {
      res.writeHead(502, CORS);
      res.end("Canal no disponible");
      return;
    }
    const text = await r.text();
    if (!text.includes("#EXT")) {
      res.writeHead(502, CORS);
      res.end("Sin señal");
      return;
    }

    const base = new URL(targetUrl);
    const rewritten = text.split(/\r?\n/).map(line => {
      const t = line.trim();
      if (!t || t.startsWith("#")) return line;
      try {
        const abs = new URL(t, base).toString();
        return `${proxyBase}?raw=${encodeURIComponent(abs)}`;
      } catch {
        return line;
      }
    }).join("\n");

    res.writeHead(200, { ...CORS, "content-type": "application/vnd.apple.mpegurl" });
    res.end(rewritten);
  } catch (e) {
    res.writeHead(502, CORS);
    res.end("Error: " + e.message);
  }
}

const PORT = process.env.PORT || 3000;

http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);
  const proxyBase = `https://${req.headers.host}/proxy`;

  if (url.pathname === "/proxy") {
    const id  = url.searchParams.get("id");
    const raw = url.searchParams.get("raw");

    if (id) {
      const target = ALLOWED[id];
      if (!target) {
        res.writeHead(404, CORS);
        res.end("Canal no encontrado");
        return;
      }
      return proxyM3U8(target, proxyBase, res);
    }

    if (raw) {
      try {
        const r = await fetch(raw, {
          headers: { "user-agent": "VLC/3.0.20 LibVLC/3.0.20" },
          signal: AbortSignal.timeout(15000),
        });
        const ct = r.headers.get("content-type") || "video/mp2t";
        if (ct.includes("mpegurl") || raw.includes(".m3u8")) {
          return proxyM3U8(raw, proxyBase, res);
        }
        res.writeHead(r.status, { ...CORS, "content-type": ct });
        const reader = r.body.getReader();
        const pump = async () => {
          const { done, value } = await reader.read();
          if (done) { res.end(); return; }
          res.write(value);
          pump();
        };
        pump();
      } catch (e) {
        res.writeHead(502, CORS);
        res.end("Error: " + e.message);
      }
      return;
    }

    res.writeHead(400, CORS);
    res.end("Usa ?id=winsport, ?id=local1 o ?id=local2");
    return;
  }

  res.writeHead(200);
  res.end("Proxy activo ✓");
}).listen(PORT, () => console.log(`Proxy corriendo en puerto ${PORT}`));
