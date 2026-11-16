#!/usr/bin/env node
/*
 * TAKE — servidor de set
 * Serve o app e liga os aparelhos pela rede local, sem internet e sem instalar nada.
 *
 *   1. deixe take.html na mesma pasta deste arquivo
 *   2. node take-server.js            (ou: node take-server.js 8080)
 *   3. abra no tablet e no celular o endereço que aparecer na tela
 *
 * Câmera: navegador só libera câmera em página segura. Em http:// comum ela não abre.
 * Para ter câmera na rede local, gere um certificado nesta pasta e o servidor usa sozinho:
 *   openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 825 -subj "/CN=take"
 * Cada aparelho vai avisar que o certificado é próprio; aceite uma vez.
 */
"use strict";
const http = require("http"), https = require("https"), fs = require("fs"),
      path = require("path"), crypto = require("crypto"), os = require("os");

const DIR  = __dirname;
const PORT = Number(process.env.PORT || process.argv[2] || 8080);
const GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

const appFile = ["take.html", "index.html"].map(f => path.join(DIR, f)).find(p => fs.existsSync(p));
const certFile = path.join(DIR, "cert.pem"), keyFile = path.join(DIR, "key.pem");
const secure = fs.existsSync(certFile) && fs.existsSync(keyFile);

/* ---------------- http ---------------- */
function handler(req, res) {
  const u = new URL(req.url, "http://local");
  if (u.pathname === "/" || u.pathname === "/index.html" || u.pathname === "/take.html") {
    if (!appFile) { res.writeHead(500, {"content-type":"text/plain; charset=utf-8"});
      return res.end("Coloque o arquivo take.html na mesma pasta deste servidor."); }
    res.writeHead(200, {"content-type":"text/html; charset=utf-8","cache-control":"no-store"});
    return res.end(fs.readFileSync(appFile));
  }
  if (u.pathname === "/status") {
    const salas = {};
    rooms.forEach((set, nome) => salas[nome] = [...set].map(c => (c.presence && c.presence.role) || "?"));
    res.writeHead(200, {"content-type":"application/json; charset=utf-8"});
    return res.end(JSON.stringify({ ok:true, seguro:secure, salas }, null, 2));
  }
  res.writeHead(404, {"content-type":"text/plain; charset=utf-8"});
  res.end("não encontrado");
}
const server = secure
  ? https.createServer({ cert: fs.readFileSync(certFile), key: fs.readFileSync(keyFile) }, handler)
  : http.createServer(handler);

/* ---------------- websocket ---------------- */
const rooms = new Map();
let nextId = 1;

server.on("upgrade", (req, socket) => {
  const u = new URL(req.url, "http://local");
  const key = req.headers["sec-websocket-key"];
  if (u.pathname !== "/ws" || !key) return socket.destroy();
  const accept = crypto.createHash("sha1").update(key + GUID).digest("base64");
  socket.write("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n" +
               "Connection: Upgrade\r\nSec-WebSocket-Accept: " + accept + "\r\n\r\n");
  socket.setNoDelay(true);

  const c = { id: "p" + (nextId++), socket,
              room: u.searchParams.get("room") || "geral",
              presence: { role: u.searchParams.get("role") || "?" },
              buf: Buffer.alloc(0), frag: null, alive: true };
  join(c);
  socket.on("data", d => { c.buf = Buffer.concat([c.buf, d]); try { drain(c); } catch (e) { leave(c); } });
  socket.on("close", () => leave(c));
  socket.on("error", () => leave(c));
});

function join(c) {
  if (!rooms.has(c.room)) rooms.set(c.room, new Set());
  rooms.get(c.room).add(c);
  log("entrou  " + c.id + "  sala " + c.room + "  papel " + c.presence.role);
  peers(c.room);
}
function leave(c) {
  if (!c.alive) return; c.alive = false;
  const set = rooms.get(c.room);
  if (set) { set.delete(c); if (!set.size) rooms.delete(c.room); }
  log("saiu    " + c.id + "  sala " + c.room);
  peers(c.room);
}
function peers(room) {
  const set = rooms.get(room); if (!set) return;
  const all = [...set];
  for (const c of set) sendJSON(c, { topic: "peers", data: { peers: all.map(o => ({
      peer: o.id, isMe: o === c, sameTab: o === c, kind: "viewer", guest: false,
      presence: o.presence, updatedAt: Date.now() })) } });
}
function onMessage(c, text) {
  let m; try { m = JSON.parse(text); } catch (e) { return; }
  if (!m || !m.topic) return;
  if (m.topic === "presence") { c.presence = m.data || {}; return peers(c.room); }
  const set = rooms.get(c.room); if (!set) return;
  for (const o of set) if (o !== c)
    sendJSON(o, { peer: c.id, isMe: false, sameTab: false, kind: "viewer", guest: false,
                  topic: m.topic, data: m.data });
}

/* quadros */
function drain(c) {
  for (;;) {
    const b = c.buf;
    if (b.length < 2) return;
    const fin = (b[0] & 0x80) !== 0, op = b[0] & 0x0f, masked = (b[1] & 0x80) !== 0;
    let len = b[1] & 0x7f, off = 2;
    if (len === 126) { if (b.length < 4) return; len = b.readUInt16BE(2); off = 4; }
    else if (len === 127) { if (b.length < 10) return;
      len = b.readUInt32BE(2) * 4294967296 + b.readUInt32BE(6); off = 10; }
    const maskOff = off; if (masked) { if (b.length < off + 4) return; off += 4; }
    if (b.length < off + len) return;
    const pay = Buffer.from(b.subarray(off, off + len));
    if (masked) { const mk = b.subarray(maskOff, maskOff + 4);
      for (let i = 0; i < pay.length; i++) pay[i] ^= mk[i & 3]; }
    c.buf = b.subarray(off + len);
    if (op === 0x8) { leave(c); try { c.socket.end(); } catch (e) {} return; }
    if (op === 0x9) { frame(c, 0xA, pay); continue; }
    if (op === 0xA) continue;
    c.frag = c.frag ? Buffer.concat([c.frag, pay]) : pay;
    if (fin) { const t = c.frag.toString("utf8"); c.frag = null; onMessage(c, t); }
  }
}
function frame(c, op, pay) {
  const n = pay.length; let head;
  if (n < 126) { head = Buffer.alloc(2); head[1] = n; }
  else if (n < 65536) { head = Buffer.alloc(4); head[1] = 126; head.writeUInt16BE(n, 2); }
  else { head = Buffer.alloc(10); head[1] = 127;
    head.writeUInt32BE(Math.floor(n / 4294967296), 2); head.writeUInt32BE(n >>> 0, 6); }
  head[0] = 0x80 | op;
  try { c.socket.write(Buffer.concat([head, pay])); } catch (e) {}
}
const sendJSON = (c, o) => frame(c, 0x1, Buffer.from(JSON.stringify(o), "utf8"));
const log = m => console.log("  " + new Date().toLocaleTimeString("pt-BR") + "  " + m);

/* ---------------- sobe ---------------- */
function enderecos() {
  const out = [];
  const ifs = os.networkInterfaces();
  for (const nome in ifs) for (const i of ifs[nome])
    if (i.family === "IPv4" && !i.internal) out.push(i.address);
  return out;
}
server.listen(PORT, () => {
  const proto = secure ? "https" : "http";
  console.log("\n  TAKE — servidor de set" + (secure ? "  (seguro, câmera liberada)" : ""));
  console.log("  " + (appFile ? "servindo " + path.basename(appFile) : "ATENÇÃO: take.html não está nesta pasta"));
  console.log("\n  abra nos aparelhos:");
  enderecos().forEach(ip => console.log("     " + proto + "://" + ip + ":" + PORT));
  console.log("     " + proto + "://localhost:" + PORT + "   (neste computador)");
  if (!secure) console.log("\n  câmera não abre em http — veja o comentário no topo deste arquivo para ligar o modo seguro");
  console.log("\n  no app: Controle remoto → Conexão → Rede local → " +
              (enderecos()[0] || "seu-ip") + ":" + PORT + "\n  encerre com Ctrl+C\n");
});
server.on("error", e => {
  if (e.code === "EADDRINUSE") console.error("\n  a porta " + PORT + " já está em uso. Rode: node take-server.js 8081\n");
  else console.error(e);
  process.exit(1);
});
