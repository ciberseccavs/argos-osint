"""
API OSINT - servidor web usando SOLO la libreria estandar de Python
(http.server), para que no haga falta instalar FastAPI/uvicorn ni compilar
nada. Las consultas las hace collectors.py (httpx, dnspython, phonenumbers,
todas librerias que se instalan sin compilador).

Uso:
    pip install -r requirements.txt
    python main.py

Luego abri en el navegador:
    http://127.0.0.1:8000/
"""

import asyncio
import base64
import json
import os
import sqlite3
import threading
import urllib.parse
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import collectors

# En la nube (Render) estas variables llegan por el entorno.
# HOST 0.0.0.0 es obligatorio para que el servidor sea accesible desde afuera.
HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "8000"))

# Clave de acceso (se configura en Render como variables de entorno).
# Si ARGOS_PASS esta vacio, la app queda ABIERTA (solo para uso local).
ARGOS_USER = os.environ.get("ARGOS_USER", "argos")
ARGOS_PASS = os.environ.get("ARGOS_PASS", "")

TIPOS = ["ip", "domain", "email", "username", "phone", "person", "cbu", "url", "patente"]

# --------------------------------------------------------------------------- #
# Auditoria: registra quien consulto que y cuando (rendicion de cuentas).
# NOTA sobre persistencia: en el plan gratuito de Render el disco es efimero
# (se reinicia al redesplegar o al dormirse). Para auditoria PERMANENTE hace
# falta un disco pago o una base externa; ver ARGOS_DB abajo.
# --------------------------------------------------------------------------- #
DB_PATH = os.environ.get("ARGOS_DB", "argos_audit.db")
_db_lock = threading.Lock()
_db = sqlite3.connect(DB_PATH, check_same_thread=False)
_db.execute("""CREATE TABLE IF NOT EXISTS auditoria (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fecha_utc TEXT, usuario TEXT, tipo TEXT, dato TEXT, origen TEXT)""")
_db.commit()


def registrar_auditoria(usuario, tipo, dato, origen):
    try:
        with _db_lock:
            _db.execute(
                "INSERT INTO auditoria (fecha_utc, usuario, tipo, dato, origen) VALUES (?,?,?,?,?)",
                (datetime.now(timezone.utc).isoformat(timespec="seconds"),
                 usuario, tipo or "", dato, origen))
            _db.commit()
    except Exception:
        pass

PAGINA = """<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="theme-color" content="#0f172a">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<meta name="apple-mobile-web-app-title" content="ARGos">
<link rel="apple-touch-icon" href="/icon.png">
<link rel="manifest" href="/manifest.json">
<title>ARGos - Inteligencia preventiva de fuentes abiertas</title>
<style>
  :root { color-scheme: light dark; }
  * { box-sizing: border-box; }
  body { font-family: system-ui, Segoe UI, Arial, sans-serif; margin: 0;
         background: #0f172a; color: #e2e8f0; }
  .wrap { max-width: 860px; margin: 0 auto; padding: 28px 18px 60px; }
  h1 { font-size: 22px; margin: 0 0 4px; }
  .sub { color: #94a3b8; font-size: 14px; margin: 0 0 22px; }
  .card { background: #1e293b; border: 1px solid #334155; border-radius: 12px;
          padding: 18px; margin-bottom: 18px; }
  label { display: block; font-size: 13px; color: #94a3b8; margin-bottom: 6px; }
  input, select { width: 100%; padding: 11px 12px; border-radius: 8px;
         border: 1px solid #475569; background: #0f172a; color: #e2e8f0;
         font-size: 15px; }
  .row { display: flex; gap: 12px; flex-wrap: wrap; }
  .row > div:first-child { flex: 1 1 320px; }
  .row > div:last-child { flex: 0 0 180px; }
  button { margin-top: 14px; width: 100%; padding: 12px; border: 0;
         border-radius: 8px; background: #2563eb; color: #fff; font-size: 15px;
         font-weight: 600; cursor: pointer; }
  button:hover { background: #1d4ed8; }
  button:disabled { background: #475569; cursor: default; }
  .hint { font-size: 12px; color: #64748b; margin-top: 10px; }
  .res { white-space: pre-wrap; word-break: break-word; font-family:
         ui-monospace, Consolas, monospace; font-size: 13px; line-height: 1.5; }
  .ok { color: #4ade80; } .bad { color: #f87171; }
  .src { font-weight: 700; margin-top: 14px; color: #e2e8f0; }
  .k { color: #93c5fd; }
  .empty { color: #64748b; }
  .lnk { color: #38bdf8; text-decoration: underline; word-break: break-all; }
  .guia { background:#131d30; border:1px solid #334155; border-radius:12px; padding:0 16px; margin-bottom:18px; }
  .guia summary { cursor:pointer; padding:14px 0; font-weight:600; color:#cbd5e1; list-style:none; }
  .guia summary::-webkit-details-marker { display:none; }
  .guia summary::before { content:"▸ "; color:#64748b; }
  .guia[open] summary::before { content:"▾ "; }
  .guia-body { padding:0 0 14px; font-size:13.5px; line-height:1.6; color:#cbd5e1; }
  .guia-body p { margin:8px 0; } .guia-body ul { margin:6px 0; padding-left:20px; }
  .guia-body li { margin:3px 0; }
  .guia code { background:#0f172a; border:1px solid #334155; border-radius:5px; padding:1px 6px; font-size:12.5px; color:#93c5fd; }
  .flujo { background:#0f172a; border:1px dashed #475569; border-radius:8px; padding:10px 12px; margin:10px 0; font-size:13px; color:#e2e8f0; }
  .flujo b { color:#93c5fd; }
  .guia-nota { background:#1e293b; border-left:3px solid #74acdf; border-radius:6px; padding:8px 10px; font-size:12.5px; color:#94a3b8; }
  .cierre { background:#172033; border:1px solid #334155; border-radius:10px; padding:14px; margin:6px 0 16px; }
  .cierre h3 { margin:0 0 8px; font-size:15px; }
  .col { margin:8px 0; }
  .col b { color:#cbd5e1; font-size:13px; }
  .col ul { margin:4px 0 0; padding-left:18px; }
  .col li { font-size:13px; line-height:1.5; margin:2px 0; }
  .sost { color:#cbd5e1; } .nose { color:#fbbf24; } .deci { color:#e2e8f0; }
  /* Badge NEUTRO a proposito: mide certeza del dato, NO seguridad del contacto. */
  .conf { display:inline-block; padding:2px 10px; border-radius:999px; font-size:12px;
          font-weight:700; background:#1e3a5f; color:#93c5fd; }
  .notea { font-size:12px; color:#94a3b8; font-style:italic; margin-top:8px; }
  .toolbar { display:flex; gap:8px; margin-bottom:10px; flex-wrap:wrap; }
  .mini { width:auto; margin:0; padding:7px 12px; font-size:13px; background:#334155; }
  .mini:hover { background:#475569; }
  @media print {
    body { background:#fff; color:#000; }
    #formulario, .toolbar, .hint, .tag { display:none !important; }
    .card, .cierre { background:#fff !important; border-color:#bbb; }
    .arg { color:#1e40af; } .nose { color:#92400e; } .empty { color:#555; }
    .k { color:#1e3a8a; } .lnk { color:#1e3a8a; }
    .conf { background:#e5e7eb; color:#1e3a8a; }
  }
  .brand { display: flex; align-items: center; gap: 12px; margin-bottom: 4px; }
  .flag { width: 40px; height: 26px; border-radius: 4px; flex: 0 0 auto;
          box-shadow: 0 0 0 1px #334155; }
  .brand h1 { margin: 0; }
  .arg { color: #74acdf; }        /* celeste argentino */
</style>
</head>
<body>
<div class="wrap">
  <div class="brand">
    <svg class="flag" viewBox="0 0 54 36" xmlns="http://www.w3.org/2000/svg" aria-label="Bandera argentina">
      <rect width="54" height="36" fill="#fff"/>
      <rect width="54" height="12" y="0" fill="#74acdf"/>
      <rect width="54" height="12" y="24" fill="#74acdf"/>
      <g transform="translate(27,18)">
        <circle r="4.2" fill="#f6b40e" stroke="#85340a" stroke-width="0.5"/>
        <g fill="#f6b40e" stroke="#85340a" stroke-width="0.3">
          <g id="ray"><polygon points="0,-4.2 1,-7.6 -1,-7.6"/></g>
          <use href="#ray" transform="rotate(30)"/><use href="#ray" transform="rotate(60)"/>
          <use href="#ray" transform="rotate(90)"/><use href="#ray" transform="rotate(120)"/>
          <use href="#ray" transform="rotate(150)"/><use href="#ray" transform="rotate(180)"/>
          <use href="#ray" transform="rotate(210)"/><use href="#ray" transform="rotate(240)"/>
          <use href="#ray" transform="rotate(270)"/><use href="#ray" transform="rotate(300)"/>
          <use href="#ray" transform="rotate(330)"/>
        </g>
      </g>
    </svg>
    <h1><span class="arg">ARG</span>os</h1>
  </div>
  <p class="sub">Inteligencia preventiva de fuentes abiertas — publicas, gratuitas y sin registro.
     &nbsp;·&nbsp; <a href="/logs" style="color:#64748b">Auditoría</a></p>

  <div class="card" id="formulario">
    <div class="row">
      <div>
        <label>Dato a consultar</label>
        <input id="target" placeholder="dominio / IP / email / telefono / nombre / CBU / link / patente"
               autocomplete="off">
      </div>
      <div>
        <label>Tipo</label>
        <select id="tipo">
          <option value="">Detectar solo</option>
          <option value="ip">IP</option>
          <option value="domain">Dominio</option>
          <option value="email">Email</option>
          <option value="username">Usuario</option>
          <option value="phone">Telefono</option>
          <option value="person">Nombre y apellido</option>
          <option value="cbu">CBU / CVU</option>
          <option value="url">Link / URL</option>
          <option value="patente">Patente de auto</option>
        </select>
      </div>
    </div>
    <button id="btn" onclick="consultar()">Consultar</button>
    <p class="hint">Para telefonos usa formato internacional con +codigo de pais
       (ej: +5491150501234). La consulta puede tardar unos segundos.</p>
  </div>

  <details class="guia" open>
    <summary>¿Cómo se usa? — guía rápida</summary>
    <div class="guia-body">
      <div class="flujo">Pegás el dato &nbsp;→&nbsp; <b>Consultar</b> &nbsp;→&nbsp; leés el <b>Cierre</b> &nbsp;→&nbsp; mirás las <b>ayudas</b> &nbsp;→&nbsp; <b>Exportás</b> (si hace falta)</div>
      <p><b>1.</b> Pegá un dato en el cuadro de arriba y tocá <b>Consultar</b>. ARGos detecta solo de qué se trata (o elegís el tipo en el menú).</p>
      <p><b>Qué podés consultar:</b></p>
      <ul>
        <li>📞 Teléfono: <code>+5491150501234</code> &nbsp;·&nbsp; 🏦 CBU/CVU: <code>0110599500000012345674</code></li>
        <li>🌐 Dominio: <code>bcra.gob.ar</code> &nbsp;·&nbsp; 🔗 Link sospechoso: <code>http://sitio-raro.xyz/login</code></li>
        <li>✉️ Email: <code>alguien@dominio.com</code> &nbsp;·&nbsp; 🧑 Nombre: <code>Juan Pérez</code> &nbsp;·&nbsp; 🖥️ IP: <code>8.8.8.8</code></li>
        <li>🚗 Patente: <code>AB123CD</code> o <code>ABC123</code> — dice el tipo y la época del vehículo y te lleva a los portales oficiales para ver <b>deuda de patente</b> y <b>multas</b> por dominio. El <b>titular</b> no es dato abierto: sale del Informe de Dominio del DNRPA (trámite oficial con costo).</li>
      </ul>
      <p><b>2.</b> Leé el <b>Cierre de la investigación</b>: lo que <i>podemos sostener</i>, lo que <i>todavía no sabemos</i> y la <i>decisión prudente</i>.</p>
      <p><b>3.</b> Bajá a las <b>ayudas</b>: búsquedas en Google, fuentes oficiales y enlaces de verificación (imágenes, reportes, etc.).</p>
      <p><b>4.</b> Para dejar constancia, usá <b>🖨 Imprimir / PDF</b> o <b>⬇ Descargar (JSON)</b> — queda con fecha y hora.</p>
      <p class="guia-nota">⚖️ ARGos es para <b>verificar y prevenir</b> con datos públicos. Entrega <b>indicios para decidir, no veredictos</b>, y no sirve para perfilar personas (es la línea que mantiene el uso del lado legal).</p>
    </div>
  </details>

  <div class="card" id="salida" style="display:none">
    <div class="toolbar">
      <button class="mini" onclick="imprimir()">🖨 Imprimir / Guardar PDF</button>
      <button class="mini" onclick="descargarJSON()">⬇ Descargar (JSON)</button>
    </div>
    <div id="meta"></div>
    <div class="res" id="res"></div>
  </div>
</div>

<script>
function esc(s){ return String(s).replace(/[&<>]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;'}[c])); }

function linkify(s){
  if (s === true) return 'Si';
  if (s === false) return 'No';
  if (s === null || s === undefined) return '<span class="empty">(sin dato)</span>';
  const t = String(s);
  if (/^https?:\\/\\//i.test(t))
    return '<a href="' + esc(t) + '" target="_blank" rel="noopener" class="lnk">' + esc(t) + '</a>';
  return esc(t);
}

function renderVal(v){
  if (v === null || v === '') return '<span class="empty">(vacio)</span>';
  if (Array.isArray(v)){
    if (v.length === 0) return '<span class="empty">(ninguno)</span>';
    return '\\n' + v.map(item =>
      '    • ' + (typeof item === 'object' ? renderObjInline(item) : linkify(item))
    ).join('\\n');
  }
  if (typeof v === 'object') return '\\n' + Object.entries(v).map(([k,val]) =>
      '    ' + k + ': ' + (typeof val === 'object' ? renderObjInline(val) : linkify(val))
    ).join('\\n');
  return linkify(v);
}

function renderObjInline(o){
  return Object.entries(o).map(([k,val]) => k + '=' + linkify(val)).join('  ');
}

function renderLista(arr, cls){
  return '<ul>' + (arr||[]).map(x => '<li class="'+cls+'">' + linkify(x) + '</li>').join('') + '</ul>';
}

function renderCierre(c){
  let h = '<div class="cierre"><h3>Cierre de la investigacion ' +
          '<span class="conf">Certeza del dato: ' + esc(c.nivel_confianza) + '</span></h3>' +
          '<div class="notea">La certeza mide cuan solidos son los datos hallados, ' +
          'NO si el contacto es confiable.</div>';
  h += '<div class="col"><b>Podemos sostener</b>' + renderLista(c.podemos_sostener,'sost') + '</div>';
  h += '<div class="col"><b>Todavia no sabemos</b>' + renderLista(c.todavia_no_sabemos,'nose') + '</div>';
  h += '<div class="col"><b>Decision prudente</b><div class="deci">' + esc(c.decision_prudente) + '</div></div>';
  if (c.nota) h += '<div class="notea">' + esc(c.nota) + '</div>';
  return h + '</div>';
}

function renderSeccion(titulo, obj){
  const out = ['<div class="src">' + esc(titulo) + '</div>'];
  for (const [k,v] of Object.entries(obj||{})){
    out.push('<span class="k">' + esc(k) + ':</span> ' + renderVal(v));
  }
  return out.join('\\n');
}

function imprimir(){ window.print(); }

function descargarJSON(){
  if(!window.ultimoReporte) return;
  const r = window.ultimoReporte;
  const blob = new Blob([JSON.stringify(r,null,2)], {type:'application/json'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  const t = String(r.entrada||'reporte').replace(/[^a-zA-Z0-9]+/g,'_').slice(0,40);
  a.download = 'ARGos_'+t+'.json';
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(()=>URL.revokeObjectURL(a.href), 1000);
}

function render(rep){
  window.ultimoReporte = rep;
  const meta = document.getElementById('meta');
  meta.innerHTML = '<b>Entrada:</b> ' + esc(rep.entrada) +
                   ' &nbsp; <b>Tipo detectado:</b> ' + esc(rep.tipo_detectado);
  if (rep.ips_resueltas) meta.innerHTML += ' &nbsp; <b>IPs:</b> ' + esc(rep.ips_resueltas.join(', '));
  if (rep.fecha_consulta_utc){
    let f = rep.fecha_consulta_utc;
    try { f = new Date(rep.fecha_consulta_utc).toLocaleString(); } catch(e){}
    meta.innerHTML += '<div class="notea">Consulta realizada: ' + esc(f) + '</div>';
  }

  const out = [];
  if (rep.cierre_investigacion) out.push(renderCierre(rep.cierre_investigacion));

  (rep.resultados || []).forEach(r => {
    const estado = r.ok ? '<span class="ok">OK</span>' : '<span class="bad">sin datos</span>';
    out.push('<div class="src">' + esc(r.source) + ' — ' + estado + '</div>');
    if (r.ok && r.data){
      for (const [k,v] of Object.entries(r.data)){
        out.push('<span class="k">' + esc(k) + ':</span> ' + renderVal(v));
      }
    } else if (!r.ok){
      out.push('<span class="empty">' + esc(r.error||'') + '</span>');
    }
  });

  if (rep.google_dorks && Object.keys(rep.google_dorks).length)
    out.push(renderSeccion('Busquedas sugeridas en Google (dorks)', rep.google_dorks));
  if (rep.fuentes_oficiales && Object.keys(rep.fuentes_oficiales).length)
    out.push(renderSeccion('Fuentes oficiales', rep.fuentes_oficiales));
  if (rep.enlaces_verificacion && Object.keys(rep.enlaces_verificacion).length)
    out.push(renderSeccion('Enlaces de verificacion', rep.enlaces_verificacion));

  document.getElementById('res').innerHTML = out.join('\\n');
  document.getElementById('salida').style.display = 'block';
}

async function consultar(){
  const t = document.getElementById('target').value.trim();
  if(!t) return;
  const tipo = document.getElementById('tipo').value;
  const btn = document.getElementById('btn');
  btn.disabled = true; btn.textContent = 'Consultando...';
  document.getElementById('salida').style.display = 'block';
  document.getElementById('meta').textContent = '';
  document.getElementById('res').textContent = 'Buscando en las fuentes...';
  try{
    let url = '/osint?target=' + encodeURIComponent(t);
    if(tipo) url += '&tipo=' + encodeURIComponent(tipo);
    const rep = await (await fetch(url)).json();
    render(rep);
  }catch(e){
    document.getElementById('res').innerHTML = '<span class="bad">Error: ' + esc(e) + '</span>';
  }finally{
    btn.disabled = false; btn.textContent = 'Consultar';
  }
}
document.getElementById('target').addEventListener('keydown', e => { if(e.key==='Enter') consultar(); });
if('serviceWorker' in navigator){ navigator.serviceWorker.register('/sw.js').catch(()=>{}); }
</script>
</body>
</html>"""


ICON_PNG_B64 = "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x2vfn//xis/X7ti5p7Kq+uTJuoaGhoT4hPT01E6d0tPT0rKzM4uLCvsV9+nfr0//fkVOSMToRQAI69l/uOiiH8G6+6t2bT51/KjxEuZyuYrHTF+/8A2hvUdYj+KhU274YaeuYsPG608ck3giN7VzF4n5f45X74+68T8ZGekP33+X3LYtLS3LVpTO//B/K1etqz585OiRmvT0tK5dswcNKL7kohkXnDtVZ9IIHdd944q/vvjPNes26bwmOTk5v3cvgw22tbX96unnnn7mz41NvtMIut0tDY2Nh4/UeP7vosXLvP+U26vH5IljpkwaO3nimNxekjMJKosAENZPcPa36rJtQUe2tLXtWbN06MyvGW+teNy5jgqAuPiExOSUDilpnXv27pLXt3DERLk+mRVvPC/xBECa1NzRp44dltjKXrd/64bsrM4SG64qXf+T+5/cuGlr+x8erTl2tObYtu273np3QdcuWU88Mufaay4Xbdnlcs25+3vX3jRb5zV5vXoYnwvk1797/qm5fxA9jP2VVa/9693X/vWupmmFBXkXXTD96isvLhkxVLQdNREAYhKTUwrOEbsT63/79+x/XSIUAJk5uV0L+rUfURoZvfoPn/XHD8LU+Nr5r0rc/tU0LSlFbJipx6njRyW20jStW+GAK37yG7ltAwq2zpqPpMTE79x2nUT7L/3jzbt+8qj+LA6Hj9Tccef9y1eueebXj4pO3HTBuVP6FhXs2l0e7AVpaQIf0PMvmJ2Uqax837znX5r3/Ev5vXOvvvKir3/tYktmsIhh3AQW02fEZKGxmG2trXvW6JW2w3t3njh8QOgYouhWsBFfLP1Aejq2hESZ8TBN9TbMeGzGxRfOyOkmvNTwG299ELL6e730jzfvf/gXortwuVy33PB1nRckGL4P5Ha3HK05JnoAwVTs3f/0s3+ZMP1r/r1JaI8AECM6+/+BHRtOnzyu/xrRBwKKSqaI3l91pla3e9nr85a9Pk+6hYSkZImtWtxRVhSuuOx80U2qDx25574nhM5/n3vhlWUrxKao0jTtskv05oc43WD0rn5CQvywITKPdMAMAkBAenZOj6LBQpv4P//lL9gYoWA6pKbnDzE6Ctuxjuzd9d5v53yx1FS3UnyCzNTHLe5mMzuNsKTExPNnCs91+siTT584ITwT3z33imWGpmkF+bntVxTwceTL27ZG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"

MANIFEST_JSON = """{
  \"name\": \"ARGos - Inteligencia preventiva\",
  \"short_name\": \"ARGos\",
  \"start_url\": \"/\",
  \"scope\": \"/\",
  \"display\": \"standalone\",
  \"background_color\": \"#0f172a\",
  \"theme_color\": \"#0f172a\",
  \"icons\": [
    {\"src\": \"/icon.png\", \"sizes\": \"512x512\", \"type\": \"image/png\", \"purpose\": \"any\"},
    {\"src\": \"/icon.png\", \"sizes\": \"192x192\", \"type\": \"image/png\", \"purpose\": \"any\"}
  ]
}"""

SW_JS = ("self.addEventListener('install', e => self.skipWaiting());\n""self.addEventListener('activate', e => self.clients.claim());\n""self.addEventListener('fetch', e => { e.respondWith(fetch(e.request)); });\n")


class Handler(BaseHTTPRequestHandler):
    def _send(self, body: bytes, status=200, ctype="application/json; charset=utf-8"):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, status=200):
        self._send(json.dumps(obj, ensure_ascii=False, indent=2).encode("utf-8"), status)

    def _autorizado(self) -> bool:
        # Si no hay clave configurada, el acceso es libre (modo local).
        if not ARGOS_PASS:
            return True
        hdr = self.headers.get("Authorization", "")
        if hdr.startswith("Basic "):
            try:
                usuario, _, clave = base64.b64decode(hdr[6:]).decode("utf-8").partition(":")
                if usuario == ARGOS_USER and clave == ARGOS_PASS:
                    return True
            except Exception:
                pass
        return False

    def _usuario_actual(self) -> str:
        hdr = self.headers.get("Authorization", "")
        if hdr.startswith("Basic "):
            try:
                usuario, _, _ = base64.b64decode(hdr[6:]).decode("utf-8").partition(":")
                return usuario or "?"
            except Exception:
                pass
        return "(sin clave)"

    def _origen(self) -> str:
        # Detras del proxy de Render, la IP real viene en X-Forwarded-For.
        return (self.headers.get("X-Forwarded-For") or self.address_string()).split(",")[0].strip()

    def do_GET(self):
        if not self._autorizado():
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="ARGos"')
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            cuerpo = "Acceso restringido - ARGos. Ingresa usuario y clave.".encode("utf-8")
            self.send_header("Content-Length", str(len(cuerpo)))
            self.end_headers()
            self.wfile.write(cuerpo)
            return

        parsed = urllib.parse.urlparse(self.path)
        ruta = parsed.path

        if ruta in ("/", "/index.html"):
            self._send(PAGINA.encode("utf-8"), ctype="text/html; charset=utf-8")
            return

        if ruta == "/osint":
            qs = urllib.parse.parse_qs(parsed.query)
            target = (qs.get("target") or [""])[0].strip()
            tipo = (qs.get("tipo") or [None])[0]
            if not target:
                self._json({"error": "parametro 'target' vacio"}, 400)
                return
            if tipo and tipo not in TIPOS:
                self._json({"error": f"tipo invalido; use uno de {TIPOS}"}, 400)
                return
            try:
                reporte = asyncio.run(collectors.investigate(target, forzar_tipo=tipo))
                registrar_auditoria(self._usuario_actual(),
                                    reporte.get("tipo_detectado", tipo), target, self._origen())
                self._json(reporte)
            except Exception as e:
                self._json({"error": f"fallo la consulta: {e}"}, 500)
            return

        if ruta == "/logs":
            self._send(self._pagina_logs().encode("utf-8"), ctype="text/html; charset=utf-8")
            return

        if ruta in ("/icon.png", "/icon-192.png", "/icon-512.png"):
            self._send(base64.b64decode(ICON_PNG_B64), ctype="image/png")
            return
        if ruta == "/manifest.json":
            self._send(MANIFEST_JSON.encode("utf-8"), ctype="application/manifest+json; charset=utf-8")
            return
        if ruta == "/sw.js":
            self._send(SW_JS.encode("utf-8"), ctype="application/javascript; charset=utf-8")
            return

        self._json({"error": "ruta no encontrada"}, 404)

    def _pagina_logs(self) -> str:
        with _db_lock:
            filas = _db.execute(
                "SELECT fecha_utc, usuario, tipo, dato, origen FROM auditoria "
                "ORDER BY id DESC LIMIT 500").fetchall()
        import html as _html
        tr = "".join(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
                *(_html.escape(str(c)) for c in f)) for f in filas)
        return f"""<!doctype html><html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ARGos - Auditoria</title><style>
body{{font-family:system-ui,Segoe UI,Arial,sans-serif;background:#0f172a;color:#e2e8f0;margin:0;padding:24px}}
a{{color:#38bdf8}} h1{{font-size:20px}} .sub{{color:#94a3b8;font-size:13px}}
table{{width:100%;border-collapse:collapse;margin-top:14px;font-size:13px}}
th,td{{border:1px solid #334155;padding:6px 8px;text-align:left;vertical-align:top}}
th{{background:#1e293b}} tr:nth-child(even){{background:#0b1220}}
</style></head><body>
<h1>ARGos — Registro de auditoría</h1>
<p class="sub">Últimas 500 consultas (fecha en UTC). <a href="/">← Volver a ARGos</a></p>
<table><tr><th>Fecha (UTC)</th><th>Usuario</th><th>Tipo</th><th>Dato consultado</th><th>Origen</th></tr>
{tr or '<tr><td colspan="5">Sin registros todavía.</td></tr>'}</table>
<p class="sub" style="margin-top:14px">Acceso restringido. Uso para rendición de cuentas; respeta la privacidad de los datos registrados.</p>
</body></html>"""

    def log_message(self, fmt, *args):
        # Log compacto en la consola
        print("  >", self.address_string(), fmt % args)


def main():
    servidor = ThreadingHTTPServer((HOST, PORT), Handler)
    local = "127.0.0.1" if HOST == "0.0.0.0" else HOST
    print("=" * 52)
    print("  Servidor ARGos corriendo.")
    print(f"  Abri en el navegador:  http://{local}:{PORT}/")
    if ARGOS_PASS:
        print(f"  Acceso con clave: usuario '{ARGOS_USER}'.")
    else:
        print("  [AVISO] Sin clave de acceso (abierto). Para publicarlo,")
        print("          configura ARGOS_USER y ARGOS_PASS.")
    print("  Para frenarlo: Ctrl + C (o cerra esta ventana)")
    print("=" * 52)
    try:
        servidor.serve_forever()
    except KeyboardInterrupt:
        print("\nServidor detenido.")
        servidor.server_close()


if __name__ == "__main__":
    main()
