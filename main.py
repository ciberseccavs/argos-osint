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
import urllib.parse
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

TIPOS = ["ip", "domain", "email", "username", "phone"]

PAGINA = """<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
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
  .cierre { background:#172033; border:1px solid #334155; border-radius:10px; padding:14px; margin:6px 0 16px; }
  .cierre h3 { margin:0 0 8px; font-size:15px; }
  .col { margin:8px 0; }
  .col b { color:#cbd5e1; font-size:13px; }
  .col ul { margin:4px 0 0; padding-left:18px; }
  .col li { font-size:13px; line-height:1.5; margin:2px 0; }
  .sost { color:#cbd5e1; } .nose { color:#fbbf24; } .deci { color:#e2e8f0; }
  .conf { display:inline-block; padding:2px 10px; border-radius:999px; font-size:12px; font-weight:700; }
  .conf-Alto { background:#14532d; color:#86efac; }
  .conf-Medio { background:#78350f; color:#fcd34d; }
  .conf-Bajo { background:#3f1d1d; color:#fca5a5; }
  .notea { font-size:12px; color:#94a3b8; font-style:italic; margin-top:8px; }
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
  <p class="sub">Inteligencia preventiva de fuentes abiertas — publicas, gratuitas y sin registro.</p>

  <div class="card">
    <div class="row">
      <div>
        <label>Dato a consultar</label>
        <input id="target" placeholder="ej: google.com  /  8.8.8.8  /  +5491150501234"
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
        </select>
      </div>
    </div>
    <button id="btn" onclick="consultar()">Consultar</button>
    <p class="hint">Para telefonos usa formato internacional con +codigo de pais
       (ej: +5491150501234). La consulta puede tardar unos segundos.</p>
  </div>

  <div class="card" id="salida" style="display:none">
    <div id="meta"></div>
    <div class="res" id="res"></div>
  </div>
</div>

<script>
function esc(s){ return String(s).replace(/[&<>]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;'}[c])); }

function linkify(s){
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
          '<span class="conf conf-' + esc(c.nivel_confianza) + '">Confianza: ' +
          esc(c.nivel_confianza) + '</span></h3>';
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

function render(rep){
  const meta = document.getElementById('meta');
  meta.innerHTML = '<b>Entrada:</b> ' + esc(rep.entrada) +
                   ' &nbsp; <b>Tipo detectado:</b> ' + esc(rep.tipo_detectado);
  if (rep.ips_resueltas) meta.innerHTML += ' &nbsp; <b>IPs:</b> ' + esc(rep.ips_resueltas.join(', '));

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
</script>
</body>
</html>"""


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
                self._json(reporte)
            except Exception as e:
                self._json({"error": f"fallo la consulta: {e}"}, 500)
            return

        self._json({"error": "ruta no encontrada"}, 404)

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
