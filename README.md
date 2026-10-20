# OSINT Aggregator

API en FastAPI que recibe **un dato** (IP, dominio, email o nombre de usuario),
detecta de qué tipo es y consulta en paralelo **fuentes públicas gratuitas y sin registro**,
devolviendo un reporte JSON unificado.

Pensada para *footprinting* de infraestructura y verificación en contexto de
seguridad defensiva (pentesting, threat intel, due diligence técnica).

## Instalación y uso

```bash
pip install -r requirements.txt
uvicorn main:app --reload
```

Consultas:

```
GET http://127.0.0.1:8000/osint?target=github.com
GET http://127.0.0.1:8000/osint?target=8.8.8.8
GET http://127.0.0.1:8000/osint?target=alguien@dominio.com
GET http://127.0.0.1:8000/osint?target=unusuario
GET http://127.0.0.1:8000/osint?target=%2B5493415123456        # telefono (usar %2B por el +)
```

Si la detección automática se equivoca, forzá el tipo:
`...&tipo=phone` (valores: ip, domain, email, username, phone).

Documentación interactiva (Swagger): `http://127.0.0.1:8000/docs`

## Qué consulta según el tipo de dato

| Tipo      | Fuentes                                                        | Devuelve |
|-----------|----------------------------------------------------------------|----------|
| IP        | ipwho.is / ip-api.com, RDAP (rdap.org), reverse DNS            | Geolocalización, ISP, ASN, red asignada, flags proxy/hosting, hostname |
| Dominio   | RDAP, DNS (A/AAAA/MX/NS/TXT/SOA/CNAME), crt.sh, geo de la IP   | Registrar, fechas, nameservers, registros DNS, subdominios, geo |
| Email     | Sintaxis + MX del dominio, RDAP del dominio                    | Validez, entregabilidad probable, datos del dominio |
| Usuario   | Presencia HTTP en plataformas públicas                        | En qué sitios existe ese username |
| Teléfono  | phonenumbers (offline, plan de numeración público)            | País, región geográfica, compañía asignada, tipo de línea, validez |

Todas las fuentes son **sin API key ni registro**. Si una está caída o cambia de
formato, el reporte se entrega igual con el resto (degradación controlada: cada
fuente devuelve `ok: true/false`).

## Límites honestos de "sin registro"

Sin cuentas, hay un techo real. Lo que **no** se puede cubrir gratis y sin registro,
y por qué:

- **Brechas de credenciales** (tipo HaveIBeenPwned): hoy requieren API key. Es la
  pieza más valiosa para un email, pero no es gratuita/anónima.
- **Shodan / Censys** (puertos y servicios expuestos de una IP): su API necesita cuenta.
- **Geolocalización por HTTPS sin límites**: los tiers gratis tienen rate limits
  (ip-api ~45 req/min; ipwho.is también limita). Para volumen, hace falta key.
- **crt.sh** puede tardar o limitar; por eso tiene timeout propio.

Para dar el salto de capacidad, el diseño ya está modularizado: cada fuente es una
función aislada en `collectors.py`, así que sumar una que use key (Shodan, HIBP,
VirusTotal) es agregar una función más sin tocar el resto.

## Estructura

```
osint_api/
├── main.py           # API FastAPI (endpoint /osint)
├── collectors.py     # detección de tipo + colectores por fuente + orquestador
├── requirements.txt
└── README.md
```

## Teléfono: qué da y qué no (importante)

El módulo offline te da país, **región geográfica** (provincia/localidad para AR,
ej. "Rosario, Santa Fe"), **compañía** y tipo de línea. Dos precisiones para no
sacar conclusiones erradas:

- La región y la compañía salen de **cómo se asignó el número** (prefijo / código
  de área), no de dónde está la persona. Son el lugar y el operador de *registro*.
- Por **portabilidad numérica**, la compañía puede ser la original del prefijo y no
  la actual. El operador real de hoy se consulta en la base de portabilidad (en AR,
  vía ENACOM), que no es anónima.
- La ubicación **en tiempo real** ("desde dónde se comunica") **no es OSINT**: eso
  solo lo da el operador por vía legal. Ninguna fuente abierta lo entrega.

## Redes sociales y vínculos entre personas

- **"¿Tiene redes sociales?"** → lo cubre el módulo de usuario: le pasás un *handle*
  y te dice en qué plataformas públicas existe esa cuenta. Es verificación de
  existencia de un alias, sin registro.
- **Correlacionar un email/teléfono con las cuentas reales de una persona y mapear
  "con quiénes se vincula"** (su red de contactos/allegados) **queda fuera de esta
  herramienta a propósito.** Ahí se deja de hacer OSINT de infraestructura y se pasa
  a armar un **perfil de una persona física concreta y su círculo**. Es la línea que
  separa la inteligencia legítima del *profiling*/doxxing, y en tu contexto toca de
  lleno la **Ley 25.326 de Protección de Datos Personales** (tratamiento de datos de
  terceros sin base legal). Para una institución regulada como un banco central, ese
  tipo de investigación se canaliza por el circuito formal (requerimiento, orden
  judicial, convenios interagenciales), no por una herramienta propia.

El enfoque preventivo que sí rinde y es defendible: **verificación y triage** de un
identificador que llega (¿el teléfono es válido, de qué operador/región?, ¿el
dominio del mail es legítimo o recién creado?, ¿la IP es de hosting/proxy?), no la
reconstrucción de la vida de una persona.

## Uso responsable

Herramienta de doble uso. Orientada a infraestructura y verificación en seguridad
defensiva. No usar para perfilar personas físicas concretas (domicilio, lugar de
trabajo, hábitos): esa línea separa el OSINT legítimo del acoso/doxxing, y además
puede tener consecuencias legales (en Argentina, Ley 25.326 de Protección de Datos
Personales, entre otras).
