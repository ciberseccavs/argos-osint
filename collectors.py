"""
Colectores OSINT sobre fuentes publicas, gratuitas y sin registro.

Cada colector es asincrono, se envuelve en su propio try/except y devuelve
un dict con la forma {"source": ..., "ok": bool, "data"/"error": ...}.
De esa manera, si una fuente esta caida o cambia su formato, el resto del
reporte se entrega igual (degradacion controlada).

Fuentes usadas (todas sin API key ni registro):
  - ip-api.com        -> geolocalizacion, ISP, ASN, flags (proxy/hosting)
  - rdap.org          -> RDAP (reemplazo moderno de WHOIS) para IP y dominio
  - crt.sh            -> Certificate Transparency -> subdominios
  - DNS (dnspython)   -> registros A/AAAA/MX/NS/TXT/SOA/CNAME
  - Resolucion local  -> reverse DNS, resolucion de dominio a IP
  - HTTP directo      -> presencia de un usuario en plataformas publicas
"""

import asyncio
import hashlib
import re
import socket
import urllib.parse
from datetime import datetime, timezone
from typing import Any

import httpx
import dns.asyncresolver
import dns.resolver
import phonenumbers
from phonenumbers import geocoder, carrier, number_type, PhoneNumberType

# Timeout corto por request; preferimos un reporte parcial rapido a uno completo lento.
HTTP_TIMEOUT = httpx.Timeout(8.0, connect=5.0)
USER_AGENT = "osint-aggregator/1.0 (+uso educativo/defensivo)"

DNS_RECORDS = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]

# Dominios de correo descartable/temporal mas comunes (bandera de fraude).
# Lista parcial pero representativa; es facil de ampliar.
DISPOSABLE_DOMAINS = {
    "mailinator.com", "guerrillamail.com", "guerrillamail.info", "10minutemail.com",
    "tempmail.com", "temp-mail.org", "tempmailo.com", "throwawaymail.com",
    "yopmail.com", "trashmail.com", "getnada.com", "nada.email", "sharklasers.com",
    "mohmal.com", "maildrop.cc", "dispostable.com", "fakeinbox.com", "mailnesia.com",
    "mintemail.com", "mytemp.email", "emailondeck.com", "spamgourmet.com",
    "tutanota.com", "burnermail.io", "33mail.com", "tempmail.plus", "inboxkitten.com",
    "mail-temp.com", "moakt.com", "luxusmail.org", "tempr.email", "discard.email",
    "grr.la", "spam4.me", "mailcatch.com", "tmpmail.net", "tmpmail.org",
}

# Localparts "de rol" (no personales): baja confianza para un contacto individual.
ROLE_LOCALPARTS = {
    "info", "admin", "administrator", "contacto", "contact", "soporte", "support",
    "ventas", "sales", "ayuda", "help", "noreply", "no-reply", "nonreply",
    "postmaster", "webmaster", "hostmaster", "abuse", "root", "mail", "office",
    "hola", "hello", "team", "equipo", "atencion", "cobranzas", "facturacion",
}

# Region por defecto cuando el numero no viene en formato internacional (+..).
DEFAULT_PHONE_REGION = "AR"

_PHONE_TYPES = {
    PhoneNumberType.MOBILE: "movil",
    PhoneNumberType.FIXED_LINE: "fijo",
    PhoneNumberType.FIXED_LINE_OR_MOBILE: "fijo o movil",
    PhoneNumberType.VOIP: "VoIP",
    PhoneNumberType.TOLL_FREE: "gratuito (0800)",
    PhoneNumberType.PREMIUM_RATE: "tarifa premium",
    PhoneNumberType.SHARED_COST: "costo compartido",
    PhoneNumberType.PERSONAL_NUMBER: "numero personal",
    PhoneNumberType.PAGER: "pager",
    PhoneNumberType.UAN: "UAN",
    PhoneNumberType.VOICEMAIL: "casilla de voz",
    PhoneNumberType.UNKNOWN: "desconocido",
}

_PHONE_CLEAN = re.compile(r"[\s\-().]")

# Plataformas con deteccion confiable por codigo de estado 404.
# name: (url_template, metodo). Metodo "status" => existe si no es 404.
USERNAME_SITES = {
    "GitHub":        "https://github.com/{u}",
    "Reddit":        "https://www.reddit.com/user/{u}/about.json",
    "GitLab":        "https://gitlab.com/{u}",
    "Twitter/X":     "https://nitter.net/{u}",        # frontend publico; puede variar
    "Instagram":     "https://www.instagram.com/{u}/",
    "TikTok":        "https://www.tiktok.com/@{u}",
    "Telegram":      "https://t.me/{u}",
    "Pinterest":     "https://www.pinterest.com/{u}/",
    "Keybase":       "https://keybase.io/{u}",
    "HackerNews":    "https://news.ycombinator.com/user?id={u}",
    "Dev.to":        "https://dev.to/{u}",
    "Medium":        "https://medium.com/@{u}",
}


# --------------------------------------------------------------------------- #
# Deteccion de tipo de dato
# --------------------------------------------------------------------------- #
def _looks_phone(value: str) -> bool:
    s = _PHONE_CLEAN.sub("", value)
    if s.startswith("+"):
        s = s[1:]
    return s.isdigit() and 7 <= len(s) <= 15


def detect_type(value: str) -> str:
    value = value.strip()
    # IPv4 / IPv6
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(family, value)
            return "ip"
        except OSError:
            pass
    # CBU / CVU: 22 digitos (puede venir con espacios/guiones)
    _solo_dig = re.sub(r"[\s\-.]", "", value)
    if _solo_dig.isdigit() and len(_solo_dig) == 22:
        return "cbu"
    if "@" in value and re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", value):
        return "email"
    # Link / URL completa (con esquema http(s):// o con ruta tras el dominio)
    if re.match(r"^https?://", value, re.I) or re.match(r"^[^\s/]+\.[^\s/]+/\S", value):
        return "url"
    # Telefono antes que dominio/usuario (numeros con + o 7-15 digitos)
    if _looks_phone(value):
        return "phone"
    # Dominio: tiene un punto, sin espacios y TLD alfabetico
    if re.match(r"^(?!-)[A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{1,63})+$", value):
        return "domain"
    # Persona: dos o mas palabras alfabeticas (nombre y apellido)
    if re.match(r"^[A-Za-zÀ-ÿ'’.\-]+(?:\s+[A-Za-zÀ-ÿ'’.\-]+)+$", value):
        return "person"
    return "username"


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
async def _get_json(client: httpx.AsyncClient, url: str) -> Any:
    # follow_redirects: RDAP global (rdap.org) redirige al servidor de cada TLD;
    # para dominios .ar eso salta a rdap.nic.ar. Seguimos el salto automaticamente.
    r = await client.get(url, headers={"User-Agent": USER_AGENT}, follow_redirects=True)
    r.raise_for_status()
    return r.json()


def _resolve_sync(domain: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(domain, None)
        return sorted({i[4][0] for i in infos})
    except Exception:
        return []


# --------------------------------------------------------------------------- #
# Colectores de IP
# --------------------------------------------------------------------------- #
async def _geo_ipwhois(client: httpx.AsyncClient, ip: str) -> dict:
    """ipwho.is: HTTPS, gratis y sin registro. Preferida en redes que bloquean HTTP."""
    data = await _get_json(client, f"https://ipwho.is/{ip}")
    if not data.get("success", False):
        raise RuntimeError(data.get("message", "ipwho.is sin exito"))
    conn = data.get("connection", {})
    return {
        "query": data.get("ip"), "country": data.get("country"),
        "countryCode": data.get("country_code"), "regionName": data.get("region"),
        "city": data.get("city"), "zip": data.get("postal"),
        "lat": data.get("latitude"), "lon": data.get("longitude"),
        "timezone": (data.get("timezone") or {}).get("id"),
        "isp": conn.get("isp"), "org": conn.get("org"),
        "as": f"AS{conn.get('asn')}" if conn.get("asn") else None,
        "asname": conn.get("domain"),
    }


async def _geo_ipapi(client: httpx.AsyncClient, ip: str) -> dict:
    """ip-api.com: gratis sin registro pero SOLO HTTP (https es de pago)."""
    fields = ("status,message,country,countryCode,regionName,city,zip,lat,lon,"
              "timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query")
    data = await _get_json(client, f"http://ip-api.com/json/{ip}?fields={fields}")
    if data.get("status") != "success":
        raise RuntimeError(data.get("message", "fallo"))
    return data


async def ip_geolocation(client: httpx.AsyncClient, ip: str) -> dict:
    # Cadena de respaldo: HTTPS primero, HTTP despues.
    for nombre, fn in (("ipwho.is", _geo_ipwhois), ("ip-api.com", _geo_ipapi)):
        try:
            return {"source": nombre, "ok": True, "data": await fn(client, ip)}
        except Exception as e:
            ultimo_error = f"{nombre}: {e}"
    return {"source": "geolocalizacion IP", "ok": False, "error": ultimo_error}


async def rdap_ip(client: httpx.AsyncClient, ip: str) -> dict:
    try:
        data = await _get_json(client, f"https://rdap.org/ip/{ip}")
        resumen = {
            "handle": data.get("handle"),
            "name": data.get("name"),
            "type": data.get("type"),
            "country": data.get("country"),
            "cidr": [c.get("v4prefix") or c.get("v6prefix") for c in data.get("cidr0_cidrs", [])],
            "entidades": [e.get("handle") for e in data.get("entities", [])],
        }
        return {"source": "rdap.org (IP)", "ok": True, "data": resumen}
    except Exception as e:
        return {"source": "rdap.org (IP)", "ok": False, "error": str(e)}


async def reverse_dns(ip: str) -> dict:
    try:
        host = await asyncio.to_thread(socket.gethostbyaddr, ip)
        return {"source": "reverse DNS", "ok": True, "data": {"hostname": host[0], "aliases": host[1]}}
    except Exception as e:
        return {"source": "reverse DNS", "ok": False, "error": str(e)}


# --------------------------------------------------------------------------- #
# Colectores de dominio
# --------------------------------------------------------------------------- #
async def rdap_domain(client: httpx.AsyncClient, domain: str) -> dict:
    try:
        data = await _get_json(client, f"https://rdap.org/domain/{domain}")
        eventos = {ev.get("eventAction"): ev.get("eventDate") for ev in data.get("events", [])}
        ns = [n.get("ldhName") for n in data.get("nameservers", [])]
        registrar = None
        for ent in data.get("entities", []):
            if "registrar" in ent.get("roles", []):
                for item in ent.get("vcardArray", [[], []])[1]:
                    if item[0] == "fn":
                        registrar = item[3]
        resumen = {
            "registrar": registrar,
            "estado": data.get("status"),
            "creado": eventos.get("registration"),
            "expira": eventos.get("expiration"),
            "actualizado": eventos.get("last changed") or eventos.get("last update of RDAP database"),
            "nameservers": ns,
        }
        return {"source": "rdap.org (dominio)", "ok": True, "data": resumen}
    except Exception as e:
        # Los dominios .ar (NIC Argentina) no publican titular/fechas de forma
        # abierta: exigen cuenta e inicio de sesion en nic.ar. No hay fuente
        # gratuita y sin registro que entregue ese dato para .ar.
        if domain.lower().endswith(".ar"):
            return {"source": "rdap.org (dominio)", "ok": False,
                    "error": ("Dominio .ar: NIC Argentina no publica titular ni "
                              "fechas sin cuenta (requiere login en nic.ar). "
                              "El resto de los datos -DNS, correo, IP- si se "
                              "obtienen. Para TLDs globales (.com/.net/.org) este "
                              "campo si trae registrador y fechas.")}
        return {"source": "rdap.org (dominio)", "ok": False, "error": str(e)}


async def dns_records(domain: str) -> dict:
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = 6.0
    out: dict[str, list[str]] = {}
    for rtype in DNS_RECORDS:
        try:
            ans = await resolver.resolve(domain, rtype)
            out[rtype] = [r.to_text() for r in ans]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            continue
        except Exception:
            continue
    if out:
        return {"source": "DNS", "ok": True, "data": out}
    return {"source": "DNS", "ok": False, "error": "sin registros resolubles"}


async def crtsh_subdomains(client: httpx.AsyncClient, domain: str) -> dict:
    # crt.sh suele dar 502/503 o timeouts: reintentamos un par de veces.
    ultimo_error = "sin respuesta"
    for intento in range(3):
        try:
            r = await client.get(f"https://crt.sh/?q=%25.{domain}&output=json",
                                 headers={"User-Agent": USER_AGENT}, timeout=httpx.Timeout(25.0))
            r.raise_for_status()
            subs = set()
            for row in r.json():
                for name in str(row.get("name_value", "")).splitlines():
                    name = name.strip().lstrip("*.").lower()
                    if name.endswith(domain):
                        subs.add(name)
            subs.discard(domain)
            return {"source": "crt.sh", "ok": True,
                    "data": {"total": len(subs), "subdominios": sorted(subs)[:200]}}
        except Exception as e:
            ultimo_error = str(e)
            if intento < 2:
                await asyncio.sleep(2)
    return {"source": "crt.sh", "ok": False,
            "error": f"{ultimo_error} (crt.sh suele caerse; reintentar mas tarde)"}


# --------------------------------------------------------------------------- #
# Colectores de email
# --------------------------------------------------------------------------- #
async def gravatar_lookup(client: httpx.AsyncClient, email: str) -> dict:
    """
    Gravatar es el UNICO lugar abierto y sin registro donde un email puede
    vincularse a perfiles sociales: devuelve SOLO lo que el propio dueño del
    email eligio publicar (nombre, foto, cuentas que linkeo). Respeta el
    consentimiento: si no armó un perfil publico, no devuelve nada.
    """
    h = hashlib.md5(email.strip().lower().encode("utf-8")).hexdigest()
    try:
        data = await _get_json(client, f"https://www.gravatar.com/{h}.json")
        entry = (data.get("entry") or [{}])[0]
        cuentas = [{"red": a.get("shortname") or a.get("name"), "url": a.get("url")}
                   for a in entry.get("accounts", [])]
        perfil = {
            "existe_perfil_publico": True,
            "nombre_mostrado": entry.get("displayName"),
            "ubicacion_declarada": entry.get("currentLocation") or None,
            "perfil_url": entry.get("profileUrl"),
            "cuentas_vinculadas_publicas": cuentas or "ninguna cuenta publica declarada",
        }
        return {"source": "Gravatar (perfil publico del email)", "ok": True, "data": perfil}
    except Exception:
        return {"source": "Gravatar (perfil publico del email)", "ok": False,
                "error": ("Sin perfil publico de Gravatar para este email (lo normal "
                          "en la mayoria). No implica nada por si solo.")}


async def email_profile(client: httpx.AsyncClient, email: str) -> list[dict]:
    local, _, domain = email.partition("@")
    domain_l = domain.lower()
    resultados = []

    sintaxis_ok = bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email))
    mx = await dns_records(domain)
    tiene_mx = mx["ok"] and "MX" in mx.get("data", {})
    descartable = domain_l in DISPOSABLE_DOMAINS
    es_rol = local.lower() in ROLE_LOCALPARTS

    # Antiguedad del dominio (via RDAP). Un dominio recien creado es señal de fraude.
    rd = await rdap_domain(client, domain)
    creado = rd.get("data", {}).get("creado") if rd.get("ok") else None

    # Lectura de riesgo orientada a prevencion de estafas.
    señales = []
    if not sintaxis_ok:
        señales.append("Sintaxis invalida: el email esta mal formado.")
    if not tiene_mx:
        señales.append("El dominio NO puede recibir correo (sin registros MX): "
                       "el email probablemente es falso o no operativo.")
    if descartable:
        señales.append("Dominio de correo DESCARTABLE/temporal: altisimo riesgo de "
                       "fraude o cuenta de un solo uso.")
    if es_rol:
        señales.append("Direccion generica/de rol (no personal), ej. info@, soporte@.")
    if not señales:
        señales.append("Sin señales automaticas de riesgo en el email/dominio.")

    resultados.append({
        "source": "email (señales de riesgo)", "ok": True,
        "data": {
            "sintaxis_valida": sintaxis_ok,
            "dominio": domain,
            "puede_recibir_correo": tiene_mx,
            "servidores_mx": mx.get("data", {}).get("MX", []),
            "dominio_descartable": descartable,
            "direccion_de_rol": es_rol,
            "dominio_creado": creado or "desconocido (ver nota RDAP)",
            "señales_riesgo": señales,
        },
    })

    # Gravatar: vinculo consentido email -> perfiles sociales publicos.
    resultados.append(await gravatar_lookup(client, email))

    # Enriquecimiento del dominio (RDAP + fechas), reutilizando la consulta ya hecha.
    resultados.append(rd)
    return resultados


# --------------------------------------------------------------------------- #
# Colectores de usuario
# --------------------------------------------------------------------------- #
async def _check_site(client: httpx.AsyncClient, name: str, url_tpl: str, username: str) -> dict:
    url = url_tpl.format(u=username)
    try:
        r = await client.get(url, headers={"User-Agent": USER_AGENT},
                             follow_redirects=True, timeout=httpx.Timeout(7.0))
        existe = r.status_code not in (404, 410)
        return {"plataforma": name, "existe": existe, "status": r.status_code, "url": url}
    except Exception:
        return {"plataforma": name, "existe": None, "status": "error", "url": url}


async def username_presence(client: httpx.AsyncClient, username: str) -> dict:
    tareas = [_check_site(client, n, t, username) for n, t in USERNAME_SITES.items()]
    checks = await asyncio.gather(*tareas)
    encontrados = [c for c in checks if c["existe"] is True]
    return {
        "source": "presencia de usuario",
        "ok": True,
        "data": {
            "nota": "Deteccion heuristica por codigo HTTP; puede dar falsos positivos/negativos.",
            "encontrados": encontrados,
            "todos": checks,
        },
    }


# --------------------------------------------------------------------------- #
# Colector de telefono (offline, metadata del plan de numeracion publico)
# --------------------------------------------------------------------------- #
def phone_info(value: str, default_region: str = DEFAULT_PHONE_REGION) -> dict:
    """
    Usa la libreria phonenumbers (datos del plan de numeracion, incluida offline).
    Devuelve pais, region geografica, compania y tipo de linea.

    IMPORTANTE sobre los limites de esta data:
    - 'region_geografica' y 'compania' derivan de como se ASIGNO el numero
      (prefijo / codigo de area), NO de donde esta la persona ahora.
    - Por portabilidad numerica, la 'compania' puede ser la ORIGINAL del prefijo
      y no la actual. Para el operador real al dia de hoy hace falta una consulta
      a la base de portabilidad (en AR, la del ENACOM), que no es anonima.
    - La ubicacion en tiempo real ("desde donde se comunica") NO es dato de
      fuente abierta: requiere al operador por via legal.
    """
    try:
        region = None if value.strip().startswith("+") else default_region
        num = phonenumbers.parse(value, region)
    except phonenumbers.NumberParseException as e:
        return {"source": "phonenumbers", "ok": False, "error": str(e)}

    valido = phonenumbers.is_valid_number(num)
    tipo = number_type(num)
    e164 = phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.E164)
    data = {
        "valido": valido,
        "posible": phonenumbers.is_possible_number(num),
        "e164": e164,
        "formato_internacional": phonenumbers.format_number(
            num, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
        "codigo_pais": f"+{num.country_code}",
        "pais": phonenumbers.region_code_for_number(num),
        "region_geografica": geocoder.description_for_number(num, "es") or None,
        "compania_asignada": carrier.name_for_number(num, "es") or None,
        "tipo_linea": _PHONE_TYPES.get(tipo, "desconocido"),
    }

    # Ambiguedad argentina: los celulares llevan un 9 tras el +54 (+54 9 11 ...).
    # Sin ese 9, un celular coincide con el formato de linea fija y se clasifica mal.
    if (phonenumbers.region_code_for_number(num) == "AR"
            and tipo in (PhoneNumberType.FIXED_LINE, PhoneNumberType.FIXED_LINE_OR_MOBILE)):
        nsn = str(num.national_number)
        if not nsn.startswith("9"):
            try:
                alt = phonenumbers.parse("+549" + nsn, None)
                if phonenumbers.is_valid_number(alt) and number_type(alt) == PhoneNumberType.MOBILE:
                    data["tipo_linea"] = "fijo o movil (ambiguo: falta el 9 del celular)"
                    data["interpretacion_si_es_celular"] = {
                        "e164": phonenumbers.format_number(alt, phonenumbers.PhoneNumberFormat.E164),
                        "formato_internacional": phonenumbers.format_number(
                            alt, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
                        "tipo_linea": "movil",
                        "compania_asignada": carrier.name_for_number(alt, "es") or None,
                        "region_geografica": geocoder.description_for_number(alt, "es") or None,
                    }
                    data["nota_argentina"] = (
                        "En Argentina los celulares se escriben con un 9 despues del +54 "
                        "(ej. +54 9 11 ...). Sin ese 9 el numero coincide con una linea fija. "
                        "Si es un celular, vale la lectura de 'interpretacion_si_es_celular'. "
                        "Para evitar la ambiguedad, consulta el numero con +549.")
            except phonenumbers.NumberParseException:
                pass

    # Lectura de riesgo orientada a prevencion de estafas.
    riesgo = []
    if not valido:
        riesgo.append("Numero NO valido en el plan de numeracion: puede estar "
                      "falseado/spoofeado (muy comun en estafas).")
    if tipo == PhoneNumberType.VOIP:
        riesgo.append("Linea VoIP (telefonia por internet): tipica de numeros "
                      "desechables usados en fraudes. Desconfiar.")
    if tipo in (PhoneNumberType.PREMIUM_RATE, PhoneNumberType.SHARED_COST):
        riesgo.append("Tarifa premium / costo compartido: NO devolver la llamada "
                      "(te pueden cobrar). Bandera roja.")
    if not riesgo:
        riesgo.append("Sin señales automaticas de riesgo. Igual verifica los "
                      "reportes comunitarios antes de confiar.")
    data["señales_riesgo"] = riesgo

    # Links a reportes comunitarios GRATIS y SIN REGISTRO (se leen sin cuenta).
    # Se evitan a proposito Truecaller / Sync.me / Whitepages (piden registro o pago).
    nums = e164.lstrip("+")                 # internacional sin +, ej: 541137798847
    nsn = str(num.national_number)          # numero nacional, ej: 1137798847
    # Google filtrando los sitios con muro de registro/pago:
    excluir = "+-site:truecaller.com+-site:sync.me+-site:whitepages.com+-site:spokeo.com"
    data["consultas_comunitarias"] = {
        "Tellows (reportes, gratis y sin registro)":
            f"https://www.tellows.com/num/{nums}",
        "ListaSpam (gratis, sin registro)":
            f"https://www.listaspam.com/busca.php?Telefono={nums}",
        "Google - foros y denuncias (sin paginas que cobran)":
            f'https://www.google.com/search?q=%22{nsn}%22+OR+%22{e164}%22+'
            f'(estafa+OR+spam+OR+denuncia+OR+%22qui%C3%A9n+llama%22){excluir}',
    }
    return {"source": "phonenumbers (offline)", "ok": True, "data": data}


# --------------------------------------------------------------------------- #
# Validador de CBU / CVU (offline) + identificacion de la entidad
# --------------------------------------------------------------------------- #
# Codigos de entidad del BCRA (referencial; confirmar en la nomina oficial).
BANCOS = {
    "007": "Banco de Galicia y Buenos Aires", "011": "Banco de la Nacion Argentina",
    "014": "Banco de la Provincia de Buenos Aires",
    "015": "ICBC (Industrial and Commercial Bank of China)", "016": "Citibank N.A.",
    "017": "BBVA Argentina", "018": "MUFG Bank",
    "020": "Banco de la Provincia de Cordoba", "027": "Banco Supervielle",
    "029": "Banco de la Ciudad de Buenos Aires", "034": "Banco Patagonia",
    "044": "Banco Hipotecario", "045": "Banco de San Juan",
    "060": "Banco del Tucuman", "065": "Banco Municipal de Rosario",
    "072": "Banco Santander Argentina", "083": "Banco del Chubut",
    "086": "Banco de Santa Cruz", "093": "Banco de La Pampa",
    "094": "Banco de Corrientes", "097": "Banco Provincia del Neuquen",
    "143": "Brubank", "147": "Banco Interfinanzas", "150": "HSBC Bank Argentina",
    "165": "JP Morgan Chase Bank", "191": "Banco Credicoop",
    "198": "Banco de Valores", "247": "Banco Roela", "254": "Banco Mariva",
    "259": "Banco Itau Argentina", "262": "Bank of America", "266": "BNP Paribas",
    "268": "Banco Provincia de Tierra del Fuego",
    "269": "Banco de la Republica Oriental del Uruguay", "277": "Banco Saenz",
    "281": "Banco Meridian", "285": "Banco Macro", "299": "Banco Comafi",
    "300": "BICE (Banco de Inversion y Comercio Exterior)", "301": "Banco Piano",
    "305": "Banco Julio", "309": "Banco Rioja", "310": "Banco del Sol",
    "311": "Nuevo Banco del Chaco", "312": "Banco Voii", "315": "Banco de Formosa",
    "319": "Banco CMF", "321": "Banco de Santiago del Estero",
    "322": "Banco Industrial (BIND)", "330": "Nuevo Banco de Santa Fe",
    "331": "Banco Cetelem Argentina", "332": "Banco de Servicios Financieros",
    "336": "Banco Bradesco Argentina", "338": "Banco de Servicios y Transacciones",
    "339": "RCI Banque", "340": "BACS Banco de Credito y Securitizacion",
    "341": "Banco Masventas", "384": "Wilobank", "386": "Nuevo Banco de Entre Rios",
    "389": "Banco Columbia", "405": "Ford Credit Cia. Financiera",
    "406": "Metropolis Cia. Financiera", "408": "Compania Financiera Argentina (CFA)",
    "415": "Multifinanzas Cia. Financiera", "426": "Banco BICA",
    "428": "Caja de Credito La Capital del Plata", "431": "Banco Coinag",
    "432": "Banco de Comercio", "440": "Banco Dino", "448": "Credicuotas Consumo",
}

# Billeteras virtuales (CVU): se identifican por el prefijo de 7 digitos
# (entidad 000 + sucursal del PSP). Referencial; se amplia a medida que se confirman.
PSP_CVU = {
    "0000003": "Mercado Pago",
}


def _dv_bloque(digitos: str, pesos: list[int]) -> int:
    suma = sum(int(d) * p for d, p in zip(digitos, pesos))
    return (10 - (suma % 10)) % 10


def cbu_info(value: str) -> dict:
    """Valida un CBU/CVU (22 digitos) con sus digitos verificadores e identifica
    la entidad por el codigo. Todo offline (es matematica + una tabla)."""
    num = re.sub(r"[\s\-.]", "", value)
    if not (num.isdigit() and len(num) == 22):
        return {"source": "CBU/CVU", "ok": False,
                "error": "No parece un CBU/CVU: deben ser 22 digitos."}
    b1, b2 = num[:8], num[8:]
    dv1_ok = _dv_bloque(b1[:7], [7, 1, 3, 9, 7, 1, 3]) == int(b1[7])
    dv2_ok = _dv_bloque(b2[:13], [3, 9, 7, 1, 3, 9, 7, 1, 3, 9, 7, 1, 3]) == int(b2[13])
    valido = dv1_ok and dv2_ok
    entidad = num[:3]
    if entidad == "000":  # CVU de billetera virtual
        es_cvu = True
        entidad_nombre = PSP_CVU.get(num[:7]) or "billetera virtual (CVU) - PSP no identificado"
    else:
        es_cvu = False
        entidad_nombre = BANCOS.get(entidad) or f"codigo {entidad} no identificado (verifica en la nomina del BCRA)"
    data = {
        "valido": valido,
        "entidad_codigo": entidad,
        "entidad": entidad_nombre,
        "sucursal": num[3:7],
        "tipo": "CVU (billetera virtual)" if es_cvu else "CBU (cuenta bancaria)",
        "nota": ("La validez confirma que el numero esta bien formado y a que entidad "
                 "pertenece. NO confirma el titular de la cuenta ni que sea de fiar. "
                 "La tabla de entidades es referencial: ante la duda, confirma con el BCRA."),
    }
    return {"source": "CBU/CVU (offline)", "ok": True, "data": data}


# --------------------------------------------------------------------------- #
# Analizador de links / URL (anti-phishing, offline)
# --------------------------------------------------------------------------- #
_SHORTENERS = {"bit.ly", "tinyurl.com", "cutt.ly", "goo.gl", "t.co", "ow.ly",
               "is.gd", "acortar.link", "rebrand.ly", "shorturl.at", "t.ly", "rb.gy"}
_TLDS_SOSPECHOSOS = {"zip", "mov", "top", "xyz", "click", "country", "gq", "tk",
                     "ml", "cf", "ga", "work", "rest", "fit", "loan", "review", "cam"}
_MARCAS = ("banco", "bank", "gob", "gov", "afip", "arca", "mercado", "pago",
           "bcra", "anses", "visa", "mastercard", "paypal")


def analyze_url(value: str) -> dict:
    raw = value.strip()
    con_esquema = bool(re.match(r"^[a-zA-Z][\w+.\-]*://", raw))
    parsed = urllib.parse.urlparse(raw if con_esquema else "http://" + raw)
    host = (parsed.hostname or "").lower()
    labels = host.split(".") if host else []
    tld = labels[-1] if labels else ""
    señales = []

    if con_esquema and parsed.scheme == "http":
        señales.append("Usa http (sin cifrado). Un sitio serio usa https.")
    if "@" in (parsed.netloc or ""):
        señales.append("Tiene '@' en la direccion: truco para ocultar el destino real.")
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
        señales.append("El destino es una IP, no un dominio: inusual y sospechoso.")
    if host.startswith("xn--") or ".xn--" in host:
        señales.append("Dominio con punycode (xn--): posible imitacion con letras parecidas.")
    if len(labels) >= 5:
        señales.append(f"Muchos subdominios ({len(labels)} niveles): comun en phishing.")
    if len(host) > 40:
        señales.append("Host muy largo: tactica para disimular el dominio real.")
    if host in _SHORTENERS:
        señales.append("Es un acortador: oculta a donde te lleva realmente.")
    if tld in _TLDS_SOSPECHOSOS:
        señales.append(f"Dominio .{tld}: TLD muy usado en fraudes (no es prueba, pero suma sospecha).")
    dominio_base = ".".join(labels[-2:]) if len(labels) >= 2 else host
    if any(m in host for m in _MARCAS) and not any(m in dominio_base for m in _MARCAS):
        señales.append("Usa el nombre de una marca conocida en el subdominio, no en el dominio real: tipico imitador.")

    data = {
        "host": host or "(no se pudo leer)",
        "dominio_base": dominio_base,
        "esquema": parsed.scheme,
        "señales_phishing": señales or ["Sin señales automaticas de phishing. Igual, no "
                                        "ingreses datos ni claves si el link llego sin que lo esperaras."],
    }
    return {"source": "analisis de link (anti-phishing)", "ok": True, "data": data}


# --------------------------------------------------------------------------- #
# Wayback Machine (archive.org) - API gratuita y sin registro
# --------------------------------------------------------------------------- #
async def wayback_machine(client: httpx.AsyncClient, value: str) -> dict:
    """Consulta si archive.org tiene copias historicas del dominio/URL (Cap. 7)."""
    url = value if value.startswith("http") else f"http://{value}"
    try:
        data = await _get_json(
            client, "https://archive.org/wayback/available?url="
            + urllib.parse.quote(url, safe=""))
        snap = (data.get("archived_snapshots") or {}).get("closest")
        if snap and snap.get("available"):
            ts = snap.get("timestamp", "")
            fecha = f"{ts[0:4]}-{ts[4:6]}-{ts[6:8]}" if len(ts) >= 8 else ts
            return {"source": "Wayback Machine (archive.org)", "ok": True, "data": {
                "tiene_copias": True,
                "copia_mas_cercana": snap.get("url"),
                "fecha_copia": fecha,
                "historial_completo": f"https://web.archive.org/web/*/{value}",
                "nota": "Compara como era la pagina antes de confiar en su version actual.",
            }}
        return {"source": "Wayback Machine (archive.org)", "ok": False,
                "error": ("Sin capturas archivadas (sitio nuevo, bloquea el archivo o "
                          "nunca fue indexado). La ausencia no prueba que no exista.")}
    except Exception as e:
        return {"source": "Wayback Machine (archive.org)", "ok": False, "error": str(e)}


# --------------------------------------------------------------------------- #
# Generador de Google Dorks (Cap. 1 - "Google como lupa")
# --------------------------------------------------------------------------- #
def _g(q: str) -> str:
    return "https://www.google.com/search?q=" + urllib.parse.quote(q)


def google_dorks(value: str, tipo: str) -> dict:
    v = value.strip()
    d: dict[str, str] = {}
    if tipo == "email":
        local, _, dom = v.partition("@")
        d["Menciones exactas del correo"] = _g(f'"{v}"')
        d["Correo en volcados/pegado"] = _g(f'"{v}" (site:pastebin.com OR site:throwbin.io OR site:ghostbin.com)')
        d["Alias (antes del @) como usuario"] = _g(f'"{local}"')
        d["Otros correos del mismo dominio"] = _g(f'"@{dom}"')
    elif tipo == "domain":
        d["Paginas indexadas del dominio"] = _g(f"site:{v}")
        d["Documentos publicados (PDF/Excel/Word)"] = _g(f"site:{v} (filetype:pdf OR filetype:xlsx OR filetype:docx)")
        d["Accesos/paneles expuestos"] = _g(f"site:{v} (inurl:login OR inurl:admin OR inurl:panel)")
        d["Correos del dominio"] = _g(f'"@{v}"')
    elif tipo == "phone":
        d["Numero entre comillas"] = _g(f'"{v}"')
        d["Numero en avisos/clasificados"] = _g(f'"{v}" (site:olx.com.ar OR site:mercadolibre.com.ar OR site:facebook.com)')
    elif tipo == "ip":
        d["IP entre comillas"] = _g(f'"{v}"')
        d["IP en reportes de abuso"] = _g(f'"{v}" (abuse OR blacklist OR malware)')
    elif tipo == "cbu":
        pass  # un CBU no se busca en Google
    elif tipo == "url":
        host = urllib.parse.urlparse(v if re.match(r"^https?://", v, re.I) else "http://" + v).hostname or v
        d["El dominio en Google (reportes)"] = _g(f'"{host}" (estafa OR phishing OR fraude OR scam)')
    elif tipo == "person":
        # LinkedIn primero: el dork site:linkedin.com/in es la forma mas efectiva
        # SIN login de encontrar el perfil publico de una persona.
        d["LinkedIn - perfil de la persona"] = _g(f'site:linkedin.com/in "{v}"')
        d["LinkedIn - menciones"] = _g(f'"{v}" site:linkedin.com')
        d["Nombre exacto"] = _g(f'"{v}"')
        d["En documentos (PDF/Word/Excel)"] = _g(f'"{v}" (filetype:pdf OR filetype:doc OR filetype:xls)')
        d["En redes sociales"] = _g(f'"{v}" (site:instagram.com OR site:facebook.com OR site:x.com)')
        d["Agregar ciudad/profesion (edita el texto)"] = _g(f'"{v}" (Argentina OR Buenos Aires)')
        d["Excluir homonimos (edita el -)"] = _g(f'"{v}" -wikipedia')
    else:  # username (un solo alias)
        d["Usuario exacto"] = _g(f'"{v}"')
        d["Usuario en foros/redes"] = _g(f'"{v}" (site:reddit.com OR site:github.com OR site:x.com OR site:instagram.com)')
    return d


# --------------------------------------------------------------------------- #
# Fuentes oficiales (Apendice - mapa de fuentes publicas; foco Argentina)
# --------------------------------------------------------------------------- #
def fuentes_oficiales(tipo: str, value: str) -> dict:
    # Puntos de entrada oficiales para verificar normas, sociedades, personas
    # y situacion fiscal/crediticia. Verifica siempre que la direccion sea oficial.
    if tipo == "ip":
        return {}
    return {
        "Boletin Oficial de la Republica Argentina": "https://www.boletinoficial.gob.ar",
        "Normativa nacional (InfoLEG / argentina.gob.ar)": "https://www.argentina.gob.ar/normativa",
        "ARCA (ex-AFIP) - constancias y servicios fiscales": "https://www.arca.gob.ar",
        "BCRA - Central de Deudores (situacion crediticia)": "https://www.bcra.gob.ar/BCRAyVos/Situacion_Crediticia.asp",
        "Mesa de Entradas Virtual - SCBA (causas Prov. Bs. As.)": "https://mev.scba.gov.ar",
        "nota": ("Empeza por la jurisdiccion correcta (Nacion, provincia o municipio). "
                 "En la documentacion esta el mapa regional (Brasil, Espana, Mexico, "
                 "Chile, Uruguay, Colombia)."),
    }


# --------------------------------------------------------------------------- #
# Enlaces de verificacion (herramientas que recomienda el libro)
# --------------------------------------------------------------------------- #
def enlaces_verificacion(tipo: str, value: str) -> dict:
    enlaces: dict[str, Any] = {}
    # Imagen/video/mapas solo tienen sentido cuando hay una persona o una foto detras.
    if tipo in ("person", "username", "email", "phone"):
        enlaces["Imagen (busqueda inversa)"] = {
            "Google Lens": "https://lens.google.com",
            "Yandex Images (mejor para rostros)": "https://yandex.com/images",
            "TinEye (antiguedad de una foto)": "https://tineye.com",
        }
        enlaces["Video (verificacion de fotogramas)"] = {
            "InVID-WeVerify": "https://www.invid-project.eu/tools-and-services/invid-verification-plugin/",
        }
        enlaces["Mapas (geolocalizacion de fotos)"] = {
            "Google Maps": "https://www.google.com/maps",
            "Google Earth": "https://earth.google.com/web/",
            "OpenStreetMap": "https://www.openstreetmap.org",
        }
    if tipo == "url":
        host = urllib.parse.urlparse(
            value if re.match(r"^https?://", value, re.I) else "http://" + value).hostname or value
        enlaces["Analisis del link (gratis, sin instalar)"] = {
            "urlscan.io (que hace la pagina)": f"https://urlscan.io/search/#{urllib.parse.quote(host)}",
            "VirusTotal (reputacion de la URL)": "https://www.virustotal.com/gui/home/url",
        }
    if tipo == "email":
        enlaces["Email (brechas de datos)"] = {
            "Have I Been Pwned (revisa manualmente)": "https://haveibeenpwned.com",
        }
    elif tipo == "domain":
        enlaces["Dominio (registro)"] = {
            "ICANN Lookup (WHOIS/RDAP)": f"https://lookup.icann.org/en/lookup?q={urllib.parse.quote(value)}",
        }
    elif tipo == "username":
        enlaces["Usuario (presencia)"] = {
            "WhatsMyName": "https://whatsmyname.app",
        }
    elif tipo == "person":
        enlaces["Persona (perfiles)"] = {
            "LinkedIn - busqueda de personas":
                f"https://www.linkedin.com/search/results/people/?keywords={urllib.parse.quote(value)}",
            "WhatsMyName (si tenes un alias)": "https://whatsmyname.app",
        }
    return enlaces


# --------------------------------------------------------------------------- #
# Cierre de investigacion: 3 columnas + nivel de confianza (marco del libro)
#   "Podemos sostener" / "Todavia no sabemos" / "Decision prudente"
#   No sentencia: ordena lo verificado y lo que falta. La ausencia NO es culpa.
# --------------------------------------------------------------------------- #
def _dato(resultados: list[dict], src_sub: str) -> dict:
    for r in resultados:
        if r.get("ok") and src_sub in r.get("source", ""):
            return r.get("data", {})
    return {}


def cierre_investigacion(tipo: str, resultados: list[dict]) -> dict:
    sostener: list[str] = []
    no_sabemos: list[str] = []
    decision = ""
    confianza = "Medio"

    if tipo == "phone":
        d = _dato(resultados, "phonenumbers")
        if d.get("valido"):
            sostener.append(f"Numero valido en el plan de numeracion de {d.get('pais')}"
                            f" ({d.get('region_geografica') or 'region no determinada'}).")
            sostener.append(f"Tipo de linea: {d.get('tipo_linea')}.")
            if d.get("compania_asignada"):
                sostener.append(f"Compania de registro del prefijo: {d['compania_asignada']}.")
            confianza = "Alto"
        else:
            sostener.append("El numero no resulta valido en el plan de numeracion.")
            confianza = "Bajo"
        no_sabemos.append("Si el numero fue portado a otra compania (la base publica no lo refleja).")
        no_sabemos.append("La ubicacion o el titular reales (no son fuente abierta).")
        no_sabemos.append("La reputacion: revisa los enlaces de reportes comunitarios.")
        tl = (d.get("tipo_linea") or "")
        if (not d.get("valido")) or tl in ("VoIP", "tarifa premium", "costo compartido"):
            decision = ("Tratar como sospechoso: no compartir datos ni devolver la "
                        "llamada hasta verificar por un canal independiente.")
        else:
            decision = ("IMPORTANTE: que el numero sea valido NO quiere decir que sea "
                        "seguro (los estafadores usan lineas validas). Revisa los enlaces "
                        "de 'reportes comunitarios' mas abajo: ahi aparecen las denuncias. "
                        "No compartas datos sensibles por telefono.")

    elif tipo == "email":
        d = _dato(resultados, "email")
        grav = _dato(resultados, "Gravatar")
        if d:
            if d.get("puede_recibir_correo"):
                sostener.append("El dominio puede recibir correo (tiene registros MX).")
            else:
                sostener.append("El dominio NO puede recibir correo (sin MX): el correo "
                                "probablemente es falso o no operativo.")
            if d.get("dominio_descartable"):
                sostener.append("El dominio es de correo descartable/temporal.")
            if d.get("dominio_creado") and "desconocido" not in str(d.get("dominio_creado")):
                sostener.append(f"Dominio registrado: {d['dominio_creado']}.")
        if grav.get("existe_perfil_publico"):
            sostener.append("El correo tiene perfil publico en Gravatar (datos que su "
                            "propio titular decidio publicar).")
        no_sabemos.append("Si el correo pertenece realmente a quien dice usarlo.")
        no_sabemos.append("Si figura en brechas de datos (revisalo en Have I Been Pwned).")
        if d.get("dominio_descartable") or not d.get("puede_recibir_correo"):
            decision = ("Alta cautela: el correo podria ser falso o descartable. No operar "
                        "sin verificar la identidad por otro canal.")
            confianza = "Bajo"
        else:
            decision = ("Sin senales negativas automaticas en el dominio. Verifica la "
                        "identidad por un canal independiente antes de confiar.")

    elif tipo == "domain":
        dns = _dato(resultados, "DNS")
        geo = _dato(resultados, "ip-api") or _dato(resultados, "ipwho")
        wb = _dato(resultados, "Wayback")
        if dns:
            if "MX" in dns:
                sostener.append(f"Correo del dominio gestionado por: {', '.join(dns['MX'])[:120]}.")
            if "NS" in dns:
                sostener.append(f"DNS/nameservers: {', '.join(dns['NS'])[:120]}.")
            confianza = "Alto"
        if geo.get("org") or geo.get("isp"):
            sostener.append(f"La IP publica pertenece a {geo.get('org') or geo.get('isp')}"
                            f" ({geo.get('country')}). Puede ser un CDN, no la sede real.")
        if wb.get("tiene_copias"):
            sostener.append(f"Hay copias historicas en archive.org (desde {wb.get('fecha_copia')}).")
        no_sabemos.append("Si el sitio es legitimo o suplanta a otro (contrasta con fuentes oficiales).")
        no_sabemos.append("Para dominios .ar: el titular no es publico sin cuenta en NIC.ar.")
        decision = ("Util como verificacion de infraestructura. Para la legitimidad del "
                    "sitio, contrasta con fuentes oficiales y con Wayback Machine.")

    elif tipo == "ip":
        geo = _dato(resultados, "ipwho") or _dato(resultados, "ip-api")
        if geo:
            sostener.append(f"La IP figura en {geo.get('country')} / {geo.get('city') or 's/d'}, "
                            f"proveedor {geo.get('isp') or geo.get('org')} ({geo.get('as')}).")
            confianza = "Alto"
        no_sabemos.append("La ubicacion fisica de una persona (esto es infraestructura de red, "
                          "no domicilio).")
        decision = "Dato de infraestructura. Interpreta la ubicacion como del servidor/red, no de una persona."

    elif tipo == "cbu":
        d = _dato(resultados, "CBU/CVU")
        if d:
            if d.get("valido"):
                sostener.append(f"{d.get('tipo')} VALIDO (digitos verificadores correctos).")
                sostener.append(f"Entidad: {d.get('entidad')} (codigo {d.get('entidad_codigo')}).")
                confianza = "Alto"
            else:
                sostener.append("El CBU/CVU NO es valido (los digitos verificadores no cierran): "
                                "esta mal copiado o es inventado.")
                confianza = "Alto"
        no_sabemos.append("El titular de la cuenta (no es dato de fuente abierta).")
        if d.get("valido"):
            decision = ("Que sea valido confirma el numero y el banco, NO al titular ni que sea "
                        "de fiar. Antes de transferir, confirma con la persona por un canal que "
                        "vos inicies (no el que te pasaron).")
        else:
            decision = ("No transferir: el numero no es valido. Pedi que te lo confirmen bien "
                        "por un canal seguro.")

    elif tipo == "url":
        d = _dato(resultados, "analisis de link")
        señ = d.get("señales_phishing", []) if d else []
        hay = señ and not señ[0].startswith("Sin señales")
        if d:
            sostener.append(f"Destino real del link: {d.get('host')} (dominio {d.get('dominio_base')}).")
        if hay:
            for s in señ:
                no_sabemos.append("Señal: " + s)
            decision = ("Varias señales de phishing: NO ingreses datos ni claves y no descargues "
                        "nada. Si dice ser tu banco/organismo, entra escribiendo vos la direccion "
                        "oficial, nunca desde este link.")
            confianza = "Alto"
        else:
            no_sabemos.append("Si el contenido del sitio es legitimo (esto es analisis del link, no del contenido).")
            decision = ("Sin señales automaticas, pero igual: no ingreses datos si el link llego "
                        "sin que lo esperaras. Verifica el sitio por la via oficial.")
            confianza = "Medio"

    elif tipo == "person":
        sostener.append("ARGos no reconstruye el perfil de la persona: te entrega busquedas "
                        "y enlaces (LinkedIn, documentos, redes) para que verifiques vos.")
        no_sabemos.append("Todo lo que surja son INDICIOS: que coincida el nombre no prueba "
                          "la identidad (hay homonimos).")
        decision = ("Usar solo para verificacion legitima y puntual (p. ej. corroborar a un "
                    "candidato o contraparte), NUNCA para perfilar. Confirma por verificacion "
                    "cruzada y respeta la Ley 25.326.")
        confianza = "Bajo"

    else:  # username
        d = _dato(resultados, "presencia de usuario")
        encontrados = d.get("encontrados", []) if d else []
        if encontrados:
            plats = ", ".join(c.get("plataforma", "") for c in encontrados)
            sostener.append(f"El alias aparece en {len(encontrados)} plataforma(s): {plats}.")
            confianza = "Medio" if len(encontrados) >= 3 else "Bajo"
        else:
            sostener.append("No se encontro presencia publica de ese alias en las plataformas revisadas.")
            confianza = "Bajo"
        no_sabemos.append("Si todas las cuentas pertenecen a la MISMA persona "
                          "(coincidir de alias no es lo mismo que coincidir de identidad).")
        decision = ("Tratar como indicios, no como prueba. Confirma con verificacion cruzada "
                    "antes de atribuir las cuentas a una persona concreta.")

    if not sostener:
        sostener.append("No se obtuvieron datos suficientes en esta consulta.")
        confianza = "Bajo"

    return {
        "podemos_sostener": sostener,
        "todavia_no_sabemos": no_sabemos,
        "decision_prudente": decision,
        "nivel_confianza": confianza,
        "nota": ("La certeza mide cuan solidos son los DATOS hallados, NO si el contacto "
                 "es confiable: un dato valido no implica que sea seguro. La ausencia de "
                 "rastro tampoco es, por si sola, senal de riesgo; 'no pude corroborarlo' "
                 "suele ser mas exacto que 'es falso'."),
    }


# --------------------------------------------------------------------------- #
# Orquestador
# --------------------------------------------------------------------------- #
async def investigate(value: str, forzar_tipo: str | None = None) -> dict:
    value = value.strip()
    tipo = forzar_tipo or detect_type(value)
    reporte: dict[str, Any] = {"entrada": value, "tipo_detectado": tipo, "resultados": []}

    if tipo == "phone":
        # Telefono: offline, sin cliente HTTP.
        reporte["resultados"] = [await asyncio.to_thread(phone_info, value)]
    elif tipo == "cbu":
        reporte["resultados"] = [cbu_info(value)]
    elif tipo == "url":
        reporte["resultados"] = [analyze_url(value)]
    elif tipo == "person":
        # Modo persona: busqueda asistida, sin consultar datos de la persona.
        reporte["resultados"] = [{
            "source": "modo persona (busqueda asistida)", "ok": True, "data": {
                "nota": ("ARGos no consulta ni almacena datos de la persona. Te arma las "
                         "busquedas y enlaces (abajo) para que verifiques vos, de forma "
                         "legitima y puntual. Trata todo como indicios, no como prueba."),
            }}]
    else:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
            if tipo == "ip":
                reporte["resultados"] = list(await asyncio.gather(
                    ip_geolocation(client, value),
                    rdap_ip(client, value),
                    reverse_dns(value),
                ))

            elif tipo == "domain":
                ips = await asyncio.to_thread(_resolve_sync, value)
                reporte["ips_resueltas"] = ips
                tareas = [rdap_domain(client, value), dns_records(value),
                          crtsh_subdomains(client, value), wayback_machine(client, value)]
                if ips:
                    tareas.append(ip_geolocation(client, ips[0]))
                reporte["resultados"] = list(await asyncio.gather(*tareas))

            elif tipo == "email":
                res = await email_profile(client, value)
                dominio = value.partition("@")[2]
                res.append(await wayback_machine(client, dominio))
                reporte["resultados"] = res

            else:  # username
                reporte["resultados"] = [await username_presence(client, value)]

    # Sintesis y ayudas de investigacion (marco del libro "OSINT para todos").
    reporte["cierre_investigacion"] = cierre_investigacion(tipo, reporte["resultados"])
    reporte["google_dorks"] = google_dorks(value, tipo)
    reporte["fuentes_oficiales"] = fuentes_oficiales(tipo, value)
    reporte["enlaces_verificacion"] = enlaces_verificacion(tipo, value)
    reporte["fecha_consulta_utc"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    return reporte
