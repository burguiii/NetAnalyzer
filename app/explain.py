"""
Traductor a "lenguaje humano".

Convierte los datos tecnicos de una conexion (IP, puerto, estado, reputacion)
en explicaciones que entiende cualquiera:
  - ¿Que es esto? (tipo de servicio)
  - ¿Quien es? (nombre reconocible: Google, YouTube, Amazon...)
  - ¿Lo cause yo o vino de fuera? (direccion)
  - ¿Es bueno o malo? (veredicto: verde / amarillo / rojo)
  - ¿Que hago? (pasos concretos)

Este modulo NO toca la red ni la BD: solo interpreta datos que ya tenemos.
"""

import ipaddress

from . import config

# ----------------------------------------------------------------------
# Puertos -> que servicio es, en cristiano
# categoria sirve para decidir si "lo causaste tu" y el consejo
# ----------------------------------------------------------------------
PORT_SERVICES = {
    443:  ("Web segura (HTTPS)", "Navegación web cifrada. La mayoría de páginas y apps (YouTube, redes sociales, banca…) usan esto.", "web"),
    80:   ("Web (HTTP)", "Navegación web sin cifrar. Habitual, aunque hoy casi todo va por HTTPS.", "web"),
    8080: ("Web alternativa", "Otro puerto típico de páginas web y APIs.", "web"),
    53:   ("DNS (buscar webs)", "Tu PC preguntando '¿a qué IP corresponde esta web?'. Ocurre sin parar cuando navegas.", "dns"),
    853:  ("DNS cifrado", "Igual que DNS pero cifrado. Normal.", "dns"),
    123:  ("Hora (NTP)", "Tu PC ajustando su reloj con un servidor de hora. Totalmente normal.", "time"),
    993:  ("Correo (IMAP)", "Tu programa de correo descargando emails.", "mail"),
    143:  ("Correo (IMAP)", "Tu programa de correo descargando emails.", "mail"),
    587:  ("Correo (envío)", "Tu programa de correo enviando emails.", "mail"),
    465:  ("Correo (envío)", "Tu programa de correo enviando emails.", "mail"),
    25:   ("Correo (SMTP)", "Envío de correo. En un PC normal es poco común; en un servidor sí.", "mail"),
    110:  ("Correo (POP3)", "Tu programa de correo descargando emails.", "mail"),
    22:   ("SSH (acceso remoto)", "Conexión de terminal remota. Normal si usas herramientas técnicas; raro si no.", "remote"),
    3389: ("Escritorio remoto (RDP)", "Control de un PC a distancia. Si no lo has activado tú, es para vigilar.", "remote"),
    445:  ("Compartir archivos (SMB)", "Compartir carpetas o impresoras. Normal en red local, peligroso hacia Internet.", "fileshare"),
    139:  ("Red local (NetBIOS)", "Cosas de red local de Windows (carpetas compartidas).", "fileshare"),
    137:  ("Red local (NetBIOS)", "Descubrimiento de equipos en tu red local.", "local"),
    138:  ("Red local (NetBIOS)", "Descubrimiento de equipos en tu red local.", "local"),
    5228: ("Notificaciones de Google", "Servicios de Google/Android/Chrome: notificaciones, sincronización, Play Store.", "push"),
    5223: ("Notificaciones de Apple", "Servicios de Apple: iCloud, notificaciones.", "push"),
    1900: ("Descubrimiento en red local (UPnP)", "Tu PC buscando dispositivos en casa (tele, router, impresora).", "local"),
    5353: ("Descubrimiento en red local (mDNS)", "Tu PC encontrando dispositivos cercanos (Chromecast, impresoras).", "local"),
    3478: ("Videollamada (WebRTC)", "Llamadas de voz/vídeo: Meet, Discord, Teams, WhatsApp Web…", "voip"),
    19302:("Videollamada de Google", "Llamadas de Google Meet.", "voip"),
    3479: ("Videollamada (WebRTC)", "Llamadas de voz/vídeo.", "voip"),
}

# Pistas para reconocer a la empresa por su ISP/hostname
ORG_HINTS = [
    ("google",     "Google (YouTube, Gmail, Búsqueda, Chrome…)"),
    ("youtube",    "YouTube (Google)"),
    ("1e100",      "Google (su red interna se llama 1e100.net)"),
    ("cloudflare", "Cloudflare (red que sirve muchísimas webs)"),
    ("amazon",     "Amazon / AWS (aloja media Internet, tiendas, apps)"),
    ("aws",        "Amazon AWS (servidores de muchas apps)"),
    ("microsoft",  "Microsoft (Windows, Office, Xbox, Bing…)"),
    ("azure",      "Microsoft Azure (servidores de apps)"),
    ("akamai",     "Akamai (red que acelera webs y descargas)"),
    ("fastly",     "Fastly (red que sirve webs, p.ej. noticias)"),
    ("meta",       "Meta (Facebook, Instagram, WhatsApp)"),
    ("facebook",   "Meta (Facebook, Instagram, WhatsApp)"),
    ("apple",      "Apple (iCloud, App Store, actualizaciones)"),
    ("netflix",    "Netflix"),
    ("spotify",    "Spotify"),
    ("twitch",     "Twitch (streaming)"),
    ("discord",    "Discord"),
    ("cdn",        "Red de distribución de contenidos (CDN): sirve vídeos, imágenes y descargas"),
    ("tiktok",     "TikTok"),
    ("bytedance",  "TikTok (ByteDance)"),
]


def _ip_kind(ip: str) -> str:
    """Devuelve 'loopback', 'lan' o 'internet'."""
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_loopback:
            return "loopback"
        if addr.is_private or addr.is_link_local:
            return "lan"
        return "internet"
    except ValueError:
        return "internet"


def service_of(port: int) -> tuple[str, str, str]:
    """(nombre, descripcion, categoria) del puerto remoto."""
    if port in PORT_SERVICES:
        return PORT_SERVICES[port]
    if port in config.SUSPICIOUS_PORTS:
        return ("Puerto inusual ⚠", "Puerto asociado a herramientas maliciosas conocidas.", "suspicious")
    return (f"Puerto {port}", "Servicio no identificado. No es raro, pero no sabemos qué app es.", "other")


def who_is(hostname: str, isp: str, country: str, city: str) -> str:
    """Nombre reconocible de con quién habla el PC."""
    text = f"{hostname} {isp}".lower()
    for key, label in ORG_HINTS:
        if key in text:
            place = f" · {city}, {country}" if country else ""
            return label + place
    if isp:
        place = f" · {city}, {country}" if country else ""
        return f"{isp}{place}"
    if hostname:
        return hostname
    return "Desconocido (aún sin nombre)"


def infer_direction(row: dict, listening_ports: set) -> str:
    """¿La conexión la inició tu PC (Saliente) o vino de fuera (Entrante)?"""
    raw = row.get("raw_status", "")
    lport = row.get("local_port") or 0
    rport = row.get("remote_port") or 0

    if _ip_kind(row.get("remote_ip", "")) == "loopback":
        return "Local"
    if raw == "LISTEN":
        return "En escucha"
    if raw == "SYN_RECV":
        return "Entrante"
    if lport in listening_ports:
        return "Entrante"
    # Heurística por puertos: el "servidor" suele tener el puerto bajo/conocido
    l_service = lport in PORT_SERVICES or lport < 1024
    r_service = rport in PORT_SERVICES or rport < 1024
    if r_service and not l_service:
        return "Saliente"
    if l_service and not r_service:
        return "Entrante"
    # Por defecto, en un PC de escritorio casi todo lo inicia el propio PC
    return "Saliente"


def describe(row: dict, info: dict | None, listening_ports: set) -> dict:
    """
    Devuelve un dict con toda la explicacion humana de UNA conexion:
      direction, service, service_desc, who, verdict ('ok'|'warn'|'bad'|'unknown'),
      caused_by_you, summary, advice (lista de pasos).
    """
    info = info or {}
    port = row.get("remote_port") or 0
    ip = row.get("remote_ip", "")
    kind = _ip_kind(ip)
    direction = infer_direction(row, listening_ports)
    svc_name, svc_desc, category = service_of(port)
    if kind == "loopback":
        who = "Tu propio PC (comunicación interna)"
    elif kind == "lan":
        who = f"Dispositivo de tu red local ({ip})"
    else:
        who = who_is(info.get("hostname", ""), info.get("isp", ""),
                     info.get("country", ""), info.get("city", ""))
    score = info.get("abuse_score")
    process = row.get("process_name", "una app")

    # ---- Veredicto (semaforo) ----
    rep_enabled = bool(config.ABUSEIPDB_API_KEY)
    unverified = False
    if score is not None and score >= config.ABUSE_SCORE_THRESHOLD:
        verdict = "bad"
    elif category == "suspicious":
        verdict = "bad"
    elif score is not None and score >= 15:
        verdict = "warn"
    elif score is not None:
        verdict = "ok"                 # reputación comprobada y limpia (0-14)
    elif kind in ("loopback", "lan"):
        verdict = "ok"
    elif not rep_enabled:
        # Sin API key no podemos comprobar reputación: no asustamos al usuario
        # con un "verificando" eterno; lo damos por normal pero lo señalamos.
        verdict = "ok"
        unverified = True
    else:
        verdict = "unknown"            # reputación activa, aún consultándose

    # ---- ¿Lo causaste tú? ----
    if kind == "loopback":
        caused = "Sí. Es tu PC hablando consigo mismo (programas internos). Inofensivo."
    elif direction == "Entrante":
        caused = "No. Esta conexión vino desde FUERA hacia tu PC. Conviene mirar quién y por qué."
    elif direction == "En escucha":
        caused = "Es un programa tuyo esperando conexiones (un 'servidor'). Normal si sabes qué es."
    elif category in ("web", "dns", "voip", "push", "time", "mail"):
        caused = f"Sí, casi seguro. Lo inició tu PC: «{process}» (tu navegador/una app). Es lo normal al navegar o usar programas."
    else:
        caused = f"Probablemente sí: lo inició «{process}» desde tu PC."

    # ---- Resumen en una frase ----
    arrow = {"Saliente": "tu PC → ", "Entrante": "→ tu PC ", "Local": "", "En escucha": ""}.get(direction, "")
    if kind == "loopback":
        summary = "Comunicación interna de tu PC. No es tráfico de Internet."
    elif direction == "Entrante":
        summary = f"Algo de fuera ({who}) conectó a tu PC usando «{svc_name}»."
    else:
        summary = f"«{process}» conectó con {who} para «{svc_name}»."

    # ---- ¿Qué hago? ----
    advice = _advice(verdict, direction, category, ip, process, who)
    if unverified and kind == "internet":
        note = ("No hemos podido comprobar la reputación de esta IP (no hay API "
                "key de AbuseIPDB configurada). Parece tráfico normal, pero para "
                "máxima seguridad puedes activar la reputación en la configuración.")
    else:
        note = ""

    return {
        "direction": direction,
        "service": svc_name,
        "service_desc": svc_desc,
        "who": who,
        "verdict": verdict,
        "caused_by_you": caused,
        "summary": summary,
        "advice": advice,
        "ip_kind": kind,
        "note": note,
    }


def _advice(verdict, direction, category, ip, process, who) -> list[str]:
    if verdict == "bad" and direction == "Entrante":
        return [
            "Alguien de fuera intentó/logró conectar a tu PC. Trátalo en serio.",
            f"Bloquea la IP {ip} con el botón «Bloquear» (crea una regla de firewall).",
            "Comprueba que no tienes programas abriendo puertos sin querer.",
            "Pasa un análisis con tu antivirus (Windows Defender vale).",
        ]
    if verdict == "bad":
        return [
            f"«{process}» está hablando con una dirección de mala reputación ({who}).",
            f"Si NO reconoces «{process}», ciérralo desde el Administrador de tareas.",
            f"Bloquea la IP {ip} con el botón «Bloquear».",
            "Haz un análisis completo con tu antivirus.",
            "Si se repite tras reiniciar, busca el nombre del programa en Google.",
        ]
    if verdict == "warn":
        return [
            "Reputación dudosa, pero no confirmada como maligna.",
            f"Vigila si «{process}» es un programa que reconoces.",
            "Si no lo reconoces o se repite mucho, bloquea la IP y analiza el PC.",
        ]
    if direction == "Entrante":
        return [
            "Conexión entrante. Suele ser tu router o dispositivos de tu casa.",
            "Si no reconoces el origen y viene de Internet, puedes bloquearla por precaución.",
        ]
    if verdict == "unknown":
        return [
            "Conexión saliente normal; aún estamos verificando la reputación de la IP (unos segundos).",
            "No hace falta hacer nada salvo que aparezca en rojo.",
        ]
    return ["Todo normal. No hay que hacer nada."]


# ----------------------------------------------------------------------
# Textos para ALERTAS (usados por detection.py)
# ----------------------------------------------------------------------
def alert_advice(rule: str, ip: str, process: str) -> str:
    """Consejo en cristiano para cada tipo de alerta."""
    p = process or "un programa"
    if rule == "Escaneo de puertos entrante":
        return (f"Alguien desde {ip} está 'probando puertas' de tu PC (buscando "
                f"puntos por donde entrar). NO lo has causado tú. Bloquea esa IP y, "
                f"si se repite mucho, avisa a tu proveedor de Internet.")
    if rule == "Conexion a IP con mala reputacion":
        return (f"«{p}» habló con {ip}, una dirección señalada por otros usuarios como "
                f"peligrosa. Si no reconoces «{p}», ciérralo, bloquea la IP y pasa el antivirus.")
    if rule == "Puerto remoto inusual":
        return (f"«{p}» usó un puerto típico de programas maliciosos hacia {ip}. "
                f"Si no sabes qué es «{p}», investígalo: ciérralo, bloquea la IP y analiza el PC.")
    if rule == "Proceso en ubicacion sospechosa":
        return (f"«{p}» se ejecuta desde una carpeta temporal/de descargas (donde suele "
                f"esconderse el malware) y se conectó a Internet. Revísalo con el antivirus.")
    if rule == "Pico de conexiones nuevas":
        return (f"«{p}» abrió MUCHAS conexiones de golpe. Puede ser normal (un juego, "
                f"un navegador con muchas pestañas, una descarga) o no. Si no reconoces "
                f"«{p}», vigílalo.")
    return "Revisa la conexión implicada y bloquéala si no la reconoces."
