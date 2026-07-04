# Especificación técnica: Monitor de Red Personal (Windows) — Fase 1

## Contexto para Claude Code

Esta app corre en un PC con **Windows**. El objetivo de esta primera fase es monitorizar únicamente el propio PC (no toda la red doméstica todavía — eso vendrá en una fase posterior con una sonda/Raspberry Pi y port mirroring). Se necesita visibilidad de: qué procesos abren qué conexiones, hacia qué IPs/dominios, en qué puertos, con qué volumen de datos, y detectar patrones sospechosos (escaneos de puertos entrantes, conexiones a IPs con mala reputación, picos anómalos de tráfico).

El usuario final no es programador — la app debe instalarse y ejecutarse de forma sencilla, con un dashboard web local claro.

---

## 1. Objetivo funcional

1. Listar en tiempo real todas las conexiones de red activas del PC: proceso, PID, IP/puerto local, IP/puerto remoto, protocolo, estado.
2. Resolver y mostrar información de la IP remota: hostname (si resuelve), país/ciudad (geolocalización), y si está en listas negras conocidas.
3. Capturar métricas de tráfico: bytes enviados/recibidos por conexión/proceso a lo largo del tiempo.
4. Detectar patrones sospechosos con reglas simples (ver sección 6) y generar alertas.
5. Guardar histórico en base de datos local para poder revisar después.
6. Dashboard web local (accesible en `http://localhost:PUERTO`) con:
   - Tabla de conexiones activas en vivo (auto-refresh).
   - Lista de alertas generadas, ordenadas por severidad/fecha.
   - Vista de histórico/búsqueda por IP, proceso o fecha.
7. (Opcional, si da tiempo) Botón para bloquear una IP concreta añadiendo una regla al Firewall de Windows.

---

## 2. Restricciones y consideraciones de entorno (Windows)

- **Captura de paquetes en Windows requiere Npcap** (https://npcap.com/) instalado en modo compatible con WinPcap. Esto es un requisito previo que el usuario debe instalar manualmente (no se puede automatizar silenciosamente por temas de permisos/firma). Indicarlo claramente en el README.
- La app necesita ejecutarse **como Administrador** para: leer todas las conexiones de todos los procesos (no solo los del usuario actual) y para capturar paquetes a nivel de interfaz de red.
- Librerías Python recomendadas:
  - `psutil` → listar conexiones activas y mapearlas a procesos (no requiere Npcap, funciona con permisos de admin).
  - `scapy` → captura de paquetes a nivel de red (requiere Npcap). Usar con moderación (puede consumir CPU si se activa sniffing completo).
  - `requests` → consultas a APIs externas (geolocalización, reputación de IP).
  - `flask` + `flask-socketio` (o simplemente polling con `fetch` desde el frontend, más simple) → backend del dashboard.
  - `sqlite3` (built-in) → almacenamiento local.
- Antivirus/Windows Defender puede marcar como sospechoso un script que haga sniffing de paquetes o modifique el firewall — advertir de esto al usuario en el README, no es malware, es comportamiento esperado de una herramienta de este tipo.

---

## 3. Arquitectura

```
monitor-red/
├── app/
│   ├── main.py                  # Punto de entrada, arranca backend + hilo de captura
│   ├── connections.py           # Módulo: lectura de conexiones activas (psutil)
│   ├── packet_capture.py        # Módulo: captura de paquetes (scapy), opcional/activable
│   ├── enrichment.py            # Módulo: geolocalización + reputación de IP (con caché)
│   ├── detection.py             # Módulo: reglas de detección de anomalías
│   ├── firewall.py              # Módulo: bloqueo de IP vía netsh advfirewall
│   ├── db.py                    # Módulo: acceso a SQLite (esquema en sección 5)
│   ├── api.py                   # Endpoints Flask (REST) que usa el frontend
│   └── config.py                # Configuración: intervalos, umbrales, puerto del dashboard
├── static/
│   ├── index.html               # Dashboard principal
│   ├── style.css
│   └── dashboard.js             # Fetch periódico a la API + renderizado de tablas
├── data/
│   └── monitor.db               # Base de datos SQLite (se crea al arrancar)
├── requirements.txt
└── README.md                    # Instrucciones de instalación (incluye lo de Npcap y admin)
```

---

## 4. Funcionalidades detalladas por módulo

### 4.1 `connections.py`
- Usar `psutil.net_connections(kind='inet')` cada N segundos (configurable, default 3s).
- Por cada conexión: PID → `psutil.Process(pid).name()` y `.exe()` para saber qué programa es.
- Guardar snapshot en memoria y persistir cambios (nuevas conexiones / conexiones cerradas) en la tabla `connections` de la BD.
- Manejar excepciones de procesos que ya no existen (`psutil.NoSuchProcess`) o acceso denegado (`psutil.AccessDenied`) sin tumbar la app.

### 4.2 `packet_capture.py` (opcional, activable desde config)
- Usar `scapy.sniff()` en un hilo aparte, con filtro BPF para no saturar (ej. excluir tráfico local/broadcast si no interesa).
- Contabilizar bytes por (IP origen, IP destino, puerto) en ventanas de tiempo (ej. cada 10s) y volcar agregados a la tabla `traffic_stats`. No es necesario guardar cada paquete individual — eso crecería demasiado la BD.
- Este módulo puede quedar deshabilitado por defecto en `config.py` (flag `ENABLE_PACKET_CAPTURE = False`) para que la app funcione ya con solo `connections.py`, y el usuario lo active cuando tenga Npcap instalado y confirmado.

### 4.3 `enrichment.py`
- Para cada IP remota nueva (no privada/local):
  - Geolocalización: usar una API gratuita (ej. `ip-api.com`, sin necesidad de key para uso básico) o base de datos local GeoLite2 si se prefiere sin depender de red externa.
  - Reputación: usar AbuseIPDB API (requiere API key gratuita que el usuario debe generar en https://www.abuseipdb.com/ y poner en `config.py` o variable de entorno). Si no hay key configurada, saltar esta parte sin romper la app.
- Cachear resultados en tabla `ip_info` para no re-consultar la misma IP constantemente (respetar límites de rate de las APIs gratuitas).
- Ignorar/marcar aparte IPs privadas (rangos 10.x, 192.168.x, 172.16-31.x, 127.x) — no tiene sentido geolocalizarlas.

### 4.4 `detection.py` — Reglas iniciales (simples, ampliables después)

| Regla | Lógica | Severidad |
|---|---|---|
| Escaneo de puertos entrante | Más de X puertos distintos tocados desde la misma IP remota en menos de Y segundos (ej. 10 puertos en 5s) | Alta |
| Conexión a IP con mala reputación | La IP remota tiene score alto en AbuseIPDB (ej. >50) | Alta |
| Proceso desconocido con conexión saliente | Proceso sin firma digital conocida o ubicado en carpeta temporal (`%TEMP%`, `AppData\Local\Temp`) abriendo conexiones salientes | Media |
| Pico de tráfico anómalo | Un proceso/IP supera un umbral de bytes/segundo configurado, muy por encima de su media histórica | Media |
| Puerto remoto inusual | Conexión saliente a puertos poco comunes asociados a malware conocido (lista configurable) | Media |
| Muchas conexiones nuevas simultáneas | Un mismo proceso abre más de X conexiones nuevas en menos de Y segundos (posible C2/botnet) | Media |

- Cada alerta generada se guarda en tabla `alerts` con: timestamp, regla disparada, IP/proceso implicado, severidad, y un campo `resuelta` (booleano) para que el usuario pueda marcarla como revisada desde el dashboard.
- Empezar en **modo solo alerta** (sin bloqueo automático) — el bloqueo es una acción manual del usuario desde el dashboard (sección 4.5).

### 4.5 `firewall.py`
- Función `block_ip(ip: str)` que ejecuta:
  ```
  netsh advfirewall firewall add rule name="MonitorRed_Block_<ip>" dir=in action=block remoteip=<ip>
  netsh advfirewall firewall add rule name="MonitorRed_Block_<ip>" dir=out action=block remoteip=<ip>
  ```
  vía `subprocess.run(..., shell=True)`, requiere permisos de administrador (ya asumidos para toda la app).
- Función `unblock_ip(ip: str)` que elimina esas reglas por nombre.
- Endpoint en la API para que el botón del dashboard dispare esto. Confirmar en el frontend antes de ejecutar (evitar bloqueos accidentales).

### 4.6 `api.py` (Flask)
Endpoints mínimos:
- `GET /api/connections` → lista de conexiones activas actuales (JSON).
- `GET /api/alerts?resuelta=false` → alertas pendientes.
- `POST /api/alerts/<id>/resolver` → marcar alerta como revisada.
- `POST /api/block` (body: `{"ip": "..."}`) → bloquea IP.
- `POST /api/unblock` (body: `{"ip": "..."}`) → desbloquea IP.
- `GET /api/history?ip=...&desde=...&hasta=...` → consulta histórico filtrable.

### 4.7 Frontend (`static/`)
- Página única, sin frameworks pesados (HTML + JS vanilla o Alpine.js si se quiere algo reactivo simple).
- Secciones:
  1. **Conexiones activas**: tabla con auto-refresh cada 3-5s (fetch a `/api/connections`). Columnas: Proceso, PID, IP remota, País (bandera si es fácil), Puerto, Protocolo, Estado, Reputación (badge de color).
  2. **Alertas**: lista de tarjetas/tabla con severidad coloreada (rojo/naranja/amarillo), botón "Marcar revisada" y botón "Bloquear IP" si aplica.
  3. **Histórico**: filtro simple por IP o proceso, tabla de resultados.
- Diseño simple pero limpio, no hace falta nada elaborado en esta fase.

---

## 5. Esquema de base de datos (SQLite)

```sql
CREATE TABLE connections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    pid INTEGER,
    process_name TEXT,
    process_path TEXT,
    local_ip TEXT,
    local_port INTEGER,
    remote_ip TEXT,
    remote_port INTEGER,
    protocol TEXT,
    status TEXT
);

CREATE TABLE ip_info (
    ip TEXT PRIMARY KEY,
    country TEXT,
    city TEXT,
    abuse_score INTEGER,
    last_checked TEXT
);

CREATE TABLE traffic_stats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    window_start TEXT,
    window_end TEXT,
    local_ip TEXT,
    remote_ip TEXT,
    remote_port INTEGER,
    bytes_sent INTEGER,
    bytes_received INTEGER
);

CREATE TABLE alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    rule TEXT NOT NULL,
    severity TEXT NOT NULL,
    remote_ip TEXT,
    process_name TEXT,
    description TEXT,
    resuelta INTEGER DEFAULT 0
);
```

---

## 6. Configuración (`config.py`)

```python
DASHBOARD_PORT = 5000
POLL_INTERVAL_SECONDS = 3
ENABLE_PACKET_CAPTURE = False       # activar cuando Npcap esté instalado y confirmado
ABUSEIPDB_API_KEY = ""              # el usuario lo rellena si quiere reputación de IP
PORT_SCAN_THRESHOLD = 10            # puertos distintos
PORT_SCAN_WINDOW_SECONDS = 5
NEW_CONN_BURST_THRESHOLD = 20       # conexiones nuevas
NEW_CONN_BURST_WINDOW_SECONDS = 10
SUSPICIOUS_PORTS = [4444, 1337, 31337, 6667]  # ampliable
```

---

## 7. Plan de implementación por pasos (para ir iterando con Claude Code)

1. **Paso 1**: Crear estructura de carpetas + `requirements.txt` + `config.py`. Verificar que `psutil` corre en Windows y lista conexiones sin errores (script suelto de prueba).
2. **Paso 2**: Implementar `db.py` con creación de tablas si no existen, y funciones `insert_connection`, `get_active_connections`, etc.
3. **Paso 3**: Implementar `connections.py` con el loop de polling, guardando en BD. Probar que detecta conexiones reales abriendo el navegador.
4. **Paso 4**: Implementar `api.py` con Flask sirviendo `/api/connections` desde la BD. Probar con `curl` o navegador que devuelve JSON correcto.
5. **Paso 5**: Construir `static/index.html` + `dashboard.js` mínimo que pinte la tabla de conexiones activas con auto-refresh.
6. **Paso 6**: Implementar `enrichment.py` (geolocalización primero, sin API key) e integrarlo — mostrar país en la tabla.
7. **Paso 7**: Implementar `detection.py` con las reglas de la sección 6, guardando alertas en BD. Probar forzando un escenario (ej. hacer un escaneo de puertos con `nmap` desde otra máquina de la propia red contra el PC, si se tiene forma de probarlo).
8. **Paso 8**: Añadir sección de Alertas al dashboard.
9. **Paso 9**: Implementar `firewall.py` + endpoint de bloqueo + botón en dashboard, con confirmación.
10. **Paso 10 (opcional)**: Activar `packet_capture.py` con scapy para métricas de tráfico reales, una vez Npcap esté confirmado instalado.
11. **Paso 11**: Pulir README con instrucciones claras: requisitos (Python, Npcap si se usa captura, ejecutar como Administrador), cómo instalar dependencias (`pip install -r requirements.txt`), cómo arrancar (`python app/main.py`) y cómo acceder al dashboard.

---

## 8. Fuera de alcance en esta fase (para fases futuras)

- Monitoreo de toda la red doméstica (requiere el switch gestionable TL-SG105E + Raspberry Pi como sonda, ya definido en el plan general).
- Suricata/Zeek como motor de IDS (se evalúa integrar en fase de red completa, aquí las reglas son propias y simples).
- Notificaciones push/Telegram (se puede añadir después reutilizando la tabla `alerts`).
- Bloqueo automático sin confirmación del usuario.

---

## 9. Notas para Claude Code

- Priorizar que cada paso del plan de la sección 7 sea ejecutable y comprobable de forma aislada antes de pasar al siguiente (no implementar todo de golpe).
- Manejar siempre errores de permisos (`PermissionError`, `psutil.AccessDenied`) sin que la app se caiga — loggear y continuar.
- No hardcodear rutas absolutas de Windows; usar `os.path` / `pathlib` para portabilidad mínima.
- Dejar comentado claramente en el código dónde el usuario debe pegar su API key de AbuseIPDB si quiere activar esa función.
