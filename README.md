# 🛡️ Monitor de Red Personal — Fase 1

Una app sencilla para **ver qué está haciendo tu PC en la red**: qué programas
se conectan a Internet, a qué IPs y países, por qué puertos, y detectar
comportamientos sospechosos — todo desde un **dashboard web local y bonito**.

> Esta primera fase monitoriza **solo tu propio PC** (Windows). El monitoreo de
> toda la red doméstica llegará en una fase posterior.

![vista](https://img.shields.io/badge/plataforma-Windows-blue) ![python](https://img.shields.io/badge/python-3.10%2B-green)

---

## ✨ Qué hace

- **Conexiones en vivo**: tabla con auto-refresh de proceso, PID, IP remota,
  país (con banderita), puerto, protocolo, estado y reputación.
- **Geolocalización** automática de las IPs remotas (gratis, sin configurar nada).
- **Reputación** de IPs vía AbuseIPDB (opcional, requiere una API key gratuita).
- **Alertas** automáticas: escaneos de puertos, IPs con mala reputación,
  procesos en carpetas sospechosas, picos de conexiones, puertos de malware…
- **Histórico** buscable por IP o proceso.
- **Bloqueo de IP** con un clic (crea una regla en el Firewall de Windows).

---

## 🚀 Instalación rápida

### 1. Requisitos
- **Windows 10/11**
- **Python 3.10 o superior** — descárgalo en https://www.python.org/downloads/
  (marca la casilla *"Add Python to PATH"* durante la instalación).

### 2. Instalar dependencias
Abre una terminal en la carpeta del proyecto y ejecuta:

```powershell
pip install -r requirements.txt
```

### 3. Ejecutar **como Administrador** (recomendado)
Para ver las conexiones de *todos* los procesos (no solo los tuyos) y poder
bloquear IPs, la app necesita permisos de administrador:

1. Pulsa **Inicio**, escribe `PowerShell`.
2. Clic derecho → **Ejecutar como administrador**.
3. Ve a la carpeta del proyecto y lanza:

```powershell
python -m app.main
```

El dashboard se abrirá **solo** en tu navegador en `http://localhost:5000`.
Para detenerlo, pulsa `Ctrl + C` en la terminal.

> Si lo ejecutas sin administrador también funciona, pero verás solo las
> conexiones de tu usuario.

---

## ⚙️ Configuración (opcional)

Todo se ajusta en [`app/config.py`](app/config.py):

| Opción | Para qué sirve |
|---|---|
| `DASHBOARD_PORT` | Puerto del dashboard (por defecto 5000). |
| `POLL_INTERVAL_SECONDS` | Cada cuántos segundos se leen las conexiones. |
| `ABUSEIPDB_API_KEY` | Pega aquí tu API key para activar la reputación de IPs. |
| `ENABLE_PACKET_CAPTURE` | Activa la captura de tráfico real (necesita Npcap). |
| `SUSPICIOUS_PORTS` | Lista de puertos considerados peligrosos. |

### Activar reputación de IPs (AbuseIPDB)
1. Crea una cuenta gratis en https://www.abuseipdb.com/account/api
2. Genera una API key (**APIv2**, 80 caracteres).
3. Copia `app/config_secret.example.py` como **`app/config_secret.py`** y pega
   tu clave en `ABUSEIPDB_API_KEY`.

   > `config_secret.py` está en `.gitignore`: tu clave **nunca se sube a Git**.
   > Como alternativa, puedes definir la variable de entorno `ABUSEIPDB_API_KEY`
   > (tiene prioridad sobre el archivo).

### Activar captura de tráfico (avanzado)
La medición de bytes enviados/recibidos necesita **Npcap**:
1. Instala Npcap desde https://npcap.com/ (marca *"WinPcap API-compatible mode"*).
2. Descomenta `scapy` en `requirements.txt` y ejecuta `pip install -r requirements.txt`.
3. Pon `ENABLE_PACKET_CAPTURE = True` en `app/config.py`.

---

## 🔐 Subir el proyecto a Git de forma segura

Tu clave de AbuseIPDB vive en `app/config_secret.py`, que está listado en
`.gitignore`, así que **no se subirá**. Para publicar el proyecto:

```powershell
cd E:\python\AnalizadorRed
git init
git add .
git status          # comprueba que config_secret.py NO aparece en la lista
git commit -m "Monitor de red - Fase 1"
```

Quien clone el repo solo tiene que copiar `config_secret.example.py` a
`config_secret.py` y poner su propia clave (o dejarlo vacío para usar la app
sin reputación).

> Si alguna vez ves `app/config_secret.py` en `git status`, **NO hagas commit**:
> revisa que `.gitignore` existe y contiene esa línea.

---

## ⚠️ Notas importantes

- **El antivirus / Windows Defender puede avisar** de que la app inspecciona la
  red o modifica el firewall. **No es un virus**: es el comportamiento normal de
  una herramienta de monitorización. Puedes añadir una excepción si hace falta.
- El bloqueo de IPs **nunca es automático**: siempre lo confirmas tú desde el
  dashboard.
- Los datos se guardan localmente en `data/monitor.db` (SQLite). Puedes borrarlo
  para empezar de cero; se recrea al arrancar.

---

## 📂 Estructura del proyecto

```
AnalizadorRed/
├── app/
│   ├── main.py            # Arranca todo
│   ├── connections.py     # Lee conexiones activas (psutil)
│   ├── enrichment.py      # Geolocalización + reputación de IPs
│   ├── detection.py       # Reglas de detección de anomalías
│   ├── firewall.py        # Bloqueo de IPs (netsh)
│   ├── packet_capture.py  # Captura de tráfico (opcional, scapy)
│   ├── db.py              # Base de datos SQLite
│   ├── api.py             # API REST (Flask)
│   └── config.py          # Configuración
├── static/                # Dashboard web (HTML/CSS/JS)
├── data/                  # Base de datos (se crea sola)
├── requirements.txt
└── README.md
```

---

## 🆘 Problemas comunes

| Síntoma | Solución |
|---|---|
| "python no se reconoce…" | Reinstala Python marcando *Add to PATH*. |
| La tabla está vacía | Abre el navegador y visita alguna web para generar conexiones. |
| No veo procesos del sistema | Ejecuta la terminal **como administrador**. |
| El puerto 5000 está ocupado | Cambia `DASHBOARD_PORT` en `app/config.py`. |
| No aparece país / reputación | La geo tarda unos segundos; la reputación necesita API key. |
