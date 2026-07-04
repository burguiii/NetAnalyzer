"""
Punto de entrada del Monitor de Red Personal.

Arranca:
  1. La base de datos (crea tablas si no existen).
  2. El hilo de enriquecimiento de IPs (geo/reputacion).
  3. El hilo de muestreo de conexiones (psutil).
  4. La captura de paquetes (solo si esta activada en config).
  5. El servidor web del dashboard (bloqueante, hilo principal).

Ejecutar como Administrador:
    python -m app.main
o bien desde la carpeta app:
    python main.py
"""

import ctypes
import sys
import webbrowser
from threading import Timer

# Permitir ejecutar tanto "python -m app.main" como "python app/main.py"
if __package__ in (None, ""):
    import os
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from app import config, connections, db, enrichment, packet_capture
    from app import api
else:
    from . import config, connections, db, enrichment, packet_capture
    from . import api


def _is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def _banner():
    print("=" * 60)
    print("   MONITOR DE RED PERSONAL  ·  Fase 1")
    print("=" * 60)
    if not _is_admin():
        print("  AVISO: no se esta ejecutando como Administrador.")
        print("  Se veran solo las conexiones de tu usuario, no las de")
        print("  todos los procesos del sistema. Para vista completa,")
        print("  abre la terminal 'Como administrador' y vuelve a lanzar.")
        print("-" * 60)
    url = f"http://localhost:{config.DASHBOARD_PORT}"
    print(f"  Dashboard:  {url}")
    print(f"  (se abrira solo en tu navegador en unos segundos)")
    print("  Para detener: Ctrl + C en esta ventana.")
    print("=" * 60)


def main():
    _banner()
    db.init_db()
    enrichment.start()
    connections.start()
    packet_capture.start()

    # Abrir el navegador automaticamente al arrancar
    url = f"http://localhost:{config.DASHBOARD_PORT}"
    Timer(1.5, lambda: webbrowser.open(url)).start()

    try:
        api.run()
    except KeyboardInterrupt:
        print("\n[main] deteniendo... hasta luego.")


if __name__ == "__main__":
    main()
