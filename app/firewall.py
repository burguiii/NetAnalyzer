"""
Bloqueo/desbloqueo de IPs mediante el Firewall de Windows (netsh advfirewall).

Requiere que la app corra como Administrador (ya asumido para toda la app).
El bloqueo es SIEMPRE una accion manual disparada por el usuario desde el
dashboard, con confirmacion previa en el frontend.
"""

import ipaddress
import subprocess

_RULE_PREFIX = "MonitorRed_Block_"


def _valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def _rule_name(ip: str) -> str:
    return f"{_RULE_PREFIX}{ip}"


def block_ip(ip: str) -> tuple[bool, str]:
    """Crea reglas de firewall (entrada y salida) que bloquean la IP."""
    if not _valid_ip(ip):
        return False, "IP no valida."
    name = _rule_name(ip)
    try:
        for direction in ("in", "out"):
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "add", "rule",
                 f"name={name}", f"dir={direction}", "action=block",
                 f"remoteip={ip}"],
                check=True, capture_output=True, text=True,
            )
        return True, f"IP {ip} bloqueada en el firewall."
    except subprocess.CalledProcessError as e:
        return False, f"Error de netsh: {e.stderr or e.stdout}"
    except FileNotFoundError:
        return False, "netsh no disponible (¿no es Windows?)."


def unblock_ip(ip: str) -> tuple[bool, str]:
    """Elimina las reglas de firewall creadas para esa IP."""
    if not _valid_ip(ip):
        return False, "IP no valida."
    name = _rule_name(ip)
    try:
        subprocess.run(
            ["netsh", "advfirewall", "firewall", "delete", "rule",
             f"name={name}"],
            check=True, capture_output=True, text=True,
        )
        return True, f"IP {ip} desbloqueada."
    except subprocess.CalledProcessError as e:
        return False, f"Error de netsh: {e.stderr or e.stdout}"
    except FileNotFoundError:
        return False, "netsh no disponible (¿no es Windows?)."


def list_blocked() -> list[str]:
    """Devuelve las IPs actualmente bloqueadas por esta app."""
    try:
        out = subprocess.run(
            ["netsh", "advfirewall", "firewall", "show", "rule",
             f"name=all"],
            capture_output=True, text=True,
        ).stdout
    except Exception:
        return []
    ips = set()
    for line in out.splitlines():
        line = line.strip()
        if line.lower().startswith("rule name:") and _RULE_PREFIX in line:
            ips.add(line.split(_RULE_PREFIX, 1)[1].strip())
    return sorted(ips)
