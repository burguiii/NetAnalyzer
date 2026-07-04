"""
PLANTILLA de secretos.

Para activar la reputación de IPs:
  1. Copia este archivo y renómbralo a "config_secret.py"
     (en la misma carpeta app/).
  2. Pega tu clave de AbuseIPDB entre las comillas de abajo.
     La consigues gratis en https://www.abuseipdb.com/account/api

El archivo "config_secret.py" está en .gitignore, así que tu clave real
NUNCA se sube a Git. Este ejemplo se queda vacío a propósito.

(La app funciona igual sin clave; solo que sin verificar reputación.)
"""

ABUSEIPDB_API_KEY = ""
