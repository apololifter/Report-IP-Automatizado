# IP Reputation Checker

Verifica la reputación de IPs usando **AbuseIPDB** y **VirusTotal** y genera un listado de IPs maliciosas.

---

## Requisitos

- Python 3.8+
- Librería `requests`
```bash
pip install requests
API keys:

ABUSEIPDB_KEY

VIRUSTOTAL_KEY

Uso
Crear lista.txt con las IPs (una por línea).

Exportar tus API keys en la terminal:

bash
Copiar código
export ABUSEIPDB_KEY="tu_key_abuseipdb"
export VIRUSTOTAL_KEY="tu_key_virustotal"
Ejecutar los scripts:

bash
Copiar código
python check_abuseipdb.py
python check_virustotal.py
El resultado final se guarda en ips_a_reportar.txt.

Cómo funciona
Valida cada IP (IPv4 o IPv6).

AbuseIPDB: marca IPs con abuseConfidenceScore >= 90.

VirusTotal: marca IPs si cumple alguna de estas condiciones:

abuseConfidenceScore >= 90

+2 motores reportan “malicious”

reputación negativa

votos de la comunidad reportan maliciosa

Combina todas las IPs maliciosas en ips_a_reportar.txt.

Archivos
lista.txt → IPs de entrada

check_abuseipdb.py → consulta AbuseIPDB

check_virustotal.py → consulta VirusTotal

ips_a_reportar.txt → IPs maliciosas reportadas

Notas
No subir tus API keys al repositorio.

Respeta los límites de las APIs para evitar bloqueos.

markdown
Copiar código

Si quieres, puedo hacer **una versión aún más visual y “GitHub friendly”** usando **badges** y resalt
