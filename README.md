# Check Malicious IPs

Este repositorio permite validar una lista de IPs contra **AbuseIPDB** y **VirusTotal**, generando un reporte final con las IPs maliciosas.

---

## Requisitos

- Python 3.x
- Biblioteca `requests`

```bash
pip install requests
Configuración
Crear un archivo lista.txt con las IPs a revisar (una IP por línea, IPv4 o IPv6).

Ejecutar los scripts:

bash
Copiar código
python check_abuseipdb.py && python check_virustotal.py
El resultado final se guarda en ips_a_reportar.txt.

Cómo funciona
Valida cada IP de la lista (IPv4 o IPv6).

AbuseIPDB: marca IPs con abuseConfidenceScore >= 90.

VirusTotal: marca IPs si se cumple alguna de las siguientes condiciones:

abuseConfidenceScore >= 90

2 o más motores reportan "malicious"

reputación negativa

votos de la comunidad indican maliciosa

Combina todas las IPs maliciosas en ips_a_reportar.txt.

Archivos
Archivo	Descripción
lista.txt	IPs de entrada (una por línea)
check_abuseipdb.py	Consulta AbuseIPDB
check_virustotal.py	Consulta VirusTotal
ips_a_reportar.txt	IPs maliciosas reportadas

Ejemplo de ips_a_reportar.txt
ruby
Copiar código
1.2.3.4  # abuseConfidenceScore: 95 (AbuseIPDB)
5.6.7.8  # virus_total: 3 motores detectaron "malicious"
2001:0db8::1  # reputación negativa
Notas
Si ips_a_reportar.txt queda vacío, puede que las IPs estén limpias o las API keys sean incorrectas.

Para procesar muchas IPs, considera usar batches o agregar rate-limiting, ya que ambas APIs tienen límites.

