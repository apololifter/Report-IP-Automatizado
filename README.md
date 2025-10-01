ChatGPT dijo:
check-malicious-ips README

Rápido y al grano: este repo chequea una lista de IPs contra AbuseIPDB y VirusTotal y genera ips_a_reportar.txt con las IPs que parecen maliciosas. No hace magia, sólo te ahorra copiar/pegar resultados.

Requisitos
pip install requests

Instalación (rápido)

Clona el repo.

Instala la dependencia arriba.

Variables de entorno (obligatorias)

Uso

Crea lista.txt con las IPs (una por línea). IPv4 o IPv6 — tranquilo, ambos sirven.

Ejecuta los scripts:

python check_abuseipdb.py && python check_virustotal.py


El resultado final queda en ips_a_reportar.txt.

Qué hace (sin vueltas)

Valida cada IP (IPv4 o IPv6).

AbuseIPDB: marca la IP si abuseConfidenceScore >= 90.

VirusTotal: marca la IP si se cumple cualquiera de:

abuseConfidenceScore >= 90

≥ 2 motores detectan “malicious”

reputación negativa

votos de la comunidad indican malicioso

Combina todas las IPs detectadas y las escribe en ips_a_reportar.txt.

Formato de archivos

lista.txt — entrada: lista de IPs, una por línea.
Ejemplo:

1.2.3.4
2001:0db8::1


check_abuseipdb.py — consulta AbuseIPDB.

check_virustotal.py — consulta VirusTotal.

ips_a_reportar.txt — salida: IPs marcadas como maliciosas (una por línea).

Ejemplo de salida
# ips_a_reportar.txt
1.2.3.4  # abuseConfidenceScore: 95 (AbuseIPDB)
5.6.7.8  # virus_total: 3 motores detectaron "malicious"
2001:0db8::1  # reputación negativa

Si no ves nada en ips_a_reportar.txt, probablemente las IPs están limpias o las API keys son inválidas. Revisa las variables de entorno.

Para procesar muchas IPs, hazlo en batches o añade rate-limiting — ambas APIs tienen límites.
