🔍 check-malicious-ips
Una herramienta rápida y eficiente para identificar direcciones IP maliciosas
Combina la potencia de AbuseIPDB y VirusTotal en un solo flujo de trabajo

🚀 Descripción Rápida
Este script automatiza la verificación de listas de IPs contra AbuseIPDB y VirusTotal, generando un archivo ips_a_reportar.txt con las IPs que muestran indicios de actividad maliciosa. ¡Sin complicaciones, solo resultados!

📋 Prerrequisitos
bash
pip install requests
⚙️ Configuración
1. Clonar el repositorio
bash
git clone https://github.com/tu-usuario/check-malicious-ips.git
cd check-malicious-ips
2. Variables de Entorno (Obligatorias)

🛠️ Uso
1. Preparar la lista de IPs
Crea lista.txt con las IPs a verificar:

txt
1.2.3.4
2001:0db8::1
5.6.7.8
2. Ejecutar la verificación
bash
python check_abuseipdb.py && python check_virustotal.py
📊 Criterios de Detección
🔴 AbuseIPDB
abuseConfidenceScore ≥ 90

🔵 VirusTotal
abuseConfidenceScore ≥ 90 o

≥ 2 motores detectan "malicious" o

Reputación negativa o

Votos de comunidad indican malicioso

📁 Estructura de Archivos
text
check-malicious-ips/
├── 📄 lista.txt              # Entrada: IPs a verificar
├── ⚡ check_abuseipdb.py      # Consulta AbuseIPDB
├── 🔍 check_virustotal.py    # Consulta VirusTotal
├── 📄 ips_a_reportar.txt     # Salida: IPs maliciosas detectadas
└── 📄 README.md
📝 Ejemplo de Salida
ips_a_reportar.txt:

txt
1.2.3.4          # abuseConfidenceScore: 95 (AbuseIPDB)
5.6.7.8          # 3 motores detectaron "malicious" (VirusTotal)
2001:0db8::1     # reputación negativa (VirusTotal)
💡 Notas Importantes
⚠️ Si ips_a_reportar.txt está vacío:

Las IPs pueden estar limpias

Revisa que las API keys sean válidas

Verifica el formato de lista.txt

📈 Para listas grandes de IPs:

Procesa en lotes (batches)

Respeta los límites de rate-limiting de las APIs

Considera añadir delays entre consultas

🎯 Características
✅ Soporte completo para IPv4 e IPv6
✅ Validación automática de formato de IP
✅ Resultados combinados y consolidados
✅ Fácil integración en flujos de trabajo existentes

