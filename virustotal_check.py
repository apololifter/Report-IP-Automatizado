import requests
import json
import ipaddress
import subprocess

API_KEY = "{api-key}"

with open("lista.txt", "r") as archivo:
    for ip in archivo:
        ip = ip.strip()
        # Validar IP
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            print(f"IP inválida: {ip}")
            continue

        # Endpoint de VirusTotal
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {
            "accept": "application/json",
            "x-apikey": API_KEY
        }

        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            print(f"No se pudo obtener información para {ip}")
            continue

        decodedResponse = response.json()

        # ====== Parámetros clave ======
        abuse_score = decodedResponse['data'].get('attributes', {}).get('abuseConfidenceScore', 0)
        last_analysis_stats = decodedResponse['data'].get('attributes', {}).get('last_analysis_stats', {})
        reputation = decodedResponse['data'].get('attributes', {}).get('reputation', 0)
        total_votes = decodedResponse['data'].get('data', {}).get('total_votes', decodedResponse['data'].get('total_votes', {}))
        last_analysis_date = decodedResponse['data'].get('attributes', {}).get('last_analysis_date', 0)

        # ====== Lógica para decidir si es maliciosa ======
        es_maliciosa = False

        # 1. Score de abuso alto
        if abuse_score >= 90:
            es_maliciosa = True

        # 2. Motores que reportan malicioso
        if last_analysis_stats.get("malicious", 0) >= 2:
            es_maliciosa = True

        # 3. Reputación negativa
        if reputation < 0:
            es_maliciosa = True

        # 4. Votos de la comunidad
        if total_votes.get("malicious", 0) >= 1:
            es_maliciosa = True

        # ====== Resultado ======
        if es_maliciosa:
            print(f"La IP {ip} es maliciosa ✅")
            with open("resultado_ips_reportadas1.txt", "a") as archivo_resultado:
                archivo_resultado.write(ip + "\n")
        else:
            print(f"La IP {ip} no está reportada ❌")


subprocess.run("sort -u resultado_ips_reportadas1.txt >> ips_a_reportar.txt", shell=True)
