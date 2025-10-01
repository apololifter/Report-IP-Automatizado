import requests
import json
import ipaddress
import subprocess

with open("lista.txt", "r") as archivo:
    for ip in archivo:
        ip = ip.strip()
        print(ip)
        while True:
            try:
                ipaddress.ip_address(ip)   # valida IPv4 o IPv6
                break
            except ValueError:
                    print("IP inválida. Intenta de nuevo.")
        # Defining the api-endpoint
        url = 'https://api.abuseipdb.com/api/v2/check'

        querystring = {
            'ipAddress': ip,
            'maxAgeInDays': '30'
        }

        headers = {
            'Accept': 'application/json',
            'Key': '{api-key}'
        }

        response = requests.request(method='GET', url=url, headers=headers, params=querystring)

        # Formatted output
        decodedResponse = json.loads(response.text)
        print(json.dumps(decodedResponse, sort_keys=True, indent=4))

        abuse_percentage = decodedResponse['data']['abuseConfidenceScore'] 
        if (abuse_percentage == 0):
            print(f"La ip {ip} no esta reportada")
        elif(abuse_percentage >= 90) :
            with open("resultado_ips_reportadas2.txt", "a") as archivo:
                archivo.write(ip+"\n")
            print("Archivo 'mi_archivo.txt' creado exitosamente.")


subprocess.run("sort -u resultado_ips_reportadas2.txt >> ips_a_reportar.txt", shell=True)
