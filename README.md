# REDFORT

RedFort es una herramienta automatizada de pentesting diseñada para simplificar y agilizar diversas tareas de seguridad informática. Permite ejecutar herramientas populares como Nmap, Hashcat, TheHarvester, msfvenom, Hydra y más.

## Características

- **Enumeración Automatizada**: Ejecución de escaneos con Nmap y recopilación de información OSINT.
- **Generación de Payloads y Reverse Shells**: Crea payloads utilizando msfvenom.
- **Cracking de Hashes**: Usa Hashcat para crackear hashes utilizando listas de palabras.
- **CheatSheets**: Acceso a hojas de referencia rápida.
- **Herramientas de Active Directory**: Enumeración y análisis de usuarios en Active Directory.
- **Ataques de Fuerza Bruta**: Utiliza Hydra para ataques de fuerza bruta.
- **Escáner de Subdominios**: Enumeración de subdominios de un dominio objetivo.
- **Generación de Reportes**: Crea reportes detallados de las actividades realizadas.

## Dependencias

Este script Utiliza las siguientes herramientas y dependencias:
  - Nmap
  - Hashcat
  - TheHarvester
  - msfvenom (Metasploit Framework)
  - Hydra
  - Python3
  - Sublist3r

## Instalación

Para instalar RedFort, simplemente clona este repositorio y ejecuta el script. 
El proceso puede tomar un tiempo, dependiendo de las dependencias/herramientas que te falten.

```bash
git clone https://github.com/Garbox0/RedFort
cd RedFort
chmod +x RedFort.sh
./RedFort.sh
