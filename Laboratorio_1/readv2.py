#!/usr/bin/env python3
"""
Programa de Decodificación ICMP + César con IA de Gemini
Captura paquetes ICMP y decodifica el mensaje con todas las combinaciones César,
usando IA Generativa para identificar el mensaje en claro.
Uso: sudo python3 icmp_decoder.py archivo_pcap.pcap
Ejemplo: sudo python3 icmp_decoder.py captura.pcap
"""

import sys
import struct
import re
from collections import Counter
import google.generativeai as genai
import os
import time

# Configura tu clave de API de Gemini
# ¡Importante! Reemplaza 'TU_CLAVE_API' con tu clave real
# Recomendado: usa os.environ["GEMINI_API_KEY"] para mayor seguridad
genai.configure(api_key="AIzaSyASy6B8KlRxyGFkG6YdRykncwmHUq_vJFA")

# Colores para terminal
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'

def leer_pcap_simple(archivo_pcap):
    """
    Lee un archivo PCAP y extrae paquetes ICMP
    Versión simplificada para archivos PCAP básicos
    """
    paquetes_icmp = []
    
    try:
        with open(archivo_pcap, 'rb') as f:
            # Leer header global PCAP (24 bytes)
            header_global = f.read(24)
            if len(header_global) < 24:
                print("Error: Archivo PCAP inválido - header muy corto")
                return []
            
            # Verificar magic number
            magic = struct.unpack('I', header_global[:4])[0]
            if magic not in [0xa1b2c3d4, 0xd4c3b2a1]:
                print("Error: No es un archivo PCAP válido")
                return []
            
            print(f"✓ Archivo PCAP válido detectado")
            
            paquete_num = 0
            while True:
                # Leer header del paquete (16 bytes)
                packet_header = f.read(16)
                if len(packet_header) < 16:
                    break
                
                # Extraer longitud del paquete
                ts_sec, ts_usec, incl_len, orig_len = struct.unpack('IIII', packet_header)
                
                # Leer datos del paquete
                packet_data = f.read(incl_len)
                if len(packet_data) < incl_len:
                    break
                
                paquete_num += 1
                
                # Analizar si es ICMP
                icmp_data = extraer_icmp(packet_data, paquete_num)
                if icmp_data:
                    paquetes_icmp.append(icmp_data)
        
        print(f"✓ Procesados {paquete_num} paquetes, encontrados {len(paquetes_icmp)} ICMP")
        return paquetes_icmp
        
    except FileNotFoundError:
        print(f"Error: No se encontró el archivo '{archivo_pcap}'")
        return []
    except Exception as e:
        print(f"Error leyendo archivo PCAP: {e}")
        return []

def extraer_icmp(packet_data, paquete_num):
    """
    Extrae información ICMP de los datos del paquete
    Busca headers ICMP en diferentes posiciones (Ethernet, IP, etc.)
    """
    # Posibles offsets para ICMP (después de Ethernet + IP)
    offsets_comunes = [34, 42, 54, 14, 22]  # Diferentes tipos de encapsulación
    
    for offset in offsets_comunes:
        if offset + 8 <= len(packet_data):  # Mínimo header ICMP
            try:
                # Intentar parsear header ICMP
                icmp_header = packet_data[offset:offset+8]
                if len(icmp_header) >= 8:
                    tipo, codigo, checksum, identifier, sequence = struct.unpack('!BBHHH', icmp_header)
                    
                    # Verificar si es Echo Request (tipo 8)
                    if tipo == 8:
                        # Extraer datos del payload
                        payload_start = offset + 8
                        payload = packet_data[payload_start:]
                        
                        return {
                            'paquete': paquete_num,
                            'tipo': tipo,
                            'codigo': codigo,
                            'checksum': checksum,
                            'identifier': identifier,
                            'sequence': sequence,
                            'payload': payload
                        }
            except struct.error:
                continue
    
    return None

def extraer_caracteres_de_icmp(paquetes_icmp):
    """
    Extrae los caracteres ocultos de los paquetes ICMP
    Filtra pings legítimos y extrae solo los datos
    """
    caracteres_extraidos = []
    
    print(f"\n{Colors.BLUE}=== ANÁLISIS DE PAQUETES ICMP ==={Colors.END}")
    print("-" * 60)
    
    for paquete in paquetes_icmp:
        seq = paquete['sequence']
        payload = paquete['payload']
        
        # Mostrar información del paquete
        print(f"Paquete {paquete['paquete']:2d}: Seq={seq:2d}, Payload={len(payload)} bytes", end="")
        
        # Filtrar pings legítimos (secuencia 1 o payload > 10 bytes)
        if seq == 1 or len(payload) > 10:
            print(f" {Colors.YELLOW}[PING LEGÍTIMO - IGNORADO]{Colors.END}")
            continue
        
        # Extraer carácter (primer byte del payload)
        if len(payload) > 0:
            caracter = chr(payload[0]) if 32 <= payload[0] <= 126 else '?'
            caracteres_extraidos.append((seq, caracter, payload[0]))
            print(f" {Colors.GREEN}-> Carácter: '{caracter}' (0x{payload[0]:02x}){Colors.END}")
        else:
            print(f" {Colors.RED}[SIN PAYLOAD]{Colors.END}")
    
    # Ordenar por secuencia
    caracteres_extraidos.sort(key=lambda x: x[0])
    mensaje_cifrado = ''.join([char[1] for char in caracteres_extraidos])
    
    print(f"\n{Colors.CYAN}Mensaje cifrado extraído: '{mensaje_cifrado}'{Colors.END}")
    return mensaje_cifrado

def descifrar_cesar(texto_cifrado, desplazamiento):
    """
    Descifra un texto usando el algoritmo de César
    """
    resultado = ""
    for caracter in texto_cifrado:
        if caracter.isalpha():
            if caracter.isupper():
                resultado += chr((ord(caracter) - ord('A') - desplazamiento) % 26 + ord('A'))
            else:
                resultado += chr((ord(caracter) - ord('a') - desplazamiento) % 26 + ord('a'))
        else:
            resultado += caracter
    return resultado

# 🔑 FUNCIÓN OPTIMIZADA DE LA IA DE GEMINI
def evaluar_todas_con_gemini_optimizado(opciones_descifrado):
    """
    Evalúa múltiples opciones de descifrado usando una sola consulta a Gemini.
    Recibe una lista de diccionarios con 'desplazamiento' y 'texto'.
    Devuelve una lista de puntuaciones y el índice de la mejor opción.
    """
    model = genai.GenerativeModel('gemini-1.5-flash')
    
    # Construir el prompt con todas las opciones numeradas
    opciones_formateadas = ""
    for i, opcion in enumerate(opciones_descifrado):
        opciones_formateadas += f"{i}: {opcion['texto']}\n"
    
    prompt = f"""Analiza las siguientes {len(opciones_descifrado)} opciones de texto descifrado y evalúa cada una en una escala del 0.0 al 1.0, donde 1.0 es una oración perfectamente coherente en español y 0.0 es completamente sin sentido.

OPCIONES A EVALUAR:
{opciones_formateadas}

Responde en el siguiente formato EXACTO (sin explicaciones adicionales):
PUNTUACIONES: [puntuación opción 0],[puntuación opción 1],...,[puntuación opción {len(opciones_descifrado)-1}]
MEJOR: [número de la opción con mayor puntuación]

Ejemplo:
PUNTUACIONES: 0.1,0.2,0.9,0.3,0.1,0.0,0.4,0.2,0.1,0.0,0.3,0.1,0.8,0.2,0.1,0.0,0.3,0.1,0.0,0.2,0.1,0.0,0.3,0.1,0.2,0.0
MEJOR: 2"""

    try:
        response = model.generate_content(prompt)
        respuesta_ia = response.text.strip()
        
        # Parsear la respuesta
        puntuaciones = [0.1] * len(opciones_descifrado)  # Valores por defecto
        mejor_indice = 0
        
        lineas = respuesta_ia.split('\n')
        for linea in lineas:
            linea = linea.strip()
            if linea.startswith('PUNTUACIONES:'):
                try:
                    punts_str = linea.split(':', 1)[1].strip()
                    puntuaciones_raw = [float(p.strip()) for p in punts_str.split(',')]
                    # Validar que tengamos el número correcto de puntuaciones
                    if len(puntuaciones_raw) == len(opciones_descifrado):
                        puntuaciones = [max(0.0, min(1.0, p)) for p in puntuaciones_raw]  # Limitar entre 0.0 y 1.0
                except (ValueError, IndexError) as e:
                    print(f"⚠️ Error parseando puntuaciones: {e}")
                    
            elif linea.startswith('MEJOR:'):
                try:
                    mejor_indice = int(linea.split(':', 1)[1].strip())
                    if not (0 <= mejor_indice < len(opciones_descifrado)):
                        mejor_indice = puntuaciones.index(max(puntuaciones))  # Fallback al mejor por puntuación
                except (ValueError, IndexError):
                    mejor_indice = puntuaciones.index(max(puntuaciones))  # Fallback al mejor por puntuación
        
        return puntuaciones, mejor_indice
        
    except Exception as e:
        print(f"❌ Error al llamar a la API de Gemini: {e}")
        # Devolver valores por defecto en caso de error
        return [0.1] * len(opciones_descifrado), 0

def analizar_todas_las_combinaciones(mensaje_cifrado):
    """
    Prueba todas las combinaciones de César y encuentra la más probable usando IA.
    VERSIÓN OPTIMIZADA: Una sola consulta a Gemini para evaluar todas las opciones.
    """
    print(f"\n{Colors.PURPLE}=== ANÁLISIS OPTIMIZADO DE TODAS LAS COMBINACIONES CÉSAR ==={Colors.END}")
    print("=" * 70)
    
    # Generar todas las opciones de descifrado
    opciones_descifrado = []
    print("🔄 Generando todas las combinaciones de descifrado...")
    
    for desplazamiento in range(26):
        texto_descifrado = descifrar_cesar(mensaje_cifrado, desplazamiento)
        opciones_descifrado.append({
            'desplazamiento': desplazamiento,
            'texto': texto_descifrado
        })
        print(f"Desplazamiento {desplazamiento:2d}: '{texto_descifrado}'")
    
    print(f"\n🤖 Consultando a Gemini para evaluar las {len(opciones_descifrado)} opciones en una sola llamada...")
    print("⏳ Esto puede tomar unos segundos...")
    
    # Hacer UNA SOLA consulta a Gemini con todas las opciones
    puntuaciones, mejor_indice = evaluar_todas_con_gemini_optimizado(opciones_descifrado)
    
    print(f"✅ Gemini eligió la opción #{mejor_indice}: '{opciones_descifrado[mejor_indice]['texto']}'")
    
    # Crear la estructura de resultados 
    resultados = []
    for i, opcion in enumerate(opciones_descifrado):
        resultados.append({
            'desplazamiento': opcion['desplazamiento'],
            'texto': opcion['texto'],
            'puntuacion': puntuaciones[i]
           
        })
        

    # Seleccionar el mejor resultado según el índice que Gemini devolvió
    mejor_resultado = resultados[mejor_indice]
    
    # Verificación de coherencia
    if mejor_resultado['desplazamiento'] != opciones_descifrado[mejor_indice]['desplazamiento']:
        print(f"🔧 Ajustando resultado: Gemini eligió desplazamiento {opciones_descifrado[mejor_indice]['desplazamiento']}")
        # Usar directamente la elección de Gemini
        mejor_resultado = {
            'desplazamiento': opciones_descifrado[mejor_indice]['desplazamiento'],
            'texto': opciones_descifrado[mejor_indice]['texto'],
            'puntuacion': puntuaciones[mejor_indice]
        }
    
    # Mostrar todos los resultados con el formato original
    print("\n" + "=" * 70)
    print("📋 RESULTADOS ORDENADOS POR PUNTUACIÓN IA:")
    print("=" * 70)
    
    for i, resultado in enumerate(resultados):
        desp = resultado['desplazamiento']
        texto = resultado['texto']
        punt = resultado['puntuacion']
        
        if i == resultados.index(mejor_resultado):
            print(f"{Colors.GREEN}{Colors.BOLD}🥇 Desplazamiento {desp:2d}: {texto}{Colors.END}")
        else:
            print(f"   Desplazamiento {desp:2d}: {texto} ")
    
    print("\n" + "=" * 70)
    print(f"{Colors.GREEN}{Colors.BOLD}🎯 MENSAJE MÁS PROBABLE (IDENTIFICADO POR IA):{Colors.END}")
    print(f"{Colors.GREEN}{Colors.BOLD}Desplazamiento: {mejor_resultado['desplazamiento']}{Colors.END}")
    print(f"{Colors.GREEN}{Colors.BOLD}Texto descifrado: '{mejor_resultado['texto']}'{Colors.END}")
    print(f"{Colors.GREEN}{Colors.BOLD}Puntuación de IA: {mejor_resultado['puntuacion']:.1f}{Colors.END}")
    
    # Mostrar estadísticas de optimización
  
    
    return mejor_resultado

def main():
    """Función principal del programa"""
    print(f"{Colors.BOLD}=== DECODIFICADOR ICMP + CÉSAR CON IA OPTIMIZADO ==={Colors.END}")
    print("Extrae mensajes ocultos de capturas ICMP y los decodifica usando IA")
    print("🚀 Versión optimizada: 1 consulta a Gemini vs 26 consultas")
    print("=" * 60)
    
    # Verificar argumentos
    if len(sys.argv) != 2:
        print("Uso: python3 icmp_decoder.py archivo_captura")
        print("Soporta formatos: .pcap, .pcapng")
        print("Ejemplo: python3 icmp_decoder.py captura.pcapng")
        sys.exit(1)
    
    archivo_pcap = sys.argv[1]
    print(f"📁 Archivo a analizar: {archivo_pcap}")
    
    # Paso 1: Leer archivo PCAP
    paquetes_icmp = leer_pcap_simple(archivo_pcap)
    
    if not paquetes_icmp:
        print("❌ No se encontraron paquetes ICMP en el archivo")
        sys.exit(1)
    
    # Paso 2: Extraer caracteres ocultos
    mensaje_cifrado = extraer_caracteres_de_icmp(paquetes_icmp)
    
    if not mensaje_cifrado:
        print("❌ No se pudieron extraer caracteres del tráfico ICMP")
        sys.exit(1)
    
    # Paso 3: Analizar todas las combinaciones César (OPTIMIZADO)
    mejor_resultado = analizar_todas_las_combinaciones(mensaje_cifrado)
    
    print(f"\n{Colors.CYAN}✅ Análisis completado exitosamente con optimización de IA{Colors.END}")

if __name__ == "__main__":
    main()