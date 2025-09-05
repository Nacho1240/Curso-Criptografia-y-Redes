#!/usr/bin/env python3
"""
Programa de Cifrado César con parámetros de línea de comandos
Uso: python3 Cesar.py "texto a cifrar" desplazamiento
"""

import sys

def cifrar_cesar(texto, desplazamiento):
    """
    Cifra un texto usando el algoritmo de César
    
    Args:
        texto (str): El texto a cifrar
        desplazamiento (int): Número de posiciones a desplazar
    
    Returns:
        str: El texto cifrado
    """
    resultado = ""
    
    for caracter in texto:
        if caracter.isalpha():
            # Para letras mayúsculas
            if caracter.isupper():
                resultado += chr((ord(caracter) - ord('A') + desplazamiento) % 26 + ord('A'))
            # Para letras minúsculas
            else:
                resultado += chr((ord(caracter) - ord('a') + desplazamiento) % 26 + ord('a'))
        else:
            # Mantener caracteres que no son letras
            resultado += caracter
    
    return resultado

def main():
    """Función principal del programa"""
    # Verificar que se proporcionen los argumentos correctos
    if len(sys.argv) != 3:
        print("Uso: python3 Cesar.py \"texto a cifrar\" desplazamiento")
        print("Ejemplo: python3 Cesar.py \"criptografia y seguridad en redes\" 9")
        sys.exit(1)
    
    # Obtener los parámetros de la línea de comandos
    texto = sys.argv[1]
    
    try:
        desplazamiento = int(sys.argv[2])
    except ValueError:
        print("Error: El desplazamiento debe ser un número entero.")
        print("Ejemplo: python3 Cesar.py \"criptografia y seguridad en redes\" 9")
        sys.exit(1)
    
    # Cifrar el texto
    texto_cifrado = cifrar_cesar(texto, desplazamiento)
    
    # Mostrar el resultado
    print(f"Texto original: {texto}")
    print(f"Desplazamiento: {desplazamiento}")
    print(f"Texto cifrado:  {texto_cifrado}")

if __name__ == "__main__":
    main()