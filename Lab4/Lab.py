from Crypto.Cipher import DES, AES, DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import binascii



#Inicializacion

def ajuste_size(clave, size_requerido):
    clave_bytes = clave.encode('utf-8')
    longitud_actual = len(clave_bytes)
    if longitud_actual < size_requerido:
        bytesfaltantes = size_requerido - longitud_actual
        bytesaleatorios = get_random_bytes(bytesfaltantes)
        clave_nueva = clave_bytes + bytesaleatorios
    elif longitud_actual > size_requerido:
        clave_nueva = clave_bytes[:size_requerido]
    else:
        clave_nueva = clave_bytes
    
    return clave_nueva


def Ajuste_iv(iv, size_requerido):
    iv_bytes = iv.encode('utf-8')
    size_actual = len(iv_bytes)

    if size_actual < size_requerido:
        bytesfaltantes = size_requerido - size_actual
        bytesaleatorios = get_random_bytes(bytesfaltantes)
        VI_nuevo = iv_bytes + bytesaleatorios
    elif size_actual > size_requerido:
        VI_nuevo = iv_bytes[:size_requerido]
    else:
        VI_nuevo = iv_bytes
    return VI_nuevo

#DES
def cifrar_DES(texto, clave, iv):
    clave_ajustada = ajuste_size(clave, 8)
    iv_nuevo = Ajuste_iv(iv, 8)
    cipher = DES.new(clave_ajustada, DES.MODE_CBC, iv_nuevo)
    texto_bytes = texto.encode('utf-8')
    texto_con_padding = pad(texto_bytes, DES.block_size)
    texto_cifrado = cipher.encrypt(texto_con_padding)
    
    print(f"\n   Texto original: {texto}")
    print(f"   Texto cifrado DES (base64): {binascii.b2a_base64(texto_cifrado).decode().strip()}")
    print('Descifrando DES.......')
    
    cipher_dec = DES.new(clave_ajustada, DES.MODE_CBC, iv_nuevo)
    padding = cipher_dec.decrypt(texto_cifrado)  
    texto_decifrado = unpad(padding, DES.block_size).decode('utf-8')
    
    print(f"   Texto descifrado: {texto_decifrado}")
    
    return texto_cifrado, texto_decifrado
    


#3DES
def cifrar_3DES(texto,clave,iv):
    clave_ajustada = ajuste_size(clave, 24)
    iv_nuevo = Ajuste_iv(iv,8)
    cipher = DES3.new(clave_ajustada, DES3.MODE_CBC, iv_nuevo)
    texto_bytes = texto.encode('utf-8')
    texto_paddeado = pad(texto_bytes, DES3.block_size)
    texto_cifrado = cipher.encrypt(texto_paddeado)
    print(f"\n   Texto original: {texto}")
    
    print(f"   Texto cifrado 3DES (base64): {binascii.b2a_base64(texto_cifrado).decode().strip()}")
    print('Descifrando 3DES.......')
    cipher_dec = DES3.new(clave_ajustada, DES3.MODE_CBC, iv_nuevo)
    padding = cipher_dec.decrypt(texto_cifrado)
    texto_decifrado = unpad(padding, DES3.block_size).decode('utf-8')
    print(f"   Texto descifrado: {texto_decifrado}")




def cifrar_AES256(texto,clave,iv):
    clave_ajustada = ajuste_size(clave, 32)
    iv_nuevo = Ajuste_iv(iv,16)
    cipher = AES.new(clave_ajustada, AES.MODE_CBC, iv_nuevo)
    texto_bytes = texto.encode('utf-8')
    texto_padeado = pad(texto_bytes, AES.block_size)
    texto_cifrado = cipher.encrypt(texto_padeado)
    print(f"\n   Texto original: {texto}")
    
    print(f"   Texto cifrado AES256 (base64): {binascii.b2a_base64(texto_cifrado).decode().strip()}")
    print('Descifrando aes256.....')
    cipher_dec = AES.new(clave_ajustada, AES.MODE_CBC, iv_nuevo)
    padding = cipher_dec.decrypt(texto_cifrado)
    texto_decifrado = unpad(padding, AES.block_size).decode('utf-8')
    print(f"   Texto descifrado: {texto_decifrado}")



def main():

    #Solicitud de Parametros
    print('='*70)
    print("Laboratorio 4")
    print('='*70)
    claveDES = input("ingrese la clave para algoritmo DES: ")
    ivDES = input(" ingrese el vector de inicializacion (IV o VI)para el algoritmo DES:")
    clave3DES = input("ingrese la clave para algoritmo 3DES: ")
    iv3DES = input(" ingrese el vector de inicializacion (IV o VI)para el algoritmo 3DS:")
    claveAES = input("ingrese la clave para algoritmo AES256: ")
    ivAES = input(" ingrese el vector de inicializacion (IV o VI)para el algoritmo AES256:")
    texto = input("Ingrese el texto a cifrar: ")
    print("-"*70)

    try:
        print('Cifrando......')
        cifrar_DES(texto,claveDES, ivDES)
        cifrar_3DES(texto,clave3DES, iv3DES)
        cifrar_AES256(texto,claveAES, ivAES)

        
    except Exception as e:
        print(f"error durante el proceso: {str(e)}")

if _name=="main_":
    print("\n Iniciando Laboratorio 4.....")
    print("\n Requiete: pip install pycryptodome")
main()