"""
Exercicio - Cliente PortKnocking: Elaborar um client port knocking para abertura de ligação de login por SSH a uma máquina Linux. 

Este módulo implementa um cliente de port knocking que:
- Solicita ao utilizador o IP do servidor e o utilizador SSH
- Envia uma sequência de knocks para as portas configuradas no servidor
- Estabelece uma ligação SSH após a sequência correta

"""

import os
import time

TEMPO_ENTRE_KNOCKS = 0.7   # segundos

def portas_validas(porta):
    """
    Valida um número de porta TCP.

    :param porta: Número da porta (int)
    :return: True se a porta for válida, False caso contrário
    """
    if porta < 0 or porta > 65535:
        print("O número da porta tem de ser entre 0 e 65535")
        return False
    return True

def ip_valido(ip):
    """
    Verifica se uma string corresponde a um endereço IPv4 válido.

    :param ip: Endereço IP em formato string
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

def main():
    """
    Função principal do cliente de Port Knocking.

    - Limpa o ecrã e mostra o título
    - Solicita o IP do servidor e o utilizador SSH
    - Pede a quantidade de portas e a sequência de knocks
    - Envia a sequência usando netcat (nc)
    - Inicia a ligação SSH após a sequência
    """
    os.system("clear")
    os.system("figlet Cliente PortKnocking")

    while True:
        endereco_servidor = input("Introduza o IP do servidor: ").strip()
        if ip_valido(endereco_servidor):
            break
        print("IP inválido. Tente novamente.")
            
    while True:
        utilizador_ssh = input("Introduza o utilizador SSH: ").strip()
        if utilizador_ssh:
            break
        print("Utilizador inválido. Tente novamente.")
    
    while True:
        try:
            quantidade_portas = int(input("Quantas portas definiu no servidor? "))
            if quantidade_portas > 0:
                break
            print("O número de portas tem de ser maior que zero.")
        except ValueError:
            print("Introduza apenas números.")

    lista_portas = []

    for i in range(quantidade_portas):
        while True:
            try:
                porta = int(input(f"Introduza a porta {i + 1}: "))
                if portas_validas(porta):
                    lista_portas.append(porta)
                    break
            except ValueError:
                print("Introduza apenas números.")
    print("\nA iniciar port knocking\n")

    for porta in lista_portas:
        print(f"[KNOCK] Porta {porta}")
        os.system(f"nc -z -w 1 {endereco_servidor} {porta}")
        time.sleep(TEMPO_ENTRE_KNOCKS)

    print("\nSequência enviada com sucesso")
    print("A ligar ao ssh")
    os.system(f"ssh {utilizador_ssh}@{endereco_servidor}")

if __name__ == "__main__":
    main()
