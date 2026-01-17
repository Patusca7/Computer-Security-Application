import socket
import sys
import os
import errno
from datetime import datetime


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


def portas_validas(porta_inicial, porta_final):
    if porta_inicial < 0 or porta_inicial > 65535:
        print("O número da porta inicial tem de ser entre 0 e 65535")
        return False

    if porta_final < 0 or porta_final > 65535:
        print("O número da porta final tem de ser entre 0 e 65535")
        return False

    if porta_final < porta_inicial:
        print("O número da porta final tem de ser maior ou igual à porta inicial.")
        return False
    return True


def guardar_resultado(linhas):
    escolha = input("\nQuer guardar o resultado num ficheiro? (s/n): ").strip().lower()
    if escolha != "s":
        return
    nome = input("Nome do ficheiro: ").strip()
    if not nome:
        nome = "resultado.txt"
    with open(nome, "w", encoding="utf-8") as f:
        f.write("\n".join(linhas) + "\n")


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

def gerar_ips_mesma_rede(ip_inicial, ip_final):
    octetos_ip_inicial = ip_inicial.split(".")
    octetos_ip_final = ip_final.split(".")

    if octetos_ip_inicial[:3] != octetos_ip_final[:3]:
        print("Os IPs não pertencem à mesma rede.")
        lista_ips = None
        return lista_ips

    ultimo_octeto_inicial = int(octetos_ip_inicial[3])
    ultimo_octeto_final = int(octetos_ip_final[3])

    if ultimo_octeto_final <= ultimo_octeto_inicial:
        print("O último octeto final tem de ser maior do que o inicial.")
        lista_ips = None
        return lista_ips

    base_rede = ".".join(octetos_ip_inicial[:3])

    lista_ips = [
        f"{base_rede}.{octeto}"
        for octeto in range(ultimo_octeto_inicial, ultimo_octeto_final + 1)
    ]

    return lista_ips

def menu():
    while True:
        print("Escolha a opção que pretende:")
        print("1 - Fazer o scan a uma máquina")
        print("2 - Fazer o scan a várias máquinas")
        opcao = input("Escolha uma opção: ").strip()

        if opcao in ("1", "2"):
            return opcao
        print("Introduza 1 ou 2.")


def menu_1():
    linhas = []

    while True:
        ip = input("Introduza o IP que pretende fazer o scan: ").strip()
        if ip_valido(ip):
            break
        print("Introduza um IP válido.")

    if not ip_responde(ip):
        m = f"{ip} - IP não encontrado"
        print(m)
        linhas.append(m)
        return

    while True:
        try:
            porta_inicial= int(input("Introduza o número da porta inicial: "))
            porta_final = int(input("Introduza o número da porta final: "))
            
            if portas_validas(porta_inicial, porta_final):
                break
        except ValueError:
            print("Introduza apenas números.")

    msg = f"O scan vai começar no IP {ip}, nas portas {porta_inicial} a {porta_final}"
    print("\n" + msg + "\n")
    linhas.append(msg)
    linhas.append("")

    tempo_inicial = datetime.now()

    try:
        for porta in range(porta_inicial, porta_final + 1):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(1)
            resultado = sock.connect_ex((ip, porta))
            if resultado == 0:
                m = f"Porta {porta} aberta"
                print(m)
                linhas.append(m)
            sock.close()
    except KeyboardInterrupt:
        pass

    tempo_final = datetime.now()
    tempo_total = tempo_final - tempo_inicial

    linhas.append("")
    linhas.append(f"O Scan foi completo em {tempo_total}")
    print(f"\nO Scan foi completo em {tempo_total}")

    guardar_resultado(linhas)


def menu_2():
    linhas = []

    while True:
        ip_inicial = input("Introduza o IP inicial: ").strip()
        ip_final = input("Introduza o IP final: ").strip()

        if ip_valido(ip_inicial) and ip_valido(ip_final):
            lista_ips = gerar_ips_mesma_rede(ip_inicial, ip_final)
            if lista_ips is not None:
                break
        print("Intervalo de IPs inválido.")

    while True:
        try:
            porta_inicial = int(input("Introduza o número da porta inicial: "))
            porta_final = int(input("Introduza o número da porta final: "))

            if portas_validas(porta_inicial, porta_final):
                break
        except ValueError:
            print("Introduza apenas números.")

    msg = f"O scan vai começar nos IPs de {ip_inicial} a {ip_final}, nas portas {porta_inicial} a {porta_final}"
    print("\n" + msg + "\n")
    linhas.append(msg)
    linhas.append("")

    tempo_inicial = datetime.now()

    try:
        for ip in lista_ips:
            if not ip_responde(ip):
                m = f"{ip} - IP não encontrado"
                print(m)
                linhas.append(m)
                continue


            print(f"A analisar {ip}")
            linhas.append(f"A analisar {ip}")

            for porta in range(porta_inicial, porta_final + 1):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                socket.setdefaulttimeout(1)
                resultado = sock.connect_ex((ip, porta))
                if resultado == 0:
                    m = f"Porta {porta} aberta"
                    print(m)
                    linhas.append(m)
                sock.close()

    except KeyboardInterrupt:
        pass

    tempo_final = datetime.now()
    tempo_total = tempo_final - tempo_inicial

    linhas.append("")
    linhas.append(f"O Scan foi completo em {tempo_total}")
    print(f"\nO Scan foi completo em {tempo_total}")

    guardar_resultado(linhas)



def main():
    os.system('clear')
    os.system('figlet Port Scanner')

    print("\nO script pede o IP da máquina alvo do PortScanner e de seguida vai pedir a porta inicial do scan e a porta final.\n")

    option = menu()
    if option == "1":
        menu_1()
    else:
        menu_2()


if __name__ == "__main__":
    main()
