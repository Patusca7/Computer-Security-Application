import socket
import sys
import os
import errno
from datetime import datetime


def validar_ip(ip):
    partes = ip.split(".")

    if len(partes) != 4:
        return False

    for i, parte in enumerate(partes):
        if not parte.isdigit():
            return False

        numero = int(parte)

        if i == 0 or i == 3:
            if numero < 1 or numero > 255:
                return False
        else:
            if numero < 0 or numero > 255:
                return False
    return True


def validar_portas(porta_inicial, porta_final):
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


def ip_existe(ip):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    try:
        r = sock.connect_ex((ip, 1))
    finally:
        sock.close()

    if r == 0:
        return True
    if r == errno.ECONNREFUSED:
        return True

    return False


def menu():
    while True:
        print("Escolha a opção que pretende:")
        print("1 - Fazer o scan a uma máquina")
        print("2 - Fazer o scan a várias máquinas")
        option = input("Escolha uma opção: ").strip()

        if option in ("1", "2"):
            return option
        print("Introduza 1 ou 2.")


def menu_1():
    linhas = []

    while True:
        ip = input("Introduza o IP que pretende fazer o scan: ").strip()
        if validar_ip(ip):
            break
        print("Introduza um IP válido.")

    if not ip_existe(ip):
        m = f"{ip} - IP não encontrado"
        print(m)
        linhas.append(m)
        return

    while True:
        try:
            start_port = int(input("Introduza o número da porta inicial: "))
            final_port = int(input("Introduza o número da porta final: "))
            if validar_portas(start_port, final_port):
                break
        except ValueError:
            print("Introduza apenas números.")

    msg = f"O scan vai começar no IP {ip}, nas portas {start_port} a {final_port}"
    print("\n" + msg + "\n")
    linhas.append(msg)
    linhas.append("")

    time1 = datetime.now()

    try:
        for port in range(start_port, final_port + 1):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(1)
            result = sock.connect_ex((ip, port))
            if result == 0:
                m = f"Porta {port} aberta"
                print(m)
                linhas.append(m)
            sock.close()
    except KeyboardInterrupt:
        pass

    time2 = datetime.now()
    total_time = time2 - time1

    linhas.append("")
    linhas.append(f"O Scan foi completo em {total_time}")
    print(f"\nO Scan foi completo em {total_time}")

    guardar_resultado(linhas)


def menu_2():
    linhas = []

    while True:
        ip_inicial = input("Introduza o IP inicial: ").strip()
        ip_final = input("Introduza o IP final: ").strip()

        if validar_ip(ip_inicial) and validar_ip(ip_final):
            lista_ips = gerar_ips_mesma_rede(ip_inicial, ip_final)
            if lista_ips is not None:
                break
        print("Intervalo de IPs inválido.")

    while True:
        try:
            start_port = int(input("Introduza o número da porta inicial: "))
            final_port = int(input("Introduza o número da porta final: "))

            if validar_portas(start_port, final_port):
                break
        except ValueError:
            print("Introduza apenas números.")

    msg = f"O scan vai começar nos IPs de {ip_inicial} a {ip_final}, nas portas {start_port} a {final_port}"
    print("\n" + msg + "\n")
    linhas.append(msg)
    linhas.append("")

    time1 = datetime.now()

    try:
        for ip in lista_ips:
            if not ip_existe(ip):
                m = f"{ip} - IP não encontrado"
                print(m)
                linhas.append(m)
                continue


            print(f"A analisar {ip}")
            linhas.append(f"A analisar {ip}")

            for port in range(start_port, final_port + 1):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                socket.setdefaulttimeout(1)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    m = f"Porta {port} aberta"
                    print(m)
                    linhas.append(m)
                sock.close()

    except KeyboardInterrupt:
        pass

    time2 = datetime.now()
    total_time = time2 - time1

    linhas.append("")
    linhas.append(f"O Scan foi completo em {total_time}")
    print(f"\nO Scan foi completo em {total_time}")

    guardar_resultado(linhas)


def gerar_ips_mesma_rede(ip_inicial, ip_final):
    partes_ip_inicial = ip_inicial.split(".")
    partes_ip_final = ip_final.split(".")

    if partes_ip_inicial[:3] != partes_ip_final[:3]:
        print("Os IPs não pertencem à mesma rede.")
        lista_ips = None
        return lista_ips

    ultimo_octeto_inicial = int(partes_ip_inicial[3])
    ultimo_octeto_final = int(partes_ip_final[3])

    if ultimo_octeto_final <= ultimo_octeto_inicial:
        print("O último octeto final tem de ser maior do que o inicial.")
        lista_ips = None
        return lista_ips

    base_rede = ".".join(partes_ip_inicial[:3])

    lista_ips = [
        f"{base_rede}.{octeto}"
        for octeto in range(ultimo_octeto_inicial, ultimo_octeto_final + 1)
    ]

    return lista_ips


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
