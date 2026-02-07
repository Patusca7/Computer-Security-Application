"""
Exercício - PortScanner que permite detetar e listar que portos de rede se encontram disponíveis numa ou mais máquinas remotas;

Este módulo implementa um scanner de portas TCP com duas opções:
1) Scan a uma máquina (1 IP)
2) Scan a várias máquinas (intervalo de IPs na mesma rede /24)

Inclui:
- Validação de IPv4
- Validação de intervalo de portas
- Verificação simples se um IP responde (tentativa TCP)
- Possibilidade de guardar resultados em ficheiro

"""
import socket
import sys
import os
import time
import errno
import csv
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from datetime import datetime

PASTA_DOWNLOAD = "./download/portscanner/"
os.makedirs(PASTA_DOWNLOAD, exist_ok=True)

def ip_valido(ip):
    """
    Verifica se uma string corresponde a um endereço IPv4 válido.

    Regras:
    - 4 octetos separados por '.'
    - 1º e 4º octeto: 1..255
    - octetos intermédios: 0..255

    :param ip: Endereço IPv4 em string
    :return: True se válido, False caso contrário
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


def portas_validas(porta_inicial, porta_final):
    """
    Valida um intervalo de portas.

    :param porta_inicial: Porta inicial (int)
    :param porta_final: Porta final (int)
    :return: True se o intervalo for válido, False caso contrário
    """
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

def ip_responde(ip):
    """
    Testa se um IP aparenta responder, usando uma tentativa TCP para a porta 1.

    Considera o host "ativo" se:
    - connect_ex retorna 0 (ligação)
    - connect_ex retorna ECONNREFUSED (host respondeu mas recusou)

    :param ip: Endereço IPv4
    :return: True se aparenta responder, False caso contrário
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

def gerar_ips_mesma_rede(ip_inicial, ip_final):
    """
    Gera uma lista de IPs entre ip_inicial e ip_final assumindo rede /24 (mesmos 3 primeiros octetos).

    :param ip_inicial: IP inicial (string)
    :param ip_final: IP final (string)
    :return: Lista de IPs (list[str]) ou None se inválido
    """
    
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



def guardar_resultado(linhas):
    """
    Guarda o resultado do PortScanner em TXT, CSV e PDF usando o MESMO nome base.

    :param linhas: Lista de strings com o output do scan
    """
    
    escolha = input("\nQuer guardar o resultado em ficheiro? (s/n): ").strip().lower()
    if escolha != "s":
        return

    nome = input("Nome do ficheiro: ").strip()
    if not nome:
        print("Nome inválido.")
        return

    caminho_txt = os.path.join(PASTA_DOWNLOAD, f"{nome}.txt")
    caminho_csv = os.path.join(PASTA_DOWNLOAD, f"{nome}.csv")
    caminho_pdf = os.path.join(PASTA_DOWNLOAD, f"{nome}.pdf")

    with open(caminho_txt, "w", encoding="utf-8") as f:
        for linha in linhas:
            f.write(linha + "\n")

    import csv
    with open(caminho_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["linha"])

        for linha in linhas:
            writer.writerow([linha])

    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.pdfgen import canvas

        c = canvas.Canvas(caminho_pdf, pagesize=A4)
        width, height = A4

        y = height - 60
        c.setFont("Helvetica-Bold", 16)
        c.drawString(50, y, "Relatório de Port Scanner")

        y -= 30
        c.setFont("Helvetica", 10)

        for linha in linhas:
            if y < 60:
                c.showPage()
                y = height - 60
                c.setFont("Helvetica", 10)

            c.drawString(50, y, linha[:110])
            y -= 14

        c.save()

    except Exception as e:
        print(f"Erro ao gerar PDF: {e}")

    print("\nFicheiros gerados")
    time.sleep(1)

def menu():
    """
    Menu principal: escolhe entre scan a 1 máquina, scan a várias máquinas, ou sair.

    :return: Opção escolhida ("1", "2" ou "0")
    """
    while True:
        print("Escolha a opção que pretende:")
        print("1 - Fazer o scan a uma máquina")
        print("2 - Fazer o scan a várias máquinas")
        print("0 - Sair")
        opcao = input("Escolha uma opção: ").strip()

        if opcao in ("1", "2", "0"):
            return opcao
        print("Introduza 1, 2 ou 0.")


def menu_1():
    """
    Executa o scan a uma única máquina (1 IP), para um intervalo de portas TCP.

    :return: None
    """
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
    """
    Executa o scan a várias máquinas (intervalo de IPs na mesma rede /24),
    para um intervalo de portas TCP.

    :return: None
    """
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
    main()


def main():
    """
    Função principal:
    - limpa ecrã
    - mostra título
    - executa menu e chama o modo escolhido

    """
    while True:
    
        os.system('clear')
        os.system('figlet Port Scanner')

        print("\nO script pede o IP da máquina alvo do PortScanner e de seguida vai pedir a porta inicial do scan e a porta final.\n")

        option = menu()
    
        if option == "1":
            menu_1()
        elif option == "2":
            menu_2()
        else:
            break
        


if __name__ == "__main__":
    main()
