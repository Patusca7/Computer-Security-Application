import os

PORTA_SSH = 22
TEMPO_ENTRE_KNOCKS = 5
TEMPO_SSH_ABERTO = 60

def limpar_firewall():
    os.system("iptables -F")
    os.system("iptables -X")
    os.system("iptables -P INPUT DROP")
    os.system("iptables -P FORWARD DROP")
    os.system("iptables -P OUTPUT ACCEPT")


def regras_basicas():
    os.system("iptables -A INPUT -i lo -j ACCEPT")
    os.system("iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT")
    os.system("iptables -A INPUT -p icmp -j ACCEPT")


def configurar_port_knocking(porta1, porta2, porta3):
    # 1º knock
    os.system(f"iptables -A INPUT -p tcp --dport {porta1} -m recent --name KNOCK1 --set -j DROP")

    # 2º knock
    os.system(f"iptables -A INPUT -p tcp --dport {porta2} -m recent --name KNOCK1 --rcheck --seconds {TEMPO_ENTRE_KNOCKS} -m recent --name KNOCK2 --set -j DROP")

    # 3º knock
    os.system(f"iptables -A INPUT -p tcp --dport {porta3} -m recent --name KNOCK2 --rcheck --seconds {TEMPO_ENTRE_KNOCKS} -m recent --name SSH_LIBERADO --set -j DROP")

    # Abrir SSH temporariamente
    os.system(f"iptables -A INPUT -p tcp --dport {PORTA_SSH} -m recent --name SSH_LIBERADO --rcheck --seconds {TEMPO_SSH_ABERTO} -j ACCEPT")


def main():
    os.system("clear")
    os.system("figlet PortKnocking Server")
    while True:
        try:
            porta_1 = int(input("Introduza a porta 1: ").strip())
            porta_2 = int(input("Introduza a porta 2: ").strip())
            porta_3 = int(input("Introduza a porta 3: ").strip())
            break
        except ValueError:
            print("Erro: as portas devem ser números inteiros.")
        
        
    print("A configurar firewall com port knocking")
    limpar_firewall()
    regras_basicas()
    configurar_port_knocking(porta_1, porta_2, porta_3)
    print("Port knocking ativo.")
    print(f"Sequência: {porta_1} -> {porta_2} -> {porta_3}")
    print(f"SSH aberto por {TEMPO_SSH_ABERTO} segundos após sequência correta.")


if __name__ == "__main__":
    main()
