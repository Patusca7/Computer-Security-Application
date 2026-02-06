"""
Exercicio - Port knocking Servidor: Deverá o aluno configurar a firewall (iptables, ipchains) numa máquina Linux para testar o acesso por SSH após o funcionamento do client port knocking.

Este módulo configura uma firewall Linux (iptables) para implementar port knocking
e permitir uma janela temporária de acesso por SSH após uma sequência correta de portas.

Funcionalidades:
- Limpeza e configuração base da firewall (políticas e regras essenciais)
- Configuração da sequência de port knocking (3 knocks)
- Abertura temporária de SSH após sequência correta

"""
import os

PORTA_SSH = 22
TEMPO_ENTRE_KNOCKS = 5
TEMPO_SSH_ABERTO = 60

def limpar_firewall():
    """
    Limpa as regras existentes e define políticas padrão restritivas.

    - Faz flush (-F) e remove chains personalizadas (-X)
    - Define INPUT e FORWARD como DROP
    - Define OUTPUT como ACCEPT

    :return: None
    """
    os.system("iptables -F")
    os.system("iptables -X")
    os.system("iptables -P INPUT DROP")
    os.system("iptables -P FORWARD DROP")
    os.system("iptables -P OUTPUT ACCEPT")


def regras_basicas():
    """
    Adiciona regras essenciais para funcionamento normal do sistema.

    - Permite loopback (lo)
    - Permite tráfego de ligações estabelecidas/relacionadas (conntrack)
    - Permite ICMP (ex.: ping)

    :return: None
    """
    os.system("iptables -A INPUT -i lo -j ACCEPT")
    os.system("iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT")
    os.system("iptables -A INPUT -p icmp -j ACCEPT")


def configurar_port_knocking(porta1, porta2, porta3):
    """
    Configura a sequência de port knocking (3 portas) usando o módulo 'recent'.

    Sequência lógica:
    1) Knock na porta1 marca o IP como KNOCK1
    2) Knock na porta2, dentro do TEMPO_ENTRE_KNOCKS, marca como KNOCK2
    3) Knock na porta3, dentro do TEMPO_ENTRE_KNOCKS, marca como SSH_LIBERADO
    4) Permite SSH por TEMPO_SSH_ABERTO segundos se SSH_LIBERADO estiver válido

    :param porta1: Primeira porta da sequência (int)
    :param porta2: Segunda porta da sequência (int)
    :param porta3: Terceira porta da sequência (int)
    :return: None
    """
    # 1º knock
    os.system(f"iptables -A INPUT -p tcp --dport {porta1} -m recent --name KNOCK1 --set -j DROP")

    # 2º knock
    os.system(f"iptables -A INPUT -p tcp --dport {porta2} -m recent --name KNOCK1 --rcheck --seconds {TEMPO_ENTRE_KNOCKS} -m recent --name KNOCK2 --set -j DROP")

    # 3º knock
    os.system(f"iptables -A INPUT -p tcp --dport {porta3} -m recent --name KNOCK2 --rcheck --seconds {TEMPO_ENTRE_KNOCKS} -m recent --name SSH_LIBERADO --set -j DROP")

    # Abrir SSH temporariamente
    os.system(f"iptables -A INPUT -p tcp --dport {PORTA_SSH} -m recent --name SSH_LIBERADO --rcheck --seconds {TEMPO_SSH_ABERTO} -j ACCEPT")


def main():
    """
    Função principal.

    - Limpa o ecrã e mostra o título
    - Pede ao utilizador as 3 portas da sequência
    - Configura a firewall e ativa port knocking

    :return: None
    """
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
