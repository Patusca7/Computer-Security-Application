"""
Exercício - Analisar e processar ficheiros de log

Este módulo permite analisar logs de:
- Autenticação SSH (/var/log/auth.log)
- Servidor Web Apache (/var/log/apache2/access.log*)

Funcionalidades principais:
- Extração de IPs, datas, horas, utilizadores e motivos
- Contagem estatística dos campos
- Identificação do país de origem via geoiplookup
- Geração de ficheiros formatados
- Menus interativos para consulta

"""

import os
from collections import Counter
import csv
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas


BASE_ANALISE = "./analise_logs"
BASE_DOWNLOAD = "./download"
PASTA_FICHEIROS = os.path.join(BASE_ANALISE, "ficheiro")
PASTA_DOWNLOAD = os.path.join(BASE_DOWNLOAD, "logscanner")

os.makedirs(BASE_ANALISE, exist_ok=True)
os.makedirs(BASE_DOWNLOAD, exist_ok=True)
os.makedirs(PASTA_FICHEIROS, exist_ok=True)
os.makedirs(PASTA_DOWNLOAD, exist_ok=True)


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

def contar_e_mostrar(lista, titulo):
    """
    Conta ocorrências numa lista e mostra os resultados ordenados.

    :param lista: Lista de valores
    :param titulo: Título a mostrar no ecrã
    :return: Objeto Counter com as contagens
    """
    contagem = Counter(lista)
    print(f"\n{titulo}")
    for valor, total in contagem.most_common():
        print(f"{valor}: {total}")
    print()
    return contagem

def guardar_ficheiro(texto):
    """
    Guarda o conteúdo em TXT, CSV e PDF usando o mesmo nome.
    """
    resposta = input("Guardar em ficheiro? (s/n): ").strip().lower()
    if resposta != "s":
        return
    while True:
        nome = input("Nome do ficheiro: ").strip()
        if not nome:
            print("Nome inválido.")
        break

    caminho_txt = os.path.join(PASTA_DOWNLOAD, f"{nome}.txt")
    caminho_csv = os.path.join(PASTA_DOWNLOAD, f"{nome}.csv")
    caminho_pdf = os.path.join(PASTA_DOWNLOAD, f"{nome}.pdf")

    with open(caminho_txt, "w", encoding="utf-8") as f:
        f.write(texto)

    import csv
    with open(caminho_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["valor", "total"])

        for linha in texto.splitlines():
            linha = linha.strip()
            if not linha:
                continue

            if ":" in linha:
                valor, total = linha.split(":", 1)
                writer.writerow([valor.strip(), total.strip()])
            else:
                writer.writerow([linha, ""])

    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.pdfgen import canvas

        c = canvas.Canvas(caminho_pdf, pagesize=A4)
        width, height = A4

        y = height - 60
        c.setFont("Helvetica-Bold", 16)
        c.drawString(50, y, "Relatório de Segurança")

        y -= 30
        c.setFont("Helvetica", 10)

        for linha in texto.splitlines():
            if y < 60:
                c.showPage()
                y = height - 60
                c.setFont("Helvetica", 10)

            c.drawString(50, y, linha[:110])
            y -= 14

        c.save()

    except Exception as e:
        print(f"Erro ao gerar PDF: {e}")

    print("\nFicheiros guardados")
    print(f"\n{caminho_csv}")
    

def menu_ssh(ips, portas, users, motivos, datas, horas, hostnames, matriz):
    """
    Menu de consulta estatística para logs SSH.

    Permite listar IPs, portas, users, motivos, países, datas, horas e hostnames.

    :param ips: Lista de IPs
    :param portas: Lista de portas
    :param users: Lista de utilizadores
    :param motivos: Lista de motivos
    :param datas: Lista de datas
    :param horas: Lista de horas
    :param hostnames: Lista de hostnames
    :param matriz: Estrutura com registos organizados por IP
    :return: None
    """
    while True:
        print("\nVerificar as listagens:")
        print("1 - IP")
        print("2 - Porta")
        print("3 - User")
        print("4 - Motivo")
        print("5 - Pais")
        print("6 - Data")
        print("7 - Hora")
        print("8 - Hostname")
        print("0 - Voltar")

        op = input("Opção: ").strip()

        if op == "0":
            break

        if op == "1":
            texto = "IP"
            contagem = Counter(ips)

        elif op == "2":
            texto = "PORTAS"
            contagem = Counter(portas)

        elif op == "3":
            texto = "USERS"
            contagem = Counter(users)

        elif op == "4":
            texto = "MOTIVOS"
            contagem = Counter(motivos)

        elif op == "5":
            texto = "PAISES"
            paises_tentativas = []
            for ip, info in matriz.items():
                paises_tentativas += [info["pais"]] * len(info["registos"])
            contagem = Counter(paises_tentativas)

        elif op == "6":
            texto = "DATA"
            contagem = Counter(datas)

        elif op == "7":
            texto = "HORAS"
            contagem = Counter(horas)

        elif op == "8":
            texto = "HOSTNAMES"
            contagem = Counter(hostnames)

        else:
            print("Opção inválida.")
            continue

        os.system("clear")
        os.system(f"figlet {texto}")

        if texto == "HORAS":
            print("A mostrar as 20 primeiras horas:\n")

        resultado = ""
        for valor, total in contagem.most_common(20):
            print(f"{valor}: {total}")
            resultado += f"{valor}: {total}\n"

        guardar_ficheiro(resultado)

def menu_apache(ips, status_codes, metodos, paths, datas, horas, matriz):
    """
    Menu de consulta estatística para logs Apache.

    Permite listar IPs, códigos HTTP, métodos, paths, países, datas e horas.

    :param ips: Lista de IPs
    :param status_codes: Lista de códigos HTTP
    :param metodos: Lista de métodos HTTP
    :param paths: Lista de paths
    :param datas: Lista de datas
    :param horas: Lista de horas
    :param matriz: Estrutura com registos organizados por IP
    :return: None
    """
    while True:
        print("\nVerificar as listagens:")
        print("1 - IP")
        print("2 - Status")
        print("3 - Metodo")
        print("4 - Path")
        print("5 - Pais")
        print("6 - Data")
        print("7 - Hora")
        print("0 - Voltar")

        op = input("Opção: ").strip()

        if op == "0":
            break

        if op == "1":
            texto = "IP"
            contagem = Counter(ips)

        elif op == "2":
            texto = "STATUS"
            contagem = Counter(status_codes)

        elif op == "3":
            texto = "METODO"
            contagem = Counter(metodos)

        elif op == "4":
            texto = "PATH"
            contagem = Counter(paths)

        elif op == "5":
            texto = "PAISES"
            paises_tentativas = []
            for ip, info in matriz.items():
                paises_tentativas += [info["pais"]] * len(info["registos"])
            contagem = Counter(paises_tentativas)

        elif op == "6":
            texto = "DATA"
            contagem = Counter(datas)

        elif op == "7":
            texto = "HORAS"
            contagem = Counter(horas)

        else:
            print("Opção inválida.")
            continue

        os.system("clear")
        os.system(f"figlet {texto}")

        if texto == "HORAS":
            print("A mostrar as 20 primeiras horas:\n")
        elif texto == "DATA":
            print("A mostrar as 20 primeiras datas:\n")
        elif texto == "PATH":
            print("A mostrar os 20 primeiros paths:\n")

        resultado = ""
        for valor, total in contagem.most_common(20):
            print(f"{valor}: {total}")
            resultado += f"{valor}: {total}\n"

        guardar_ficheiro(resultado)

def analisar_ssh():
    """
    Analisa o ficheiro de logs SSH (/var/log/auth.log).

    Extrai tentativas de login falhadas e utilizadores inválidos,
    identifica países de origem e gera estatísticas.
    """
    
    linhas = os.popen("grep -hE 'Failed password|Invalid user' /var/log/auth.log* 2>/dev/null").read().splitlines()
    
    datas = []
    horas = []
    hostnames = []
    motivos = []
    users = []
    ips = []
    portas = []

    matriz = {}

    for linha in linhas:
        partes = linha.split()
        if len(partes) < 10:
            continue

        # Timestamp
        data, hora = partes[0].split(".")[0].split("T", 1)

        # Hostname
        hostname = partes[1]

        # Motivo + user
        if "Failed password" in linha:
            motivo = "Failed password"
            try:
                user = linha.split(" for ", 1)[1].split(" from ", 1)[0].strip()
            except:
                user = "UNKNOWN_FP"

        elif "Invalid user" in linha:
            motivo = "Invalid user"
            try:
                user = linha.split("Invalid user ", 1)[1].split()[0].strip()
            except:
                user = "UNKNOWN_IU"
        else:
            motivo = "UNKNOWN"
            user = "UNKNOWN"

        # IP
        try:
            ip = linha.split(" from ", 1)[1].split()[0]
            if not ip_valido(ip):
                continue
        except:
            continue
        
        # Porta
        try:
            porta = linha.split(" port ", 1)[1].split()[0]
        except:
            porta = "UNKNOWN"

        datas.append(data)
        horas.append(hora)
        hostnames.append(hostname)
        motivos.append(motivo)
        users.append(user)
        ips.append(ip)
        portas.append(porta)

        reg = {
            "data": data,
            "hora": hora,
            "hostname": hostname,
            "motivo": motivo,
            "user": user,
            "ip": ip,
            "porta": porta
        }

        if ip not in matriz:
            matriz[ip] = {"pais": None, "registos": []}

        matriz[ip]["registos"].append(reg)

   
    for ip in matriz:
        if not ip_valido(ip):
            matriz[ip]["pais"] = "UNKNOWN"
            continue
    
        resultado_geo = os.popen(f"geoiplookup {ip}").read()
        try:
            pais_nome = resultado_geo.split(":")[1].split(",")[-1].strip()
            if not pais_nome:
                pais_nome = "UNKNOWN"
        except:
            pais_nome = "UNKNOWN"

        matriz[ip]["pais"] = pais_nome

    caminho_ssh = os.path.join(PASTA_FICHEIROS, "texto_formatado_ssh.txt")
    with open(caminho_ssh, "w", encoding="utf-8") as file:
        for ip, info in matriz.items():
            pais = info["pais"]
            for r in info["registos"]:
                file.write(
                    f"Data: {r['data']} Hora: {r['hora']} "
                    f"Hostname: {r['hostname']} "
                    f"Motivo: {r['motivo']} "
                    f"User: {r['user']} "
                    f"IP: {r['ip']} "
                    f"Porta: {r['porta']} "
                    f"Pais: {pais}\n"
                )

    print("\nFicheiro 'texto_formatado.txt' criado.")
    print(f"Total de linhas: {len(ips)}")

    menu_ssh(ips, portas, users, motivos, datas, horas, hostnames, matriz)


def analisar_apache():    
    """
    Analisa os ficheiros de acesso do Apache (/var/log/apache2/access.log*).

    Extrai IPs, métodos HTTP, paths, códigos de estado, datas e horas,
    identifica países de origem e gera estatísticas.
    """
    
    linhas = os.popen("zcat -f /var/log/apache2/access.log* 2>/dev/null").read().splitlines()
    
    
    datas = []
    horas = []
    ips = []
    metodos = []
    paths = []
    status_codes = []
    
    matriz = {}
    
    for linha in linhas:
    
        partes = linha.split()
        if len(partes) < 9:
            continue
        #IP
        ip = partes[0]
    
        if not ip_valido(ip):
            continue
    
        if "[" not in linha or "]" not in linha:
            continue
        
        timestamp = linha.split("[", 1)[1].split("]", 1)[0]
    
        # Separar data/hora
        parte_datahora = timestamp.split(" ", 1)[0] 
    
        if ":" not in parte_datahora:
            continue
    
        data, hora = parte_datahora.split(":", 1)     
 
        if '"' not in linha:
            continue

        # Metodo + path
        try:
            request = linha.split('"')[1]            
            req_partes = request.split()
            metodo = req_partes[0] if len(req_partes) > 0 else "UNKNOWN"
            path = req_partes[1] if len(req_partes) > 1 else "UNKNOWN"
        except:
            metodo = "UNKNOWN"
            path = "UNKNOWN"

        # Status
        try:
            depois_request = linha.split('"')[2].strip().split()
            status = depois_request[0] if len(depois_request) > 0 else "UNKNOWN"
        except:
            status = "UNKNOWN"
    
        ips.append(ip)
        datas.append(data)
        horas.append(hora)
        metodos.append(metodo)
        paths.append(path)
        status_codes.append(status)
    
        reg = {
            "data": data,
            "hora": hora,
            "metodo": metodo,
            "path": path,
            "status": status,
            "ip": ip
        }
    
        if ip not in matriz:
            matriz[ip] = {"pais": None, "registos": []}
    
        matriz[ip]["registos"].append(reg)

    for ip in matriz:
        if not ip_valido(ip):
            matriz[ip]["pais"] = "UNKNOWN"
            continue
    
        resultado_geo = os.popen(f"geoiplookup {ip}").read()
        try:
            pais_nome = resultado_geo.split(":")[1].split(",")[-1].strip()
            if not pais_nome:
               pais_nome = "UNKNOWN"
        except:
            pais_nome = "UNKNOWN"
    
        matriz[ip]["pais"] = pais_nome
        
    caminho_apache = os.path.join(PASTA_FICHEIROS, "texto_formatado_apache.txt")
    with open(caminho_apache, "w", encoding="utf-8") as file:
        for ip, info in matriz.items():
            pais = info["pais"]
            for r in info["registos"]:
                file.write(
                    f"Data: {r['data']} Hora: {r['hora']} "
                    f"Metodo: {r['metodo']} Path: {r['path']} "
                    f"Status: {r['status']} IP: {r['ip']} "
                    f"Pais: {pais}\n"
                )
    
    print("\nFicheiro 'texto_formatado_apache.txt' criado.")
    print(f"\nTotal de acessos: {len(ips)}")

    menu_apache(ips, status_codes, metodos, paths, datas, horas, matriz)
    
def menu():
    """
    Menu principal do programa.
    """
    os.system('clear')
    os.system('figlet Log Scanner')
    while True:
        print("Escolha a opção que pretende:")
        print("1 - Analisar logs SSH")
        print("2 - Analisar logs APACHE")
        print("0 - Sair")

        opcao = input("Escolha uma opção: ").strip()

        if opcao == "1":
            analisar_ssh()
        elif opcao == "2":
            analisar_apache()
        elif opcao == "0":
            print("A sair")
            break
        else:
            print("Introduza 1, 2 ou 0.\n")


def main():
    """
    Função principal do programa.
    """
    menu()


if __name__ == "__main__":
    main()
