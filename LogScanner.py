import os
from collections import Counter

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

def contar_e_mostrar(lista, titulo):
    contagem = Counter(lista)
    print(f"\n{titulo}")
    for valor, total in contagem.most_common():
        print(f"{valor}: {total}")
    print()
    return contagem

def guardar_ficheiro(texto):
    resposta = input("Guardar num ficheiro? (s/n): ").strip().lower()
    
    if resposta == "s":
        nome = input("Qual o nome do ficheiro: ").strip()
        with open(nome, "w", encoding="utf-8") as file:
            file.write(texto)
        print(f"Guardado em: {nome}\n")

def menu_ssh(ips, portas, users, motivos, datas, horas, hostnames, matriz):
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
    
    linhas = os.popen("grep -E 'Failed password|Invalid user' /var/log/auth.log").read().splitlines()

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

    with open("texto_formatado_ssh.txt", "w", encoding="utf-8") as file:
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
    linhas = os.popen(f"cat /var/log/apache2/access.log*").read().splitlines()
    
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
    
    with open("texto_formatado_apache.txt", "w", encoding="utf-8") as file:
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
    menu()


if __name__ == "__main__":
    main()
