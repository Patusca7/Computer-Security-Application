import os
import subprocess
import time
import getpass
import hashlib

VENV_PY = "./venv/bin/python"

def autenticar():
    """
    Autenticação simples para acesso à aplicação.
    """
    UTILIZADOR = "diogo"

    # password: python (hash SHA256)
    PASSWORD_HASH = "11a4a60b518bf24989d481468076e5d5982884626aed9faeb35b8576fcd223e1"

    os.system("figlet Autenticacao")
    print("Precisa de se autenticar para correr este código!")
    
    while True:
        user = input("Utilizador: ").strip()
        pwd = getpass.getpass("Password: ")

        pwd_hash = hashlib.sha256(pwd.encode()).hexdigest()

        if user == UTILIZADOR and pwd_hash == PASSWORD_HASH:
            print("\nLogin  com sucesso.\n")
            return True

        print("\nCredenciais inválidas. Tente novamente\n")


def run(script):
    r = subprocess.run(["sudo", "-E", VENV_PY, script], text=True)
    print(f"\n[exit code = {r.returncode}]")

def main():
    autenticar()
        
    while True:
        os.system("clear")
        os.system("figlet Menu")
        print("\nEscolha uma opção no menu:\n")
        print("1 - Port Scanner")
        print("2 - UDP Flood")
        print("3 - Syn Flood")
        print("4 - Log Scanner")
        print("5 - Chat Server")
        print("6 - Chat Client")
        print("7 - Port Knocking Server")
        print("8 - Port Knocking Client")
        print("9 - Password Manager")
        print("0 - Sair")

        op = input("> ").strip()

        match op:
            case "1":
                run("PortScanner.py")
            case "2":
                run("UdpFlood.py")
            case "3":
                os.system("sudo python3 SynFlood.py")
            case "4":
                run("LogScanner.py")
            case "5":
                run("ChatServer.py")
            case "6":
                run("ChatClient.py")
            case "7":
                run("PortKnocking_Server.py")
            case "8":
                run("PortKnocking_Client.py")
            case "9":
                run("PasswordManager.py")
            case "0":
                print("A sair.")
                break
            case _:
                print("Opção inválida.\n")
                time.sleep(0.5)

if __name__ == "__main__":
    main()
