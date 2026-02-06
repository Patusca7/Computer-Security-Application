import os
import subprocess
import time

VENV_PY = "./venv/bin/python"

def run(script):
    r = subprocess.run(["sudo", "-E", VENV_PY, script], text=True)
    print(f"\n[exit code = {r.returncode}]")

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
