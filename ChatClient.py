"""
Exercicio - Chat, parte do cliente 

Este módulo implementa o cliente de um sistema de chat cifrado que:
- Estabelece ligação TCP com o servidor
- Realiza handshake criptográfico (RSA + AES)
- Permite autenticação por username
- Envia e recebe mensagens cifradas
- Suporta múltiplas sessões, downloads e comandos interativos

"""
import os
import socket
import struct
import base64
import readline
import sys
import threading
import queue

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes

HOST = "192.168.1.244"
PORTA = 12345
TAMANHO_BUFFER = 4096
FICHEIRO_CHAVE_PUBLICA = "./chaves/chat/servidor_publica.pem"
BASE_DOWNLOAD = "./download"
PASTA_CHAT = os.path.join(BASE_DOWNLOAD, "chat")

os.makedirs(BASE_DOWNLOAD, exist_ok=True)
os.makedirs(PASTA_CHAT, exist_ok=True)

print_lock = threading.Lock()
esperando_resposta = threading.Event()

def print_sem_estragar_prompt(linha):
    """
    Imprime texto no ecrã sem interferir com o prompt interativo.

    :param linha: Texto a imprimir
    """
    with print_lock:
        buffer_atual = readline.get_line_buffer()
        sys.stdout.write("\r\033[K")
        sys.stdout.write(linha + "\n")
        sys.stdout.write("> " + buffer_atual)
        sys.stdout.flush()


def enviar_pacote(ligacao, dados):
    """
    Envia um pacote precedido do seu tamanho (4 bytes).

    :param ligacao: Socket TCP
    :param dados: Dados em bytes
    """

    ligacao.sendall(struct.pack("!I", len(dados)) + dados)

def receber_n_bytes(ligacao, num_bytes):
    """
    Recebe exatamente N bytes de um socket.

    :param ligacao: Socket TCP
    :param num_bytes: Número de bytes a receber
    :return: Bytes recebidos
    """

    buffer = b""
    while len(buffer) < num_bytes:
        parte = ligacao.recv(num_bytes - len(buffer))
        if not parte:
            raise ConnectionError("Ligação fechada.")
        buffer += parte
    return buffer

def receber_pacote(ligacao):
    """
    Recebe um pacote completo (tamanho + dados).

    :param ligacao: Socket TCP
    :return: Dados recebidos
    """
    tamanho_mensagem_bytes = receber_n_bytes(ligacao, 4)   #Ler o tamanho da mensagem
    tamanho_mensagem = struct.unpack("!I", tamanho_mensagem_bytes)[0]   #Converter em Int
    mensagem = receber_n_bytes(ligacao, tamanho_mensagem)  #Ler exatamente esses n bytes
    return mensagem
        
def comando_resposta(texto):
    """
    Verifica se um comando espera resposta do servidor.

    :param texto: Comando introduzido
    :return: True se esperar resposta, False caso contrário
    """

    if not texto:
        return False
    op = texto.split()[0].upper()
    return op in {"LIST", "GET", "VIEW", "OPEN", "NEW", "INVITE", "DELETE", "DOWNLOAD"}


#AES
def cifrar_aes(chave, mensagem):
    """
    Cifra dados com AES em modo EAX.

    :param chave: Chave AES
    :param mensagem: Mensagem em bytes
    :return: Pacote cifrado
    """

    cifra = AES.new(chave, AES.MODE_EAX)
    texto_cifrado, tag = cifra.encrypt_and_digest(mensagem)
    # nonce_len(2) + nonce | tag_len(2) + tag | ct_len(4) + ct
    pacote_cifrado = (struct.pack("!H", len(cifra.nonce)) + cifra.nonce + struct.pack("!H", len(tag)) + tag + struct.pack("!I", len(texto_cifrado)) + texto_cifrado)
        
    return pacote_cifrado

def decifrar_aes(chave, pacote):
    """
    Decifra um pacote cifrado com AES EAX.

    :param chave: Chave AES
    :param pacote: Pacote cifrado
    :return: Mensagem original em bytes
    """

    posicao = 0
    tamanho_nonce_bytes = pacote[posicao:posicao+2]
    tamanho_nonce = struct.unpack("!H", tamanho_nonce_bytes)[0]
    posicao += 2

    nonce = pacote[posicao:posicao+tamanho_nonce]
    posicao += tamanho_nonce

    tamanho_tag_bytes = pacote[posicao:posicao+2]
    tamanho_tag = struct.unpack("!H", tamanho_tag_bytes)[0]
    posicao += 2

    tag = pacote[posicao:posicao+tamanho_tag]
    posicao += tamanho_tag

    tamanho_texto_bytes = pacote[posicao:posicao+4]
    tamanho_texto = struct.unpack("!I", tamanho_texto_bytes)[0]
    posicao += 4

    texto_cifrado = pacote[posicao:posicao+tamanho_texto]

    cifra = AES.new(chave, AES.MODE_EAX, nonce=nonce)
    mensagem = cifra.decrypt(texto_cifrado)
    cifra.verify(tag)

    return mensagem

#RSA
def carregar_chave_publica_servidor():
    """
    Carrega a chave pública RSA do servidor.

    :return: Objeto RSA public key
    """
    with open(FICHEIRO_CHAVE_PUBLICA, "rb") as f:
        return RSA.import_key(f.read())

#Cliente
def criar_socket_cliente(host, porta):
    """
    Cria e estabelece ligação TCP ao servidor.

    :param host: Endereço do servidor
    :param porta: Porta TCP
    :return: Socket ligado
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, porta))
    return s

def fazer_handshake(ligacao, chave_publica_servidor):
    """
    Realiza handshake criptográfico com o servidor.

    - Gera chave AES
    - Envia-a cifrada com RSA
    - Aguarda confirmação cifrada

    :return: Chave AES da sessão
    """
    chave = get_random_bytes(16)
    cifra_rsa = PKCS1_OAEP.new(chave_publica_servidor) # Prepara o RSA com a chave pública do servidor
    chave_aes_cifrada = cifra_rsa.encrypt(chave) # Cifra a chave AES com a pública do servidor

    enviar_pacote(ligacao, chave_aes_cifrada)

    confirmacao = decifrar_aes(chave, receber_pacote(ligacao)).decode(errors="ignore")
    if "handshake_ok" not in confirmacao:
        raise RuntimeError("Handshake falhou.")
    return chave

def tratar_msg(resposta, username):
    """
    Processa mensagens de broadcast.

    :return: (remetente, mensagem)
    """
    try:
        _, nome_sessao, remetente, texto_msg = resposta.split(" ", 3)
        texto_msg = texto_msg.strip()
        if remetente == username:
            return  ("Eu", texto_msg)
        return (remetente, texto_msg)
    except ValueError:
        return ("Servidor", resposta)
        
def recetor(socket_cliente, chave, fila, username):
    """
    Thread responsável por receber mensagens do servidor.

    :param socket_cliente: Socket TCP
    :param chave: Chave AES
    :param fila: Queue de mensagens
    :param username: Username local
    """

    while True:
        try:
            pacote = receber_pacote(socket_cliente)
            texto = decifrar_aes(chave, pacote).decode(errors="ignore").strip()

            if texto.startswith("MSG "):
                remetente, texto_msg = tratar_msg(texto, username)
                if remetente == "Eu":
                    continue
                print_sem_estragar_prompt(f"{remetente}: {texto_msg}")
                continue
                
            if esperando_resposta.is_set():
                fila.put(texto)
            else:
                print_sem_estragar_prompt(f"Servidor: {texto}")
                
        except Exception:
            fila.put(None)
            break

def parse_list_map(texto):
    """Cria mapa índice -> nome a partir de LIST."""
    m = {}
    for linha in (texto or "").splitlines():
        linha = linha.strip()
        if ")" not in linha:
            continue
        esq, dir = linha.split(")", 1)
        if esq.strip().isdigit() and dir.strip():
            m[esq.strip()] = dir.strip()
    return m


def reescrever_comando(comando, mapa, comando_padrao="OPEN"):
    """Permite usar índices numéricos em comandos."""
    
    comando = (comando or "").strip()
    if not comando:
        return comando

    partes = comando.split()

    if len(partes) == 1 and partes[0].isdigit():
        if partes[0] in mapa:
            return f"{comando_padrao} {mapa[partes[0]]}"
        return comando

    op = partes[0].upper()

    if op in {"OPEN", "GET", "VIEW", "DELETE", "DOWNLOAD"}:
        if len(partes) == 2 and partes[1].isdigit() and partes[1] in mapa:
            partes[1] = mapa[partes[1]]
            return " ".join(partes)

    if op == "INVITE":
        if len(partes) == 3 and partes[1].isdigit() and partes[1] in mapa:
            partes[1] = mapa[partes[1]]
            return " ".join(partes)

    return comando


def chat_loop(socket_cliente, chave, username):
    """
    Loop principal do chat interativo.
    """

    mapa_sessoes = {}

    try:
        pacote_help = receber_pacote(socket_cliente)
        help_txt = decifrar_aes(chave, pacote_help).decode(errors="ignore")
        if help_txt.strip():
            print("Servidor:", help_txt.strip())
    except Exception:
        pass

    fila = queue.Queue()
    t = threading.Thread(target=recetor, args=(socket_cliente, chave, fila, username), daemon=True)
    t.start()

    sys.stdout.write("> ")
    sys.stdout.flush()
    
    while True:
        try:
            while True:
                msg = fila.get_nowait()
                if msg is None:
                    print("O Servidor desligou.")
                    return
                
                if msg.strip():
                    print_sem_estragar_prompt(f"Servidor: {msg.strip()}")
        except queue.Empty:
            pass

        texto = input().strip()

        if texto.lower() in ("sair", "exit", "quit"):
            break
        if not texto:
            continue
        
        print_sem_estragar_prompt(f"Eu: {texto}")

        texto_enviar = reescrever_comando(texto, mapa_sessoes)
        pacote_cifrado = cifrar_aes(chave, (texto_enviar + "\n").encode())
        
        espera = comando_resposta(texto_enviar)
        if espera:
            esperando_resposta.set()

        enviar_pacote(socket_cliente, pacote_cifrado)

        if not espera:
            continue

        try:
            msg = fila.get()
            if msg is None:
                print("O Servidor desligou.")
                return

            resp = msg.strip()

            novo_mapa = parse_list_map(resp)
            if novo_mapa:
                mapa_sessoes = novo_mapa

        
            if resp.startswith("DOWNLOAD_OK "):
                try:
                    _, nome, b64 = resp.split(" ", 2)
                    
                    caminho = os.path.join(PASTA_CHAT, os.path.basename(nome))
                
                    with open(caminho, "wb") as f:
                        f.write(base64.b64decode(b64.encode()))
                    print_sem_estragar_prompt(f"Servidor: OK (download guardado em {caminho})")
                except Exception:
                    print_sem_estragar_prompt("Servidor: DOWNLOAD inválido/erro a guardar.")
            else:
                print_sem_estragar_prompt(f"Servidor: {resp}")

        finally:
            esperando_resposta.clear()

def main():
    os.system("clear")
    os.system("figlet Cliente")

    ligacao = criar_socket_cliente(HOST, PORTA)

    try:
        chave = fazer_handshake(ligacao, carregar_chave_publica_servidor())
        while True:
            username = input("Username: ").strip()
            
            if username.lower() in ("exit", "quit", "sair"):
                print("A sair.")
                return
                
            enviar_pacote(ligacao, cifrar_aes(chave, f"USER {username}\n".encode()))

            try:
                pacote = receber_pacote(ligacao)
                resposta = decifrar_aes(chave, pacote).decode(errors="ignore").strip()
            except Exception:
                print("Erro ao contactar o servidor.")
                return
            print_sem_estragar_prompt(f"Servidor: {resposta}")
        

            if resposta.startswith("OK"):
                break  
            else:
                print("Username inválido. Tenta novamente.\n")

        chat_loop(ligacao, chave, username)

    finally:
        ligacao.close()

if __name__ == "__main__":
    main()
