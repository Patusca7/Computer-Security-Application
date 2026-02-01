import os
import socket
import struct
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes

HOST = "192.168.1.244"
PORTA = 12345
TAMANHO_BUFFER = 4096
FICHEIRO_CHAVE_PUBLICA = "servidor_publica.pem"

def enviar_pacote(ligacao, dados):
    ligacao.sendall(struct.pack("!I", len(dados)) + dados)

def receber_n_bytes(ligacao, num_bytes):
    buffer = b""
    while len(buffer) < num_bytes:
        parte = ligacao.recv(num_bytes - len(buffer))
        if not parte:
            raise ConnectionError("Ligação fechada.")
        buffer += parte
    return buffer

def receber_pacote(ligacao):
    tamanho_mensagem_bytes = receber_n_bytes(ligacao, 4)   #Ler o tamanho da mensagem
    tamanho_mensagem = struct.unpack("!I", tamanho_mensagem_bytes)[0]   #Converter em Int
    mensagem = receber_n_bytes(ligacao, tamanho_mensagem)  #Ler exatamente esses n bytes
    return mensagem

#AES
def cifrar_aes(chave, mensagem):
    cifra = AES.new(chave, AES.MODE_EAX)
    texto_cifrado, tag = cifra.encrypt_and_digest(mensagem)
    # nonce_len(2) + nonce | tag_len(2) + tag | ct_len(4) + ct
    pacote_cifrado = (struct.pack("!H", len(cifra.nonce)) + cifra.nonce + struct.pack("!H", len(tag)) + tag + struct.pack("!I", len(texto_cifrado)) + texto_cifrado)
        
    return pacote_cifrado

def decifrar_aes(chave, pacote):
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
    with open(FICHEIRO_CHAVE_PUBLICA, "rb") as f:
        return RSA.import_key(f.read())

#Cliente
def criar_socket_cliente(host, porta):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, porta))
    return s

def fazer_handshake(ligacao, chave_publica_servidor):
    chave = get_random_bytes(16)
    cifra_rsa = PKCS1_OAEP.new(chave_publica_servidor) # Prepara o RSA com a chave pública do servidor
    chave_aes_cifrada = cifra_rsa.encrypt(chave) # Cifra a chave AES com a pública do servidor

    enviar_pacote(ligacao, chave_aes_cifrada)

    confirmacao = decifrar_aes(chave, receber_pacote(ligacao)).decode(errors="ignore")
    if "handshake_ok" not in confirmacao:
        raise RuntimeError("Handshake falhou.")
    return chave

def receber_mensagem_inicial(socket_cliente, chave):
    pacote = receber_pacote(socket_cliente)
    mensagem = decifrar_aes(chav, pacote)
    print("Servidor:", mensagem.decode(errors="ignore"), end="")

def chat_loop(socket_cliente, chave):

    pacote_inicial = receber_pacote(socket_cliente)
    mensagem_inicial = decifrar_aes(chave, pacote_inicial).decode(errors="ignore")
    print("Servidor: ", mensagem_inicial, end="")
    
    while True:
        texto = input("> ")
        if texto.lower() in ("sair", "exit", "quit"):
            break

        pacote_cifrado = cifrar_aes(chave, (texto + "\n").encode())
        enviar_pacote(socket_cliente, pacote_cifrado)
        
        pacote_resposta = receber_pacote(socket_cliente)
        resposta = decifrar_aes(chave, pacote_resposta).decode(errors="ignore")
        print("Servidor:", resposta, end="")


def main():
    os.system("clear")
    os.system("figlet Cliente")
    chave_publica = carregar_chave_publica_servidor()
    ligacao = criar_socket_cliente(HOST, PORTA)

    try:
        chave = fazer_handshake(ligacao, chave_publica)
        chat_loop(ligacao, chave)
    finally:
        ligacao.close()


if __name__ == "__main__":
    main()
