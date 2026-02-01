import os
import socket
import struct 
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes

HOST = "192.168.1.244"
PORTA = 12345
TAMANHO_BUFFER = 4096
FICHEIRO_CHAVE_PRIVADA = "servidor_privada.pem"
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
def garantir_chaves_rsa():
    if os.path.exists(FICHEIRO_CHAVE_PRIVADA) and os.path.exists(FICHEIRO_CHAVE_PUBLICA):
        return

    chave = RSA.generate(2048)
    with open(FICHEIRO_CHAVE_PRIVADA, "wb") as f:
        f.write(chave.export_key())
    with open(FICHEIRO_CHAVE_PUBLICA, "wb") as f:
        f.write(chave.publickey().export_key())

    #print("Chave privada em", FICHEIRO_CHAVE_PRIVADA, "e chave publica em", FICHEIRO_CHAVE_PUBLICA)

def carregar_chave_privada():
    with open(FICHEIRO_CHAVE_PRIVADA, "rb") as f:
        return RSA.import_key(f.read())

#Servidor
def criar_socket_servidor(host, porta):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) #Apenas porque só tenho a porta para isto
    s.bind((host, porta))
    s.listen(1)
    return s

def fazer_handshake(ligacao, chave_privada_rsa):
    chave_aes_cifrada = receber_pacote(ligacao) # Cliente envia chave AES cifrada com a pública do servidor

    cifra_rsa = PKCS1_OAEP.new(chave_privada_rsa) # Servidor decifra com a sua privada
    chave = cifra_rsa.decrypt(chave_aes_cifrada)

    enviar_pacote(ligacao, cifrar_aes(chave, b"handshake_ok\n"))
    return chave

def aceitar_cliente(socket_servidor):
    ligacao, endereco = socket_servidor.accept()
    return ligacao, endereco


def chat_loop(ligacao, chave):
    enviar_pacote(ligacao, cifrar_aes(chave, b"Bem-vindo ao chat seguro!\nEnvie a sua mensagem para o servidor\n")) # Mensagem inicial cifrada

    while True:
        try:
            pacote = receber_pacote(ligacao)
        except ConnectionError:
            break

        try:
            mensagem = decifrar_aes(chave, pacote).decode(errors="ignore")
        except Exception:
            enviar_pacote(ligacao, cifrar_aes(chave, b"[ERRO] Mensagem invalida/alterada.\n"))
            continue

        if not mensagem:
            continue

        print("Cliente:", mensagem, end="")

        enviar_pacote(ligacao, cifrar_aes(chave, mensagem.encode()))

def main():
    os.system("clear")
    os.system("figlet Servidor")
    garantir_chaves_rsa()
    chave_privada = carregar_chave_privada()  # carrega a chave privada RSA do servidor

    socket_servidor = criar_socket_servidor(HOST, PORTA)
    print(f"Servidor ligado!") 

    ligacao, endereco = aceitar_cliente(socket_servidor)  
    print("Ligado a:", endereco)

    try:
        chave = fazer_handshake(ligacao, chave_privada)  # recebe e decifra a chave AES
        chat_loop(ligacao, chave)                # inicia o chat
    finally:
        ligacao.close()                
        socket_servidor.close()        
        print("Servidor encerrado.")



if __name__ == "__main__":
    main()
