import os
import socket
import struct 
import json
import base64
from datetime import datetime
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes

HOST = "192.168.1.244"
PORTA = 12345
TAMANHO_BUFFER = 4096
FICHEIRO_CHAVE_PRIVADA = "servidor_privada.pem"
FICHEIRO_CHAVE_PUBLICA = "servidor_publica.pem"
PASTA_FICHEIRO = "./mensagens_arquivadas"

def base64_encode(dados):
    return base64.b64encode(dados).decode("ascii")

def base64_decode(texto):
    return base64.b64decode(texto.encode("ascii"))

def garantir_pasta_ficheiro():
    os.makedirs(PASTA_FICHEIRO, exist_ok=True)

def caminho_seguro_sessao(nome_ficheiro):
    nome_limpo = os.path.basename(nome_ficheiro.strip())    # impede path traversal
    return os.path.join(PASTA_FICHEIRO, nome_limpo)

def listar_sessoes():
    if not os.path.isdir(PASTA_FICHEIRO):
        return "Não existe a pasta com as sessoes.\n"

    ficheiros = sorted([f for f in os.listdir(PASTA_FICHEIRO) if f.startswith("sessao_") and f.endswith(".txt")])

    if not ficheiros:
        return "Sem sessoes.\n"

    linhas = []
    for i, f in enumerate(ficheiros, start=1):
        linhas.append(f"{i}) {f}")
    return "\n".join(linhas) + "\n"

def arquivar_mensagem(mensagem, caminho_sessao, chave_ficheiro, info_mensagem):
    
    cifra_aes = AES.new(chave_ficheiro, AES.MODE_EAX)
    texto_cifrado, tag = cifra_aes.encrypt_and_digest(mensagem)

    registo = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "info_da_mensagem": info_mensagem,
        "aes_eax_nonce": base64_encode(cifra_aes.nonce),
        "aes_eax_tag": base64_encode(tag),
        "aes_eax_texto_cifrado": base64_encode(texto_cifrado),
    }

    with open(caminho_sessao, "a", encoding="utf-8") as f:
        f.write(json.dumps(registo, ensure_ascii=False) + "\n")

def desencriptar_sessao(caminho_sessao, chave_privada_rsa):

    if not os.path.exists(caminho_sessao):
        return "Ficheiro nao existe.\n"

    with open(caminho_sessao, "r", encoding="utf-8") as f:
        linhas = f.read().splitlines()

    if not linhas:
        return "Ficheiro vazio.\n"

    try:
        cabecalho = json.loads(linhas[0])
        chave_ficheiro_cifrada_b64 = cabecalho.get("rsa_oaep_chave_ficheiro")
        if not chave_ficheiro_cifrada_b64:
            return "Cabecalho sem chave do ficheiro.\n"
    except Exception:
        return "Cabecalho invalido.\n"

    # Decifrar a chave AES do ficheiro (com a privada do servidor)
    try:
        chave_ficheiro_cifrada = base64_decode(chave_ficheiro_cifrada_b64)
        cifra_rsa = PKCS1_OAEP.new(chave_privada_rsa)
        chave_ficheiro = cifra_rsa.decrypt(chave_ficheiro_cifrada)
    except Exception:
        return "Nao foi possivel decifrar a chave do ficheiro.\n"

    # Decifrar todas as mensagens
    saida = []
    for linha in linhas[1:]:
        if not linha.strip():
            continue

        try:
            registo = json.loads(linha)
            nonce = base64_decode(registo["aes_eax_nonce"])
            tag = base64_decode(registo["aes_eax_tag"])
            ct = base64_decode(registo["aes_eax_texto_cifrado"])

            cifra = AES.new(chave_ficheiro, AES.MODE_EAX, nonce=nonce)
            msg_bytes = cifra.decrypt(ct)
            cifra.verify(tag)

            direcao = registo.get("info_da_mensagem", {}).get("direcao", "?")
            ts = registo.get("timestamp", "?").replace("T", " ")
            msg_txt = msg_bytes.decode(errors="ignore").strip()

            remetente = "Desconhecido"
            if direcao in ("Cliente -> Servidor"):
                remetente = "Cliente"
            elif direcao in ("Servidor -> Cliente"):
                remetente = "Servidor"
            saida.append(f"{ts} {remetente}: {msg_txt}")
            
        except Exception:
            saida.append("Linha invalida/alterada no ficheiro.")

    if not saida:
        return "[i] Sem mensagens.\n"

    return "\n".join(saida) + "\n"

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


def chat_loop(ligacao, chave, chave_publica_rsa, chave_privada_rsa, endereco_cliente):
    enviar_pacote(ligacao, cifrar_aes(chave, b"Bem-vindo ao chat seguro!\nEnvie a sua mensagem para o servidor\n")) # Mensagem inicial cifrada

    garantir_pasta_ficheiro()
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    caminho_sessao = os.path.join(PASTA_FICHEIRO,f"sessao_{timestamp}_{endereco_cliente[0]}_{endereco_cliente[1]}.txt")

    chave_ficheiro = get_random_bytes(16)
    cifra_rsa = PKCS1_OAEP.new(chave_publica_rsa)
    chave_ficheiro_cifrada = cifra_rsa.encrypt(chave_ficheiro)
    
    cabecalho = {
            "tipo": "sessao_chat",
            "timestamp_inicio": datetime.now().isoformat(timespec="seconds"),
            "cliente": f"{endereco_cliente[0]}:{endereco_cliente[1]}",
            "rsa_oaep_chave_ficheiro": base64_encode(chave_ficheiro_cifrada),
            "aes_modo": "EAX"
        }
    
    with open(caminho_sessao, "w", encoding="utf-8") as f:
       f.write(json.dumps(cabecalho, ensure_ascii=False) + "\n")
            
    while True:
        try:
            pacote = receber_pacote(ligacao)
        except ConnectionError:
            break

        try:
            mensagem = decifrar_aes(chave, pacote)
        except Exception:
            enviar_pacote(ligacao, cifrar_aes(chave, b"Mensagem invalida/alterada.\n"))
            continue

        if not mensagem:
            continue
        
        mensagem_texto = mensagem.decode(errors="ignore").strip()
        if mensagem_texto.upper() == "LIST":
            enviar_pacote(ligacao, cifrar_aes(chave, listar_sessoes().encode()))
            continue
        
        if mensagem_texto.upper().startswith("GET ") or mensagem_texto.upper().startswith("VIEW "):
            partes = mensagem_texto.split(maxsplit=1)
            if len(partes) != 2:
                enviar_pacote(ligacao, cifrar_aes(chave, b"Uso: GET/VIEW <ficheiro_sessao.txt>\n"))
                continue
        
            nome_ficheiro = partes[1].strip()
            caminho = caminho_seguro_sessao(nome_ficheiro)
        
            texto_claro = desencriptar_sessao(caminho, chave_privada_rsa)
            enviar_pacote(ligacao, cifrar_aes(chave, texto_claro.encode()))
            continue

        info_mensagem = {"direcao": "Cliente -> Servidor","cliente": f"{endereco_cliente[0]}:{endereco_cliente[1]}"}
        arquivar_mensagem(mensagem, caminho_sessao, chave_ficheiro, info_mensagem)
        
        print("Cliente:", mensagem_texto)
        enviar_pacote(ligacao, cifrar_aes(chave, mensagem))

        info_resposta = {"direcao": "Servidor -> Cliente","cliente": f"{endereco_cliente[0]}:{endereco_cliente[1]}"}
        arquivar_mensagem(mensagem, caminho_sessao, chave_ficheiro, info_resposta)

def main():
    os.system("clear")
    os.system("figlet Servidor")
    
    garantir_chaves_rsa()
    chave_privada = carregar_chave_privada()
    chave_publica = chave_privada.publickey()
    
    socket_servidor = criar_socket_servidor(HOST, PORTA)
    print(f"Servidor ligado!") 

    ligacao, endereco = aceitar_cliente(socket_servidor)  
    print("Ligado a:", endereco)

    try:
        chave = fazer_handshake(ligacao, chave_privada)
        chat_loop(ligacao, chave, chave_publica, chave_privada, endereco)
    finally:
        ligacao.close()                
        socket_servidor.close()        
        print("Servidor encerrado.")



if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nServidor encerrado.")
