"""
Exercicio - Chat parte do Servidor

Este módulo implementa um servidor de chat seguro que:
- Aceita múltiplos clientes TCP concorrentes
- Realiza handshake criptográfico (RSA + AES)
- Gere sessões de chat com controlo de acesso (ACL)
- Armazena mensagens cifradas em ficheiros
- Permite comandos de gestão (LIST, GET, OPEN, INVITE, DELETE, DOWNLOAD)

"""
import os
import socket
import struct 
import json
import base64
import threading
from datetime import datetime
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes

HOST = "192.168.1.244"
PORTA = 12345
TAMANHO_BUFFER = 4096
PASTA_CHAVES = "./chaves/chat"
FICHEIRO_CHAVE_PRIVADA = "./chaves/chat/servidor_privada.pem"
FICHEIRO_CHAVE_PUBLICA = "./chaves/chat/servidor_publica.pem"
PASTA_FICHEIRO = "./mensagens_arquivadas"
SESSOES_LOCK = threading.Lock()
SESSOES_ATIVAS = {}  
SEND_LOCKS = {} 

os.makedirs(PASTA_CHAVES, exist_ok=True)

def base64_encode(dados):
    """Codifica bytes para Base64 (string ASCII)."""
    return base64.b64encode(dados).decode("ascii")

def base64_decode(texto):
    """Descodifica uma string Base64 para bytes."""
    return base64.b64decode(texto.encode("ascii"))

def garantir_pasta_ficheiro():
    """Garante a existência da pasta de armazenamento das sessões."""
    os.makedirs(PASTA_FICHEIRO, exist_ok=True)

def caminho_seguro_sessao(nome_ficheiro):
    """
    Constrói um caminho seguro dentro da pasta de sessões.

    Previne path traversal.
    """
    nome_limpo = os.path.basename((nome_ficheiro or "").strip())
    caminho = os.path.join(PASTA_FICHEIRO, nome_limpo)

    base = os.path.abspath(PASTA_FICHEIRO) + os.sep
    alvo = os.path.abspath(caminho)
    if not alvo.startswith(base):
        raise ValueError("Nome de sessão inválido.")
    return caminho

#AES
def cifrar_aes(chave, mensagem):
    """Cifra uma mensagem usando AES em modo EAX."""
    cifra = AES.new(chave, AES.MODE_EAX)
    texto_cifrado, tag = cifra.encrypt_and_digest(mensagem)
    # nonce_len(2) + nonce | tag_len(2) + tag | ct_len(4) + ct
    pacote_cifrado = (struct.pack("!H", len(cifra.nonce)) + cifra.nonce + struct.pack("!H", len(tag)) + tag + struct.pack("!I", len(texto_cifrado)) + texto_cifrado)
    
    return pacote_cifrado

def decifrar_aes(chave, pacote):
    """Decifra um pacote cifrado com AES EAX."""
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
    """Garante a existência do par de chaves RSA do servidor."""
    if os.path.exists(FICHEIRO_CHAVE_PRIVADA) and os.path.exists(FICHEIRO_CHAVE_PUBLICA):
        return

    chave = RSA.generate(2048)
    with open(FICHEIRO_CHAVE_PRIVADA, "wb") as f:
        f.write(chave.export_key())
    with open(FICHEIRO_CHAVE_PUBLICA, "wb") as f:
        f.write(chave.publickey().export_key())

    #print("Chave privada em", FICHEIRO_CHAVE_PRIVADA, "e chave publica em", FICHEIRO_CHAVE_PUBLICA)

def carregar_chave_privada():
    """Carrega a chave privada RSA do servidor."""
    with open(FICHEIRO_CHAVE_PRIVADA, "rb") as f:
        return RSA.import_key(f.read())

def enviar_pacote(ligacao, dados):
    """Envia um pacote com prefixo de tamanho."""
    ligacao.sendall(struct.pack("!I", len(dados)) + dados)

def receber_n_bytes(ligacao, num_bytes):
    """Recebe exatamente N bytes de um socket."""
    buffer = b""
    while len(buffer) < num_bytes:
        parte = ligacao.recv(num_bytes - len(buffer))
        if not parte:
            raise ConnectionError("Ligação fechada.")
        buffer += parte
    return buffer

def receber_pacote(ligacao):
    """Recebe um pacote completo (tamanho + dados)."""
    tamanho_mensagem_bytes = receber_n_bytes(ligacao, 4)   #Ler o tamanho da mensagem
    tamanho_mensagem = struct.unpack("!I", tamanho_mensagem_bytes)[0]   #Converter em Int
    mensagem = receber_n_bytes(ligacao, tamanho_mensagem)  #Ler exatamente esses n bytes
    return mensagem

def _get_send_lock(ligacao):
    """
    Obtém (ou cria) um lock de envio associado à ligação.

    :param ligacao: Socket do cliente
    :return: threading.Lock
    """
    with SESSOES_LOCK:
        lock = SEND_LOCKS.get(id(ligacao))
        if lock is None:
            lock = threading.Lock()
            SEND_LOCKS[id(ligacao)] = lock
        return lock
        
def adicionar_sessao(nome_sessao, ligacao, chave_sessao, username):
    """
    Adiciona um cliente a uma sessão ativa em memória.

    :param nome_sessao: Nome do ficheiro da sessão
    :param ligacao: Socket do cliente
    :param chave_sessao: Chave AES da sessão TCP
    :param username: Username do cliente
    :return: None
    """
    with SESSOES_LOCK:
        SESSOES_ATIVAS.setdefault(nome_sessao, set()).add((ligacao, chave_sessao, username))

def remover_sessao(nome_sessao, conn):
    """
    Remove uma ligação de uma sessão ativa.

    :param nome_sessao: Nome da sessão
    :param conn: Socket a remover
    :return: None
    """
    with SESSOES_LOCK:
        subscricoes_sessao = SESSOES_ATIVAS.get(nome_sessao)
        if not subscricoes_sessao:
            return

        subscricoes_restantes = set()
        for (conn_atual, chave_atual, user_atual) in subscricoes_sessao:
            if conn_atual is not conn:
                subscricoes_restantes.add((conn_atual, chave_atual, user_atual))

        if subscricoes_restantes:
            SESSOES_ATIVAS[nome_sessao] = subscricoes_restantes
        else:
            del SESSOES_ATIVAS[nome_sessao]


def remover_cliente_(conn):
    """
    Remove uma ligação de todas as sessões ativas e limpa o lock de envio associado.

    :param conn: Socket do cliente
    :return: None
    """
    with SESSOES_LOCK:
        sessoes_para_apagar = []

        for nome_sessao, subscricoes in SESSOES_ATIVAS.items():
            subscricoes_filtradas = {
                (conn_atual, chave_atual, user_atual)
                for (conn_atual, chave_atual, user_atual) in subscricoes
                if conn_atual is not conn
            }

            if subscricoes_filtradas:
                SESSOES_ATIVAS[nome_sessao] = subscricoes_filtradas
            else:
                sessoes_para_apagar.append(nome_sessao)

        for nome_sessao in sessoes_para_apagar:
            del SESSOES_ATIVAS[nome_sessao]

        SEND_LOCKS.pop(id(conn), None)


def broadcast_para_sessao(nome_sessao, sender_username, texto_msg):
    """
    Envia (broadcast) uma mensagem para todos os subscritos de uma sessão ativa.

    O payload enviado aos clientes segue o formato:
        MSG <sessao> <sender_username> <texto_msg>

    :param nome_sessao: Nome da sessão ativa
    :param sender_username: Username do remetente
    :param texto_msg: Texto a enviar
    :return: Lista de usernames a quem foi entregue
    """
    with SESSOES_LOCK:
        subscricoes = list(SESSOES_ATIVAS.get(nome_sessao, set()))

    payload = f"MSG {nome_sessao} {sender_username} {texto_msg}\n".encode("utf-8")

    entregues = []
    for (conn, chave_canal, user_destino) in subscricoes:
        try:
            lock_envio = _get_send_lock(conn)
            with lock_envio:
                enviar_pacote(conn, cifrar_aes(chave_canal, payload))
            entregues.append(user_destino)
        except Exception:
            pass

    return entregues

def ler_cabecalho_sessao(caminho_sessao):
    """
    Lê o cabeçalho JSON (primeira linha) de um ficheiro de sessão.

    :param caminho_sessao: Caminho do ficheiro
    :return: dict do cabeçalho ou None
    """
    try:
        with open(caminho_sessao, "r", encoding="utf-8") as f:
            primeira = f.readline()
        if not primeira:
            return None
        return json.loads(primeira.strip())
    except Exception:
        return None

def utilizador_e_owner(username, caminho_sessao):
    """
    Verifica se um utilizador é o owner da sessão.

    :param username: Username
    :param caminho_sessao: Caminho da sessão
    :return: True se for owner, False caso contrário
    """
    cabecalho = ler_cabecalho_sessao(caminho_sessao)
    if not isinstance(cabecalho, dict):
        return False
    return cabecalho.get("owner") == username

def utilizador_sessao(username, caminho_sessao):
    """
    Verifica se um utilizador está autorizado a ver/usar a sessão.

    :param username: Username
    :param caminho_sessao: Caminho da sessão
    :return: True se o username existir na ACL, False caso contrário
    """
    cabecalho = ler_cabecalho_sessao(caminho_sessao)
    if not cabecalho:
        return False
    utilizadores = cabecalho.get("utilizadores", [])
    return username in utilizadores

def listar_sessoes_utilizador(username):
    """
    Lista as sessões visíveis para um utilizador (com base na ACL).

    :param username: Username
    :return: String formatada para envio ao cliente
    """
    if not os.path.isdir(PASTA_FICHEIRO):
        return "Não existe a pasta com as sessões.\n"

    ficheiros = sorted(
        [f for f in os.listdir(PASTA_FICHEIRO) if f.startswith("sessao_") and f.endswith(".txt")]
    )
    if not ficheiros:
        return "Sem sessões.\n"

    permitidos = []
    for f in ficheiros:
        caminho = os.path.join(PASTA_FICHEIRO, f)
        if utilizador_sessao(username, caminho):
            permitidos.append(f)

    if not permitidos:
        return "Sem sessões visíveis para este utilizador.\n"

    linhas = [f"{i}) {nome}" for i, nome in enumerate(permitidos, start=1)]
    return "\n".join(linhas) + "\n"

def arquivar_mensagem(mensagem, caminho_sessao, chave_ficheiro, info_mensagem):
    """
    Arquiva uma mensagem no ficheiro da sessão cifrando com AES-EAX.

    :param mensagem: bytes (mensagem original)
    :param caminho_sessao: caminho da sessão no disco
    :param chave_ficheiro: chave AES usada no ficheiro
    :param info_mensagem: dict com metadados (direcao/cliente/username)
    :return: None
    """
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
    """
    Decifra todo o ficheiro de sessão e devolve o histórico em texto.

    - A chave AES do ficheiro está cifrada no cabeçalho (RSA-OAEP)
    - Cada linha de mensagem está cifrada com AES-EAX

    :param caminho_sessao: Caminho do ficheiro de sessão
    :param chave_privada_rsa: Chave privada RSA do servidor
    :return: String com mensagens ou erro
    """
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

            if isinstance(direcao):
                if "->" in direcao:
                    remetente = direcao.split("->", 1)[0].strip()
                else:
                    remetente = direcao.strip()
            
            saida.append(f"{ts} {remetente}: {msg_txt}")
            
        except Exception:
            saida.append("Linha invalida/alterada no ficheiro.")

    if not saida:
        return "[i] Sem mensagens.\n"

    return "\n".join(saida) + "\n"

_lock_usernames = threading.Lock()
_usernames_ativos = set()

def validar_username(username):
    """
    Valida username:
    - 3..20 chars
    - alfanumérico ou underscore

    :param username: string
    :return: True/False
    """
    if not (3 <= len(username) <= 20):
        return False
    for ch in username:
        if not (ch.isalnum() or ch == "_"):
            return False
    return True

def registar_username(username):
    """
    Regista o username como ativo (evita duplicados simultâneos).

    :param username: string
    :return: True se registou, False se já existia
    """
    with _lock_usernames:
        if username in _usernames_ativos:
            return False
        _usernames_ativos.add(username)
        return True

def libertar_username(username):
    """
    Remove o username do conjunto de ativos.

    :param username: string
    :return: None
    """
    with _lock_usernames:
        _usernames_ativos.discard(username)
#Servidor
def criar_socket_servidor(host, porta):
    """
    Cria e configura o socket TCP do servidor.

    :param host: IP
    :param porta: Porta
    :return: socket em modo listen
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) #Apenas porque só tenho a porta para isto
    s.bind((host, porta))
    s.listen(50)
    return s

def fazer_handshake(ligacao, chave_privada_rsa):
    """
    Handshake:
    - Cliente envia chave AES cifrada com a pública do servidor
    - Servidor decifra com a privada e envia confirmação cifrada

    :param ligacao: socket do cliente
    :param chave_privada_rsa: chave privada RSA
    :return: chave AES da sessão (bytes)
    """
    chave_aes_cifrada = receber_pacote(ligacao) # Cliente envia chave AES cifrada com a pública do servidor

    cifra_rsa = PKCS1_OAEP.new(chave_privada_rsa) # Servidor decifra com a sua privada
    chave = cifra_rsa.decrypt(chave_aes_cifrada)

    enviar_pacote(ligacao, cifrar_aes(chave, b"handshake_ok\n"))
    return chave

def receber_username(ligacao, chave_aes):
    """
    Recebe o comando USER e valida o username.

    Repete até ser válido e não estar ativo.

    :param ligacao: socket do cliente
    :param chave_aes: chave AES da sessão
    :return: username validado
    """
    while True:
        pacote = receber_pacote(ligacao)
        msg = decifrar_aes(chave_aes, pacote).decode(errors="ignore").strip()
    
        if not msg.upper().startswith("USER "):
            enviar_pacote(ligacao, cifrar_aes(chave_aes, b"Use 'USER <username>'\n"))
            continue
        
        username = msg.split(" ", 1)[1].strip()
        if not validar_username(username):
            enviar_pacote(ligacao, cifrar_aes(chave_aes, "Username invalido, use entre 3 e 20 caracteres, apenas letras e numeros.\n".encode()))
            continue
        
        if not registar_username(username):
            enviar_pacote(ligacao, cifrar_aes(chave_aes, "Esse username esta ativo.\n".encode()))
            continue
        
        enviar_pacote(ligacao, cifrar_aes(chave_aes, b"OK\n"))
        return username

def enviar_erro(ligacao, chave, texto):
    """
    Envia uma mensagem de erro cifrada ao cliente.

    :param ligacao: socket
    :param chave: chave AES
    :param texto: mensagem
    :return: None
    """
    enviar_pacote(ligacao, cifrar_aes(chave, (texto.rstrip() + "\n").encode()))

def aceitar_cliente(socket_servidor):
    """
    Aceita uma ligação de cliente.

    :param socket_servidor: socket em listen
    :return: (ligacao, endereco)
    """
    ligacao, endereco = socket_servidor.accept()
    return ligacao, endereco

def add_user_to_session(requester, session_filename, new_user):
    """
    Adiciona um utilizador à ACL (lista 'utilizadores') de uma sessão.

    Regras:
    - requester tem de já estar na ACL
    - sessão tem de existir
    - new_user tem de ser válido e não pode já ter acesso

    :param requester: username que convida
    :param session_filename: ficheiro da sessão
    :param new_user: username a adicionar
    :return: mensagem (string)
    """
    if not validar_username(new_user):
        return "Username inválido (3-20 chars, letras/números/_).\n"

    caminho = caminho_seguro_sessao(session_filename)
    if not os.path.isfile(caminho):
        return "Sessão não encontrada.\n"

    try:
        with open(caminho, "r", encoding="utf-8") as f:
            linhas = f.readlines()
        if not linhas:
            return "Sessão vazia.\n"
        cabecalho = json.loads(linhas[0].strip())
    except Exception:
        return "Sessão com cabeçalho inválido.\n"

    utilizadores = cabecalho.get("utilizadores", [])
    if not isinstance(utilizadores, list):
        utilizadores = []
    utilizadores = [u for u in utilizadores if isinstance(u, str)]

    if requester not in utilizadores:
        return "Sem permissões para adicionar utilizadores a esta sessão.\n"

    if new_user in utilizadores:
        return "Utilizador já tinha acesso.\n"

    utilizadores.append(new_user)
    cabecalho["utilizadores"] = sorted(set(utilizadores))

    linhas[0] = json.dumps(cabecalho, ensure_ascii=False) + "\n"
    try:
        with open(caminho, "w", encoding="utf-8") as f:
            f.writelines(linhas)
    except Exception:
        return "Não foi possível atualizar a sessão.\n"

    return f"{new_user} adicionado à sessão.\n"

def criar_sessao(owner, endereco_cliente, chave_publica_rsa):
    """
    Cria uma nova sessão no disco e define ACL inicial com o owner.

    Guarda no cabeçalho:
    - owner
    - utilizadores [owner]
    - chave AES do ficheiro cifrada com RSA-OAEP

    :param owner: username do criador
    :param endereco_cliente: (ip, porta)
    :param chave_publica_rsa: chave pública RSA do servidor
    :return: (caminho_sessao, chave_ficheiro)
    """
    garantir_pasta_ficheiro()

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    caminho_sessao = os.path.join(PASTA_FICHEIRO, f"sessao_{timestamp}_{owner}.txt")

    # chave AES do ficheiro (para cifrar cada registo no disco)
    chave_ficheiro = get_random_bytes(16)

    # cifra a chave do ficheiro com a chave pública do servidor
    cifra_rsa = PKCS1_OAEP.new(chave_publica_rsa)
    chave_ficheiro_cifrada = cifra_rsa.encrypt(chave_ficheiro)

    cabecalho = {
        "tipo": "sessao_chat",
        "timestamp_inicio": datetime.now().isoformat(timespec="seconds"),
        "cliente_criador": f"{endereco_cliente[0]}:{endereco_cliente[1]}",
        "owner": owner,
        "utilizadores": [owner], 
        "rsa_oaep_chave_ficheiro": base64_encode(chave_ficheiro_cifrada),
        "aes_modo": "EAX",
    }

    with open(caminho_sessao, "w", encoding="utf-8") as f:
        f.write(json.dumps(cabecalho, ensure_ascii=False) + "\n")

    return caminho_sessao, chave_ficheiro

def obter_chave_ficheiro_da_sessao(caminho_sessao, chave_privada_rsa):
    """
    Obtém a chave AES do ficheiro de sessão decifrando RSA-OAEP.

    :param caminho_sessao: caminho do ficheiro
    :param chave_privada_rsa: chave privada RSA
    :return: chave AES do ficheiro (bytes)
    """
    cabecalho = ler_cabecalho_sessao(caminho_sessao)
    if not isinstance(cabecalho, dict):
        raise ValueError("Sessão com cabeçalho inválido.")

    b64 = cabecalho.get("rsa_oaep_chave_ficheiro")
    if not b64:
        raise ValueError("Cabeçalho sem rsa_oaep_chave_ficheiro.")

    chave_ficheiro_cifrada = base64_decode(b64)
    cifra_rsa = PKCS1_OAEP.new(chave_privada_rsa)
    return cifra_rsa.decrypt(chave_ficheiro_cifrada)

def handle_cliente(ligacao, endereco_cliente, chave_publica_rsa, chave_privada_rsa):
    """
    Handler por cliente (executa numa thread).

    Fluxo:
    - handshake
    - receber username
    - entrar no chat_loop
    - libertar username e fechar ligação ao terminar

    :param ligacao: socket do cliente
    :param endereco_cliente: (ip, porta)
    :param chave_publica_rsa: chave pública RSA
    :param chave_privada_rsa: chave privada RSA
    :return: None
    """
    username = None
    chave_sessao = None
    try:
        chave_sessao = fazer_handshake(ligacao, chave_privada_rsa)

        username = receber_username(ligacao, chave_sessao)

        chat_loop(ligacao, chave_sessao, chave_publica_rsa, chave_privada_rsa, endereco_cliente, username)

    except Exception as e:
        try:
            if chave_sessao:
                enviar_erro(ligacao, chave_sessao, f"ERRO: {e}")
        except Exception:
            pass
    finally:
        if username:
            libertar_username(username)
        try:
            ligacao.close()
        except Exception:
            pass


def chat_loop(ligacao, chave, chave_publica_rsa, chave_privada_rsa, endereco_cliente, username):
    """
    Loop principal do servidor para um cliente.

    Implementa comandos:
    - LIST
    - GET/VIEW <sessao>
    - DELETE <sessao>
    - DOWNLOAD <sessao>
    - OPEN <sessao>
    - NEW
    - INVITE <sessao> <user>

    Mensagem normal:
    - arquiva no ficheiro da sessão
    - faz broadcast para os utilizadores subscritos na sessão ativa

    :param ligacao: socket do cliente
    :param chave: chave AES da sessão TCP
    :param chave_publica_rsa: chave pública RSA
    :param chave_privada_rsa: chave privada RSA
    :param endereco_cliente: (ip, porta)
    :param username: username autenticado
    :return: None
    """
    # cria sessão ativa inicial
    caminho_sessao, chave_ficheiro = criar_sessao(username, endereco_cliente, chave_publica_rsa)
    sessao_ativa_nome = os.path.basename(caminho_sessao)
    adicionar_sessao(sessao_ativa_nome, ligacao, chave, username)

    enviar_pacote(ligacao, cifrar_aes( chave, ( f"Bem-vindo {username}!\n" 
    "Estão disponíveis os comandos:\n\t LIST: mostra todos os chats\n\t GET <sessao>: mostra o conteudo de um chat\n\t DELETE <sessao>: apaga um chat\n\t DOWNLOAD <sessao>: descarrega um chat\n\t OPEN <sessao>: entra noutro chat\n\t INVITE <sessao> <user>: convida um user para o chat escolhido\n").encode()))

    while True:
        try:
            pacote = receber_pacote(ligacao)
        except ConnectionError:
            break

        try:
            mensagem = decifrar_aes(chave, pacote)
        except Exception:
            enviar_pacote(ligacao, cifrar_aes(chave, "Mensagem inválida/alterada.\n".encode("utf-8")))
            continue

        texto = mensagem.decode(errors="ignore").strip()
        if not texto:
            continue

        partes = texto.split()
        cmd = partes[0].upper()

        # LIST
        if cmd == "LIST":
            enviar_pacote(ligacao, cifrar_aes(chave, listar_sessoes_utilizador(username).encode()))
            continue

        # GET/VIEW
        if cmd in ("GET", "VIEW"):
            if len(partes) != 2:
                enviar_pacote(ligacao, cifrar_aes(chave, b"Uso: GET/VIEW <sessao.txt>\n"))
                continue
            nome = partes[1].strip()
            caminho = caminho_seguro_sessao(nome)

            if not utilizador_sessao(username, caminho):
                enviar_pacote(ligacao, cifrar_aes(chave, "Sem permissões para esta sessão.\n".encode("utf-8")))
                continue

            mensagem = desencriptar_sessao(caminho, chave_privada_rsa)
            enviar_pacote(ligacao, cifrar_aes(chave, mensagem.encode()))
            continue

        # DELETE
        if cmd == "DELETE":
            if len(partes) != 2:
                enviar_pacote(ligacao, cifrar_aes(chave, b"Uso: DELETE <sessao.txt>\n"))
                continue
            nome = partes[1].strip()
            caminho = caminho_seguro_sessao(nome)

            if not utilizador_e_owner(username, caminho):
                enviar_pacote(ligacao, cifrar_aes(chave, "Sem permissões para apagar esta sessão.\n".encode("utf-8")))
                continue

            try:
                os.remove(caminho)
                if os.path.basename(caminho) == sessao_ativa_nome:
                    caminho_sessao, chave_ficheiro = criar_sessao(username, endereco_cliente, chave_publica_rsa)
                    sessao_ativa_nome = os.path.basename(caminho_sessao)
                    enviar_pacote(ligacao, cifrar_aes(chave, f"Apagada. Nova sessão ativa: {sessao_ativa_nome}\n".encode()))
                else:
                    enviar_pacote(ligacao, cifrar_aes(chave, "Sessão apagada.\n".encode("utf-8")))
            except FileNotFoundError:
                enviar_pacote(ligacao, cifrar_aes(chave, "Sessão não encontrada.\n".encode("utf-8")))
            except Exception:
                enviar_pacote(ligacao, cifrar_aes(chave, "Erro ao apagar sessão.\n".encode("utf-8")))
            continue

        # DOWNLOAD
        if cmd == "DOWNLOAD":
            if len(partes) != 2:
                enviar_pacote(ligacao, cifrar_aes(chave, b"Uso: DOWNLOAD <sessao.txt>\n"))
                continue
            nome = partes[1].strip()
            caminho = caminho_seguro_sessao(nome)

            if not utilizador_sessao(username, caminho):
                enviar_pacote(ligacao, cifrar_aes(chave, "Sem permissões para descarregar esta sessão.\n".encode("utf-8")))
                continue
            if not os.path.isfile(caminho):
                enviar_pacote(ligacao, cifrar_aes(chave, "Sessão não encontrada.\n".encode("utf-8")))
                continue

            with open(caminho, "rb") as f:
                blob = f.read()
            payload = base64.b64encode(blob)
            enviar_pacote(ligacao, cifrar_aes(chave, b"DOWNLOAD_OK " + os.path.basename(caminho).encode() + b" " + payload + b"\n"))
            continue

        # OPEN
        if cmd == "OPEN":
            if len(partes) != 2:
                enviar_pacote(ligacao, cifrar_aes(chave, b"Uso: OPEN <sessao.txt>\n"))
                continue
            nome = partes[1].strip()
            caminho = caminho_seguro_sessao(nome)

            if not utilizador_sessao(username, caminho):
                enviar_pacote(ligacao, cifrar_aes(chave, "Sem permissões para abrir esta sessão.\n".encode("utf-8")))
                continue

            try:
                chave_ficheiro = obter_chave_ficheiro_da_sessao(caminho, chave_privada_rsa)
            except Exception:
                enviar_pacote(ligacao, cifrar_aes(chave, "Não foi possível abrir (chave inválida).\n".encode("utf-8")))
                continue

            remover_sessao(sessao_ativa_nome, ligacao)
            
            caminho_sessao = caminho
            sessao_ativa_nome = os.path.basename(caminho_sessao)

            adicionar_sessao(sessao_ativa_nome, ligacao, chave, username)
            
            enviar_pacote(ligacao, cifrar_aes(chave, f"Sessão ativa = {sessao_ativa_nome}\n".encode()))
            continue

        # NEW
        if cmd == "NEW":
            remover_sessao(sessao_ativa_nome, ligacao)
            
            caminho_sessao, chave_ficheiro = criar_sessao(username, endereco_cliente, chave_publica_rsa)
            sessao_ativa_nome = os.path.basename(caminho_sessao)

            adicionar_sessao(sessao_ativa_nome, ligacao, chave, username)
            
            enviar_pacote(ligacao, cifrar_aes(chave, f"Nova sessão ativa = {sessao_ativa_nome}\n".encode()))
            continue

        # INVITE
        if cmd == "INVITE":
            if len(partes) != 3:
                enviar_pacote(ligacao, cifrar_aes(chave, b"Uso: INVITE <sessao.txt> <username>\n"))
                continue
            nome = partes[1].strip()
            novo = partes[2].strip()
            res = add_user_to_session(username, nome, novo)
            enviar_pacote(ligacao, cifrar_aes(chave, res.encode()))
            continue

        # Mensagem normal -> sessão ativa (com ACL)
        if not utilizador_sessao(username, caminho_sessao):
            enviar_pacote(ligacao, cifrar_aes(chave, "Sem permissões na sessão ativa (use OPEN/NEW).\n".encode("utf-8")))
            continue

        texto_msg = mensagem.decode(errors="ignore").strip()
        
        info_in = {"direcao": f"{username} -> Servidor", "cliente": f"{endereco_cliente[0]}:{endereco_cliente[1]}", "username": username}
        arquivar_mensagem(mensagem, caminho_sessao, chave_ficheiro, info_in)

        #with SESSOES_LOCK:
        #    subs = SESSOES_ATIVAS.get(sessao_ativa_nome, set())
        #    print("DEBUG sessão:", sessao_ativa_nome, "subscritos:", [u for (_, _, u) in subs])
            
        destinatarios = broadcast_para_sessao(sessao_ativa_nome, username, texto_msg)
        outros_destinatarios = [u for u in destinatarios if u != username]
        
        if outros_destinatarios:
            for user_destino in outros_destinatarios:
                info_out = {"direcao": f"Servidor -> {user_destino}", "cliente": f"{endereco_cliente[0]}:{endereco_cliente[1]}", "username": username}
                arquivar_mensagem(mensagem, caminho_sessao, chave_ficheiro, info_out)
        else:
            enviar_pacote(ligacao, cifrar_aes(chave, (texto_msg + "\n").encode("utf-8")))
            info_out = {"direcao": f"Servidor -> {username}", "cliente": f"{endereco_cliente[0]}:{endereco_cliente[1]}", "username": username}
            arquivar_mensagem(mensagem, caminho_sessao, chave_ficheiro, info_out)


def main():
    """
    Função principal do servidor.

    - Inicializa pastas
    - Garante chaves RSA
    - Inicia socket TCP
    - Aceita clientes e cria uma thread por ligação
    """
    os.system("clear")
    os.system("figlet Servidor")
    
    garantir_pasta_ficheiro()
    garantir_chaves_rsa()
    chave_privada = carregar_chave_privada()
    chave_publica = chave_privada.publickey()
    
    socket_servidor = criar_socket_servidor(HOST, PORTA)
    print(f"Servidor ligado!") 


    try:
        while True:
            ligacao, endereco = socket_servidor.accept()
            t = threading.Thread(target=handle_cliente, args=(ligacao, endereco, chave_publica, chave_privada), daemon=True, )

            t.start()
    except KeyboardInterrupt:
        print("\nServidor encerrado.")
    finally:
        socket_servidor.close()



if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nServidor encerrado.")
