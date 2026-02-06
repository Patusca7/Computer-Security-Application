"""
Exercicio - Password Manager

Este módulo implementa um gestor de passwords simples que:
- Guarda registos cifrados (URL, utilizador, password)
- Utiliza criptografia híbrida (RSA + AES)
- Protege a consulta de passwords com autenticação 2FA (TOTP)
- Usa SQLite como base de dados local

Funcionalidades principais:
- Criar, atualizar, apagar e listar registos
- Consultar passwords com 2FA
- Inicialização e visualização da configuração 2FA
- Geração automática de documentação via pydoc
"""

import os
import sqlite3
import json
import base64
import pyotp

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes

PASTA_BD= "./UTILS/Password_Manager_BD/"
FICHEIRO_BD = "./UTILS/Password_Manager_BD/password_manager.db"
PASTA_CHAVES = "./chaves/password_manager/"
FICHEIRO_CHAVE_PRIVADA = "./chaves/password_manager/pm_privada.pem"
FICHEIRO_CHAVE_PUBLICA = "./chaves/password_manager/pm_publica.pem"

os.makedirs(PASTA_BD, exist_ok = True)
os.makedirs(PASTA_CHAVES, exist_ok = True)

def base64_encode(dados):
    """
    Codifica bytes em Base64 (string ASCII).

    :param dados: Bytes a codificar
    :return: String Base64
    """
    return base64.b64encode(dados).decode("ascii")

def base64_decode(texto):
    """
    Descifica uma string Base64 para bytes.

    :param texto: String Base64
    :return: Bytes descodificados
    """
    return base64.b64decode(texto.encode("ascii"))

def garantir_chaves_rsa():
    """
    Garante a existência de um par de chaves RSA.

    Caso não existam, gera:
    - Chave privada (PEM)
    - Chave pública (PEM)
    """
    if os.path.exists(FICHEIRO_CHAVE_PRIVADA) and os.path.exists(FICHEIRO_CHAVE_PUBLICA):
        return

    chave = RSA.generate(2048)
    with open(FICHEIRO_CHAVE_PRIVADA, "wb") as f:
        f.write(chave.export_key()) 
    with open(FICHEIRO_CHAVE_PUBLICA, "wb") as f:
        f.write(chave.publickey().export_key())

def carregar_chave_privada():
    """
    Carrega a chave privada RSA a partir de ficheiro.

    :return: Objeto RSA private key
    """
    with open(FICHEIRO_CHAVE_PRIVADA, "rb") as f:
        return RSA.import_key(f.read())

def carregar_chave_publica():
    """
    Carrega a chave pública RSA a partir de ficheiro.

    :return: Objeto RSA public key
    """
    with open(FICHEIRO_CHAVE_PUBLICA, "rb") as f:
        return RSA.import_key(f.read())

def cifrar_aes_eax(chave, mensagem_bytes):
    """
    Cifra dados usando AES em modo EAX.

    :param chave: Chave AES
    :param mensagem_bytes: Dados em bytes
    :return: Dicionário com nonce, tag e texto cifrado (Base64)
    """
    cifra = AES.new(chave, AES.MODE_EAX)
    texto_cifrado, tag = cifra.encrypt_and_digest(mensagem_bytes)
    return {
        "aes_nonce": base64_encode(cifra.nonce),
        "aes_tag": base64_encode(tag),
        "aes_ct": base64_encode(texto_cifrado),
    }

def decifrar_aes_eax(chave, pacote):
    """
    Decifra dados cifrados com AES EAX.

    :param chave: Chave AES
    :param pacote: Dicionário com nonce, tag e texto cifrado
    :return: Dados originais em bytes
    """
    
    nonce = base64_decode(pacote["aes_nonce"])
    tag = base64_decode(pacote["aes_tag"])
    ct = base64_decode(pacote["aes_ct"])

    cifra = AES.new(chave, AES.MODE_EAX, nonce=nonce)
    msg = cifra.decrypt(ct)
    cifra.verify(tag)
    return msg

def ligar_bd():
    """
    Cria ligação à base de dados SQLite.

    :return: Objeto de ligação SQLite
    """
    bd = sqlite3.connect(FICHEIRO_BD)
    bd.execute("PRAGMA foreign_keys = ON;")
    return bd

def criar_tabelas():
    """
    Cria as tabelas necessárias caso não existam:
    - configuracao (2FA)
    - registos (passwords)
    """
    with ligar_bd() as bd:
        bd.execute("""
            CREATE TABLE IF NOT EXISTS configuracao (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                segredo_totp TEXT NOT NULL
            );
        """)
        bd.execute("""
            CREATE TABLE IF NOT EXISTS registos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nome TEXT NOT NULL UNIQUE,

                chave_aes_cifrada TEXT NOT NULL,

                url_json TEXT NOT NULL,
                user_json TEXT NOT NULL,
                pass_json TEXT NOT NULL
            );
        """)


def segredo_totp_existe():
    """
    Verifica se já existe segredo TOTP configurado.

    :return: True se existir, False caso contrário
    """
    
    with ligar_bd() as bd:
        cur = bd.execute("SELECT segredo_totp FROM configuracao WHERE id = 1;")
        return cur.fetchone() is not None

def obter_segredo_totp():
    """
    Obtém o segredo TOTP armazenado.

    :return: Segredo TOTP (string)
    """
    
    with ligar_bd() as bd:
        cur = bd.execute("SELECT segredo_totp FROM configuracao WHERE id = 1;")
        return cur.fetchone()[0]

def inicializar_2fa():
    """
    Inicializa o sistema 2FA gerando um segredo TOTP
    e apresentando o URI para configuração no autenticador.
    """
    
    segredo = pyotp.random_base32()
    with ligar_bd() as bd:
        bd.execute("INSERT OR REPLACE INTO configuracao (id, segredo_totp) VALUES (1, ?);", (segredo,))

    issuer = "PasswordManagerPython"
    conta = "utilizador"
    uri = pyotp.totp.TOTP(segredo).provisioning_uri(name=conta, issuer_name=issuer)

    print("\nSegredo criado e guardado na base de dados.")
    print("Adiciona no Google Authenticator / Authy usando este URI:")
    print(uri)


def validar_2fa():
    """
    Valida um código TOTP introduzido pelo utilizador.

    :return: True se for válido, False caso contrário
    """
    segredo = obter_segredo_totp()
    totp = pyotp.TOTP(segredo)

    codigo = input("Introduza o código 2FA (TOTP): ").strip()
    return totp.verify(codigo, valid_window=1)

def mostrar_configuracao_2fa():
    """
    Mostra o segredo e URI TOTP para configuração manual do autenticador.
    """
    segredo = obter_segredo_totp()

    issuer = "PasswordManagerPython"
    conta = "utilizador"
    uri = pyotp.totp.TOTP(segredo).provisioning_uri(
        name=conta,
        issuer_name=issuer
    )

    print("\nCONFIGURAÇÃO 2FA")
    print("SECRET:")
    print(segredo)
    print("\nURI:")
    print(uri)
    print("\nUse estes dados apenas para configurar o Microsoft Authenticator.\n")


def cifrar_registo(chave_publica_rsa, url, user, password):
    """
    Cifra um registo usando criptografia híbrida (RSA + AES).

    :return: Tuplo com chave AES cifrada e campos cifrados em JSON
    """
    chave_aes = get_random_bytes(16)  # AES-128

    url_pacote = cifrar_aes_eax(chave_aes, url.encode("utf-8"))
    user_pacote = cifrar_aes_eax(chave_aes, user.encode("utf-8"))
    pass_pacote = cifrar_aes_eax(chave_aes, password.encode("utf-8"))

    cifra_rsa = PKCS1_OAEP.new(chave_publica_rsa)
    chave_aes_cifrada = cifra_rsa.encrypt(chave_aes)

    return (
        base64_encode(chave_aes_cifrada),
        json.dumps(url_pacote, ensure_ascii=False),
        json.dumps(user_pacote, ensure_ascii=False),
        json.dumps(pass_pacote, ensure_ascii=False),
    )

def decifrar_registo(chave_privada_rsa, chave_aes_cifrada_b64, url_json, user_json, pass_json):
    """
    Decifra um registo previamente armazenado.

    :return: Tuplo (url, user, password)
    """
    
    cifra_rsa = PKCS1_OAEP.new(chave_privada_rsa)
    chave_aes = cifra_rsa.decrypt(base64_decode(chave_aes_cifrada_b64))

    url_pacote = json.loads(url_json)
    user_pacote = json.loads(user_json)
    pass_pacote = json.loads(pass_json)

    url = decifrar_aes_eax(chave_aes, url_pacote).decode("utf-8", errors="ignore")
    user = decifrar_aes_eax(chave_aes, user_pacote).decode("utf-8", errors="ignore")
    password = decifrar_aes_eax(chave_aes, pass_pacote).decode("utf-8", errors="ignore")
    return url, user, password


def pedir_texto(mensagem):
    """Pede texto não vazio ao utilizador."""
    
    while True:
        texto = input(mensagem).strip()
        if texto:
            return texto
        print("Valor inválido. Tente novamente.\n")

def menu():
    """Mostra o menu principal."""
    
    print("Escolha a opção que pretende:")
    print("1 - Criar registo")
    print("2 - Atualizar registo")
    print("3 - Apagar registo")
    print("4 - Consultar registo (exige 2FA)")
    print("5 - Listar registos")
    print("6 - Mostrar configuração 2FA")
    print("0 - Sair")

def listar_registos():
    """Lista os nomes dos registos existentes."""
    
    with ligar_bd() as bd:
        cur = bd.execute("SELECT nome FROM registos ORDER BY nome;")
        nomes = [r[0] for r in cur.fetchall()]

    if not nomes:
        print("Sem registos.\n")
        return
    print("\nRegistos:")
    for n in nomes:
        print(f" - {n}")
    print("")



def criar_registo(chave_publica_rsa):
    """Cria um novo registo cifrado."""
    
    nome = pedir_texto("Nome do registo (ex: github, email): ")
    url = pedir_texto("URL: ")
    user = pedir_texto("User: ")
    password = pedir_texto("Pass: ")

    chave_aes_cifrada_b64, url_json, user_json, pass_json = cifrar_registo(chave_publica_rsa, url, user, password)

    with ligar_bd() as bd:
        try:
            bd.execute("""
                INSERT INTO registos (nome, chave_aes_cifrada, url_json, user_json, pass_json)
                VALUES (?, ?, ?, ?, ?);
            """, (nome, chave_aes_cifrada_b64, url_json, user_json, pass_json))
            print("Registo criado com sucesso.\n")
        except sqlite3.IntegrityError:
            print("Já existe um registo com esse nome.\n")

def atualizar_registo(chave_publica_rsa):
    """Atualiza um registo existente."""
    
    nome = pedir_texto("Nome do registo a atualizar: ")

    with ligar_bd() as bd:
        cur = bd.execute("SELECT id FROM registos WHERE nome = ?;", (nome,))
        if cur.fetchone() is None:
            print("Registo não encontrado.\n")
            return

    url = pedir_texto("Nova URL: ")
    user = pedir_texto("Novo User: ")
    password = pedir_texto("Nova Pass: ")

    chave_aes_cifrada_b64, url_json, user_json, pass_json = cifrar_registo(chave_publica_rsa, url, user, password)

    with ligar_bd() as bd:
        bd.execute("""
            UPDATE registos
            SET chave_aes_cifrada = ?, url_json = ?, user_json = ?, pass_json = ?
            WHERE nome = ?;
        """, (chave_aes_cifrada_b64, url_json, user_json, pass_json, nome))

    print("Registo atualizado com sucesso.\n")

def apagar_registo():
    """Apaga um registo."""
    
    nome = pedir_texto("Nome do registo a apagar: ")
    confirmacao = input(f"Tem a certeza que quer apagar '{nome}'? (s/n): ").strip().lower()
    if confirmacao != "s":
        print("Operação cancelada.\n")
        return

    with ligar_bd() as bd:
        cur = bd.execute("DELETE FROM registos WHERE nome = ?;", (nome,))
        if cur.rowcount == 0:
            print("Registo não encontrado.\n")
        else:
            print("Registo apagado com sucesso.\n")

def consultar_registo(chave_privada_rsa):
    """Consulta um registo após validação 2FA."""
    
    nome = pedir_texto("Nome do registo a consultar: ")

    with ligar_bd() as bd:
        cur = bd.execute("""
            SELECT chave_aes_cifrada, url_json, user_json, pass_json
            FROM registos
            WHERE nome = ?;
        """, (nome,))
        linha = cur.fetchone()

    if linha is None:
        print("Registo não encontrado.\n")
        return

    print("\n 2FA necessário para consultar passwords.")
    if not validar_2fa():
        print("Código 2FA inválido.\n")
        return

    try:
        url, user, password = decifrar_registo(chave_privada_rsa, linha[0], linha[1], linha[2], linha[3])
        print("\n REGISTO ")
        print(f"Nome: {nome}")
        print(f"URL : {url}")
        print(f"User: {user}")
        print(f"Pass: {password}")
        print("\n")
    except Exception:
        print("Erro ao decifrar.\n")


def main():
    """Função principal do Password Manager."""
    
    os.system("clear")
    os.system("figlet Password Manager")
    
    criar_tabelas()

    # chaves RSA
    garantir_chaves_rsa()
    chave_privada = carregar_chave_privada()
    chave_publica = carregar_chave_publica()

    # 2FA setup
    if not segredo_totp_existe():
        inicializar_2fa()

    while True:
        menu()
        opcao = input("Escolha uma opção: ").strip()

        if opcao == "1":
            criar_registo(chave_publica)
        elif opcao == "2":
            atualizar_registo(chave_publica)
        elif opcao == "3":
            apagar_registo()
        elif opcao == "4":
            consultar_registo(chave_privada)
        elif opcao == "5":
            listar_registos()
        elif opcao == "6":
            mostrar_configuracao_2fa()
        elif opcao == "0":
            print("A sair.")
            break
        else:
            print("Opção inválida.\n")


if __name__ == "__main__":
    main()
