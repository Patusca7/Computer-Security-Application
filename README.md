# Aplicação de Segurança Informática
Neste projeto tenho como objetivo a criação de uma aplicação de segurança informática construída com python, implementando as seguintes ferramentas:
  1. Detetar e listar que portos de rede se encontram disponíveis numa ou mais máquinas remota
  2. Elaborar um UDP flood (DoS) para um IP remoto
  3. Elaborar um SYN flood
  4. Analisar e processar ficheiros de log, de no mínimo 2 serviços, listando a origem dos acessos e/ou tentativas de acesso inválidas. O output do processamento deverá mencionar as listas de origem do país, as datas das tentativas e/ou acessos...
  5. Elaborar um serviço básico de troca de mensagens seguras entre um cliente e servidor, utilizando chaves simétricas e/ou assimétricas
  6. Elaborar um client port knocking para abertura de ligação de login por SSH a uma máquina Linux.
  7. Elaborar um “password manager” simples, este aplicativo deve guardar 3 campos (URL / user / pass). Deve permitir criar registo, atualizar registo, apagar registo, consultar registo. Deve ser utilizado chaves assimétricas para encriptação dos respetivos registos. Para aceder e consultar as passwords deve ser implementado 2FA 
  

Além destas funcionalidades existem algumas funcionalidades extras que poderão ser exploradas como por exemplo:
  8. Serviço de troca de mensagens multiutilizador, com o arquivamento das mensagens seguras trocadas entre todos os intervenientes, estas mensagens devem ser armazenadas em ficheiros de texto encriptados com chaves assimétricas. As mensagens apenas devem ser armazenadas no lado do servidor. É obrigatório que seja possível a consulta/visualização de todas as mensagens utilizando a chave privada correspondente. 
  9. Deve ser possível a pedido de um qualquer cliente do sistema de troca de mensagens a listagem, a remoção, o download de todas as mensagens arquivadas existentes no servidor em que o cliente foi interveniente
  10. Deve ser possível o backup/exportação, com chaves simétricas ou assimétricas, de todas as mensagens trocadas no serviço básico de mensagens OU no serviço de mensagens multiutilizador para um ficheiro encriptado, sendo possível desencriptar com as credenciais corretas. 
