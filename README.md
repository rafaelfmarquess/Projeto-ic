# Projeto-ic

# Projeto SIC: Rede Ad-hoc Segura para Dispositivos IoT

## 1. Identificação dos Autores
* **[Rafael Marques]** ([119927]): 50%
* **[ João Cardoso ]** ([120440]): 50%


---

## 2. Relatório de Design e Implementação

### Arquitetura da Rede
O sistema baseia-se numa topologia em árvore onde o **Sink** atua como raiz e gateway aplicacional. Os dispositivos IoT funcionam como sensores e routers, minimizando o número de saltos (*hops*) até ao Sink através de uma estratégia *lazy*: um nó escolhe o uplink com menor distância e mantém a ligação até que esta falhe.

### Gestão de Rotas e Liveness
* **Tabelas de Encaminhamento**: Cada nó implementa uma tabela de encaminhamento dinâmica que aprende o caminho de volta para os NIDs (Network Identifiers) com base nas mensagens recebidas no sentido do uplink.
* **Heartbeat e Reação em Cadeia**: O Sink emite batimentos cardíacos assinados a cada 5 segundos. A perda de 3 batimentos consecutivos (15 segundos) faz com que um nó considere o seu uplink em baixo, desligando automaticamente todos os seus downlinks para forçar a reconstrução da árvore.

---

## 3. Justificação das Opções de Segurança

A segurança foi desenhada em duas camadas para garantir proteção contra intrusos e nós intermédios maliciosos:

### Segurança por Salto (Link Layer)
* **AES-GCM**: Escolhido para a proteção dos links diretos entre nós. Este modo de cifra autenticada garante simultaneamente a confidencialidade e a integridade das mensagens.
* **Nonces e Frescura**: Cada mensagem inclui um *nonce* incremental de 12 bytes, permitindo ao recetor detetar e descartar ataques de replaying.
* **Mutual Auth (X.509 + ECDH)**: A autenticação mútua utiliza certificados digitais emitidos por uma CA central. O acordo de chaves de sessão é feito via **Elliptic Curve Diffie-Hellman (P-521)**, garantindo chaves únicas por sessão.

### Segurança Ponta-a-Ponta (End-to-End)
* **DTLS**: Implementado para proteger a comunicação direta entre cada Nó IoT e o Sink. Como o tráfego atravessa múltiplos routers (nós intermédios), o DTLS garante que apenas os intervenientes finais consigam decifrar os dados aplicacionais, mantendo a autenticidade e integridade em toda a rede.

---

## 4. Funcionalidades Implementadas

### Serviços
* **Inbox**: Envio de mensagens cifradas E2E para o Sink.
* **Consulta de Rede (LIST_NODES)**: Qualquer nó pode solicitar ao Sink a lista de NIDs ativos na rede através de um canal DTLS.
* **Mailbox (Inter-node Messaging)**: Implementação de um sistema de "caixa de correio" no Sink. Os nós podem depositar mensagens para outros destinatários e consultá-las/levantá-las mais tarde.
* **Portas de Aplicação**: Identificação de clientes por números aleatórios (portas) para correta gestão do tráfego downlink.

### Controlo e Depuração
* **Menu Interativo**: Interface completa para monitorização de NIDs, estatísticas de reencaminhamento, status de uplink/downlink e batimentos perdidos.
* **Pesquisa e Seleção Manual**: O comando de *Scan* permite listar vizinhos, os seus *hop counts* e escolher manualmente o próximo salto para testes de topologia.
* **Simulação de Falhas (Blacklist)**: O Sink permite bloquear o heartbeat de um nó específico, simulando falhas de link para validar a reação em cadeia da rede.

---

## 5. Lista de Funcionalidades Não Implementadas
* O sistema de portas está funcional ao nível do protocolo, mas a separação física de diferentes aplicações no mesmo hardware é simulada por via da interface de utilizador.
* Não foi implementada a funcionalidade de múltiplos Sinks simultâneos (bónus opcional).