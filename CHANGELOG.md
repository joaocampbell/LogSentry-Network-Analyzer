# Changelog

## 3.1.3 — 2026-10-29
- A recolha Linux compara a saída normal de `ss` com uma consulta `sudo -n` não interativa mesmo quando alguns processos já são visíveis, evitando perder atribuição parcial.
- A associação entre `psutil` e `ss` usa protocolo, endereço local normalizado e porta; o fallback por porta só é usado quando todos os candidatos apontam para o mesmo processo.
- O relatório apresenta estado explícito da atribuição (`complete`, `partial`, `unavailable_or_permission_limited`) e aviso acionável para executar `sudo -v` antes de repetir a auditoria, sem elevar a GUI nem pedir palavra-passe.
- Adicionados testes para saída privilegiada mais completa, correspondência de sockets e estado da atribuição.
- Mantém o comportamento de leitura; não altera serviços, firewall ou rotas.


## 3.1.2 — 2026-10-29
- Recolha multiplataforma de processos e sockets via psutil; fallback Linux com `ss`/`ps` e enriquecimento opcional de metadados através de `ss`.
- Recolha Windows de interfaces via psutil e rotas, vizinhos e DNS através de cmdlets PowerShell em modo de leitura.
- Suporte ao ping nativo em Windows e deteção de integrações ajustada ao sistema operativo.
- Estados explícitos para sockets recolhidos, recolha parcial/permissões negadas, zero ligações no instante e indisponibilidade.
- Tabela de exposição mais compacta; a lista HTML de processos limita a apresentação a 30 entradas, mantendo a recolha completa no JSON.
- Folha de estilos de impressão A4 horizontal melhorada.
- Dependência `psutil` documentada; não há alterações automáticas à firewall ou serviços.
- Adicionados testes de regressão para atribuição de PID, recolha Windows simulada e estados de recolha.

## 3.1.0
- Melhoria da atribuição de processos aos sockets: se `ss` não expuser metadados, pode tentar uma segunda consulta `sudo -n ss` sem prompt e sem alterar configurações.
- O relatório passa a incluir o método de atribuição e a cobertura de sockets com processo identificado.
- Os alertas de exposição incluem fundamento da gravidade, confiança heurística e contexto para evitar sugerir que uma porta aberta prova acesso externo.
- Recomendações mais prudentes: validar processo, necessidade do serviço, firewall e encaminhamento antes de qualquer alteração.
- Mantidas as funcionalidades da versão 3.0.1 e o comportamento read-only do diagnóstico.

## 3.0.1
- Corrigido o estado visual da barra de progresso: agora é parada e reposta ao terminar/falhar, com estado textual explícito.
- Melhorado o tratamento de timeout, exceções inesperadas e saídas parciais do subprocesso.
- A interface confirma que os relatórios HTML e JSON existem antes de anunciar conclusão.
- Reativa os controlos ao terminar ou falhar a análise.

## 3.0.0
- Nova interface gráfica Tkinter para diagnóstico plug-and-play.
- Execução da análise em thread separada, progresso e resumo de resultados.
- Seleção opcional de EVE JSON, caminho para ClamAV e rede privada para descoberta.
- Deteção de ferramentas e estados de serviços em relatórios.
- Atalhos de execução e instalador de atalho de desktop para Linux.
- Mantidos CLI, comparador, privacidade, baselines, descoberta Nmap, leitura Suricata EVE e análise ClamAV opcional.
- Não instala dependências de segurança, não modifica firewall e não desativa serviços automaticamente.

## 2.9.0
- Ver relatório anterior no histórico de versões e `TECHNICAL_AUDIT_PT.md`.
