# LogSentry 3.1.3 — investigação e decisões técnicas

## Fontes técnicas consultadas

- Python Packaging User Guide, `pyproject.toml` e entry points: https://packaging.python.org/en/latest/specifications/pyproject-toml/ e https://packaging.python.org/en/latest/specifications/entry-points/
- Documentação oficial Suricata, EVE JSON: https://docs.suricata.io/en/latest/output/eve/eve-json-output.html
- Documentação oficial Wazuh API: https://documentation.wazuh.com/current/user-manual/api/index.html
- Documentação oficial ClamAV, análise de ficheiros: https://docs.clamav.net/manual/Usage/Scanning.html

## Decisões

1. A interface gráfica usa Tkinter, biblioteca padrão Python, para evitar uma dependência Python adicional. Em algumas instalações mínimas de Linux Mint, `python3-tk` poderá ter de ser instalado.
2. O motor de diagnóstico continua disponível pela CLI. A GUI chama o mesmo motor; não existe uma segunda implementação de diagnóstico.
3. Integrações são opcionais. O programa deteta executáveis, alguns estados systemd e o ficheiro EVE em caminhos padrão. Presença não prova que a integração esteja corretamente configurada.
4. Suricata: o LogSentry lê eventos EVE existentes; não configura captura de tráfego.
5. Wazuh: esta versão deteta a presença do agente e verifica o estado do serviço; não implementa ainda cliente autenticado para a API do manager. A API exige autenticação, pelo que uma integração futura deve usar credenciais fornecidas pelo utilizador e validação TLS adequada.
6. ClamAV: a análise é explicitamente solicitada para um caminho escolhido. Não remove nem coloca ficheiros em quarentena automaticamente.
7. Descoberta Nmap: apenas rede privada indicada explicitamente, limitada a 256 endereços e `-sn` (descoberta de hosts, sem varrimento de portas).
8. Privacidade: o perfil público continua recomendado antes de partilhar relatórios; deve ser feita revisão manual de todos os artefactos.
9. Segurança por defeito: a aplicação não instala pacotes, não muda regras de firewall, não desativa serviços e não pede privilégios elevados automaticamente.

## Limitações

- Os testes automatizados verificam comportamento de funções e relatórios; não substituem testes de campo em várias distribuições e configurações.
- A descoberta de hosts pode não detetar dispositivos que não respondem às sondagens.
- A ausência de alertas não significa ausência de ameaça.
- Não é um antivírus, EDR ou IDS completo.


## Atualizações 3.1.3 — multiplataforma e fiabilidade

- `psutil` é a camada preferida para sockets/processos em Linux e Windows; o fallback Linux continua a usar `ss`/`ps`. A documentação oficial de psutil lista suporte de Windows e Linux: https://psutil.io/platform/
- Windows: interfaces por psutil; rotas, vizinhos e servidores DNS por cmdlets PowerShell (`Get-NetRoute`, `Get-NetNeighbor`, `Get-DnsClientServerAddress`) em execução sem perfil e sem alterações de configuração.
- Estados de recolha explicitam zero observado, parcial/permissões negadas e indisponibilidade.
- A análise de sockets e descoberta de rede continuam em modo de leitura; Nmap é opcional e a descoberta é limitada a redes privadas explicitamente indicadas. Ver documentação oficial Nmap: https://nmap.org/docs.html
- Os relatórios devem minimizar dados pessoais e de infraestrutura quando partilhados; seguir princípios de logging seguro e minimização de dados da OWASP: https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html
- Testes unitários não são equivalentes a validação real no Windows. A versão necessita de testes de campo em Windows 10/11 e várias distribuições Linux antes de se declarar universalmente pronta para produção.

## Atualizações 3.1.3 — atribuição de sockets

A evidência recolhida no Linux Mint mostrou que `sudo ss -lntup` apresenta processos e PID, enquanto o relatório 3.1.2 não os associou. A 3.1.3 melhora a comparação entre `psutil` e `ss`: compara a consulta normal com `sudo -n` mesmo se parte dos processos já for visível, prefere a consulta privilegiada apenas quando tem mais metadados e usa uma associação normalizada por protocolo, endereço e porta. Um fallback por porta só é aceite quando todos os candidatos identificam o mesmo processo, evitando associações ambíguas.

A ferramenta não pede nem guarda palavras-passe e não executa a interface gráfica como administrador. No Linux, `sudo -v` pode atualizar temporariamente a credencial em cache; depois, a aplicação tenta `sudo -n` sem prompt. Se a política local impedir essa operação, o relatório assinala a limitação. Esta alteração é somente de leitura e não altera serviços nem regras de firewall.
