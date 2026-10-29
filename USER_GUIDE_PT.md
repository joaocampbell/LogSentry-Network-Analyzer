# LogSentry Network Analyzer 3.1.3 — Guia rápido

## Instalação / validação
Requer Python 3.10+ e Linux; não tem dependências Python externas.
```bash
python3 -m compileall -q netanalyzer tests
python3 -m unittest discover -s tests -v
python3 -m netanalyzer --version
```

## Diagnóstico de rede
```bash
python3 -m netanalyzer --privacy-profile public --out output/relatorio-28
```

## Auditoria local e exposição potencial
```bash
python3 -m netanalyzer --endpoint-audit --privacy-profile public --out output/auditoria-endpoint
```
O relatório mostra processos, sockets em escuta e ligações estabelecidas. Quando permitido, tenta associar sockets a processos. Sinaliza serviços em endereços não locais para revisão; não confirma acessibilidade externa nem classifica processos como malware.

## Análise ClamAV explícita (opcional)
Depois de instalar e atualizar ClamAV, escolhe um ficheiro ou diretório que tenhas autorização para analisar:
```bash
python3 -m netanalyzer --endpoint-audit --clamav-scan ~/Downloads --privacy-profile public --out output/clamav-downloads
```
A análise só ocorre quando `--clamav-scan PATH` é fornecido. Não remove nem coloca ficheiros em quarentena. Uma deteção deve ser investigada; uma análise limpa não garante ausência de malware.

## Descoberta de hosts
```bash
python3 -m netanalyzer --discover-network 192.168.1.0/24 --privacy-profile public --out output/descoberta
```
Usar apenas numa rede privada autorizada, até 256 endereços. O modo `nmap -sn` não testa portas. Hosts que não respondem podem continuar ligados.

## Privacidade
O perfil `public` oculta identificadores conhecidos e omite linhas de comando dos processos. Antes de publicar relatórios, revê também caminhos de ficheiros, nomes de serviços e outros metadados que possam identificar o ambiente.

## Limitações
LogSentry não é antivírus, EDR ou IDS; não garante deteção de malware. A avaliação de exposição é heurística e depende da configuração de rede, firewall e permissões.


## Novidades da versão 3.1.3

A auditoria local tenta atribuir processos aos sockets com `ss`. Se o sistema ocultar esses metadados, pode fazer uma segunda consulta de leitura através de `sudo -n`; esta opção não pede palavra-passe nem altera a configuração. Se a consulta privilegiada não estiver autorizada, o programa mantém os dados recolhidos e assinala a limitação. A percentagem de sockets com processo atribuído é uma medida de cobertura, não de segurança.


## Windows 10/11 (versão 3.1.3)

Requisitos: Python 3.10 ou superior e Tkinter incluído na instalação Python. Abre PowerShell na pasta extraída do projeto e executa:

```powershell
py -3 -m pip install -r requirements.txt
py -3 -m netanalyzer --version
py -3 -m netanalyzer --out "$env:USERPROFILE\Documents\LogSentryReports\network-report"
py -3 -m netanalyzer --endpoint-audit --out "$env:USERPROFILE\Documents\LogSentryReports\endpoint-report"
```

Para abrir a interface gráfica, executa `run-logsentry-gui.bat` ou `py -3 -m netanalyzer.gui`. A recolha Windows de interfaces usa psutil; rotas, vizinhos e DNS usam cmdlets PowerShell de leitura. A visibilidade de processos/sockets pode ser limitada sem permissões elevadas. Executar como Administrador só deve ser considerado quando necessário e autorizado.

## Interpretação dos estados de recolha

- `collected_nonzero`: foram observadas ligações estabelecidas no instante da recolha.
- `collected_zero_at_snapshot`: recolha concluída, sem ligações estabelecidas observadas nesse instante.
- `partial_or_unavailable` / `unavailable`: a recolha não foi completa; não interpretar zero como ausência de ligações.
- A associação processo/PID depende das permissões e da informação disponibilizada pelo sistema operativo.

## Utilização doméstica e empresarial

Para uma rede doméstica, começar por executar o diagnóstico e, se necessário, a descoberta apenas para a sub-rede privada própria (limitada a 256 endereços). Em ambiente empresarial, obter autorização, documentar o âmbito e horário, testar primeiro uma rede de baixa criticidade e guardar relatórios em local com acesso restrito. O LogSentry não aplica alterações a firewall, não captura tráfego e não substitui SIEM/EDR, auditoria formal ou ferramentas de gestão de vulnerabilidades.


## Novidades da versão 3.1.3

No Linux, a auditoria compara a saída normal de `ss` com uma consulta privilegiada não interativa quando disponível. Para permitir essa consulta sem executar a aplicação gráfica como administrador, abre um terminal e executa `sudo -v`; depois volta a executar a análise na GUI. O LogSentry não recolhe nem guarda a palavra-passe. Se a política `sudo` não permitir a consulta não interativa, o relatório indica que a atribuição pode estar limitada por permissões. A associação entre sockets usa protocolo, endereço e porta; correspondências ambíguas não são atribuídas automaticamente.
