# LogSentry Network Analyzer 3.1.3

Ferramenta Python de diagnóstico de rede e triagem local para Linux, com relatórios HTML/JSON.

## Interface gráfica plug-and-play

A GUI usa Tkinter (biblioteca padrão Python) e chama o mesmo motor de diagnóstico da CLI. Não instala ferramentas nem altera configurações do sistema.

```bash
./run-logsentry-gui.sh
```

Se o Tkinter estiver ausente no Linux Mint, instala o componente do sistema com `sudo apt install python3-tk` e volta a executar o script. Para adicionar um atalho ao menu de aplicações:

```bash
./install-desktop.sh
```

A GUI permite gerar relatórios, ativar auditoria local, selecionar um ficheiro EVE do Suricata, escolher um alvo para ClamAV e indicar uma rede privada autorizada para descoberta Nmap.

## Funcionalidades

- Diagnóstico de DNS, TCP, TLS, HTTPS e ICMP.
- Inventário de interfaces, rotas, configuração DNS e vizinhos ARP/NDP.
- Perfil de privacidade pública e auditoria de anonimização.
- Comparação de relatórios e baselines ARP/NDP.
- Leitura opcional de alertas Suricata EVE JSON (mantida; requer ficheiro de eventos existente).
- Auditoria local de processos e sockets com avaliação heurística do âmbito de escuta.
- Melhor atribuição de processos aos sockets, com tentativa opcional `sudo -n` estritamente de leitura quando os metadados estão ocultos.
- Cobertura de atribuição apresentada como contagem e percentagem; alertas incluem fundamento e limites da classificação.
- Descoberta opcional de hosts com Nmap, limitada a redes privadas explicitamente indicadas de até 256 endereços.
- Análise ClamAV explicitamente solicitada para um caminho existente; sem remoção ou quarentena automática.

## Requisitos

- Python 3.10 ou superior.
- Linux recomendado para a recolha detalhada.
- `ip` e `ss` para informações locais; `nmap` opcional para descoberta; `clamscan` opcional para análise antivírus.
- Suricata opcional: o LogSentry lê um ficheiro EVE JSON já produzido, mas não instala nem configura o IDS.

## Instalação Python opcional

A execução a partir do ZIP extraído não requer instalação Python nem dependências de terceiros. Para uma instalação isolada opcional, cria um ambiente virtual com `python3 -m venv .venv`, ativa-o com `source .venv/bin/activate` e executa `python -m pip install --no-build-isolation .`.

## Validar

```bash
python3 -m compileall -q netanalyzer tests
python3 -m unittest discover -s tests -v
python3 -m netanalyzer --version
```

## Diagnóstico básico

```bash
python3 -m netanalyzer --privacy-profile public --out output/relatorio
xdg-open output/relatorio.html
```

## Auditoria local de endpoint

```bash
python3 -m netanalyzer --endpoint-audit --privacy-profile public --out output/endpoint
```

## Descoberta de hosts autorizada

```bash
python3 -m netanalyzer --discover-network 192.168.1.0/24 --privacy-profile public --out output/descoberta
```

O alvo tem de ser uma rede privada e conter no máximo 256 endereços. A descoberta usa `nmap -sn`; não executa varrimento de portas.

## Ler alertas Suricata existentes

```bash
python3 -m netanalyzer --suricata-eve /var/log/suricata/eve.json --privacy-profile public --out output/suricata
```

Se o ficheiro não existir ou não for legível, o relatório deverá ser interpretado como sem visibilidade IDS, não como ausência de ameaças.

## ClamAV opcional

```bash
python3 -m netanalyzer --endpoint-audit --clamav-scan ~/Downloads --privacy-profile public --out output/clamav
```

A análise só ocorre quando o ClamAV está instalado e o caminho existe. Deteções exigem investigação; um resultado limpo não garante ausência de malware.

## Segurança e limitações

- O LogSentry é uma ferramenta de diagnóstico e triagem, não um antivírus, EDR ou IDS completo.
- Sockets ligados a interfaces não loopback são candidatos a exposição, não prova de acessibilidade externa. Firewall, encaminhamento e permissões alteram a exposição real.
- Nomes de processos e números de porta não provam comprometimento.
- O perfil público reduz informação identificável, mas os relatórios devem ser revistos antes de partilhar.
- Executa descoberta apenas em redes que possuis ou tens autorização para analisar.


## Compatibilidade de plataforma

A versão 3.1.3 suporta Linux e Windows para diagnósticos comuns. A profundidade da recolha varia por sistema operativo e permissões; campos não disponíveis são assinalados como incompletos em vez de serem tratados como resultados negativos. No Windows, instala `requirements.txt` e executa `run-logsentry-gui.bat`. Ver `USER_GUIDE_PT.md` para instruções e limites.
