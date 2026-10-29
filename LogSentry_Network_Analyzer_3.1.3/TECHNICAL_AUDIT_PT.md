# Auditoria técnica — LogSentry 3.1.3

## Alterações nesta versão

- `psutil` é dependência explícita para recolha multiplataforma de processos, sockets e interfaces.
- CLI e GUI Tkinter partilham o mesmo motor. O script `.bat` permite iniciar a GUI no Windows; o script `.sh` mantém-se para Linux.
- Windows: recolha de rotas, vizinhos e DNS por PowerShell em modo de leitura.
- Linux: recolha de rede via `iproute2`; sockets via psutil e tentativa de enriquecimento de metadados através de `ss`, incluindo `sudo -n` não interativo quando configurado pelo administrador.
- Estados explícitos distinguem recolha concluída sem resultados, recolha parcial e indisponibilidade.
- A tabela de exposição foi reduzida para melhorar a legibilidade em PDF; HTML apresenta até 30 processos, enquanto JSON conserva os dados recolhidos.
- As integrações opcionais não instalam, iniciam, param nem reconfiguram serviços automaticamente.

## Limites e validação

56 testes automatizados passaram no ambiente de desenvolvimento Linux. O smoke test da CLI gerou JSON e HTML. O teste Windows é simulado: ainda é necessário validar em Windows 10/11 reais e verificar manualmente GUI e impressão nos dois sistemas. O ambiente de desenvolvimento não disponibilizou PID para os sockets observados, pelo que a cobertura de atribuição real foi 0%; o programa reporta essa limitação.

A integração Wazuh continua limitada à deteção de presença/estado; não há cliente autenticado para a API do manager. Suricata lê EVE JSON existente; não configura captura. ClamAV só é executado quando o utilizador indica explicitamente um caminho. A ferramenta é diagnóstico/triagem, não um EDR, antivírus ou sistema de monitorização contínua.

Consulta `RESEARCH_AND_DESIGN.md` para fontes técnicas e decisões de arquitetura.


## Alterações específicas da 3.1.3

- A consulta `sudo -n ss` é tentada para comparar a quantidade de metadados de processo visíveis, não apenas quando a saída normal não tem nenhum PID. A saída privilegiada só é preferida quando contém mais atribuições.
- A associação dos registos `ss` e `psutil` normaliza endereços IP e compara protocolo/endereço/porta. O fallback por protocolo/porta só é aceite quando todos os candidatos identificam o mesmo processo.
- O JSON e o relatório incluem `process_attribution_status`; quando não há metadados, é apresentado um aviso com o procedimento `sudo -v`. A GUI continua sem ser executada como root.
- Os testes de Windows continuam simulados nesta versão; validar em Windows real continua pendente.
