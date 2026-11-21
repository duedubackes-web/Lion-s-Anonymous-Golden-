# Lion's Anonymous Golden

Ferramenta local para triagem de registros AVC do SELinux. Agrupa ocorrências pelo tipo de origem, pelo tipo de destino, pela classe do objeto, pelas permissões e pelo modo registrado. Os grupos mais recorrentes aparecem primeiro.

## Executar

Requer Python 3.9 ou posterior. A ferramenta usa a biblioteca padrão do Python.

```sh
python3 avc_review.py exemplo.log
python3 avc_review.py exemplo.log --format aurion --asset "Portal" > eventos.json
```

Substitua `exemplo.log` por um export bruto de auditoria autorizado. A entrada aceita registros AVC e USER_AVC com campos `scontext`, `tcontext` e `tclass`. Use `-` para ler a entrada padrão.

- **report** lista as ocorrências por grupo e o primeiro e último horário observado.
- **aurion** exporta um evento por grupo com horário válido para importar em **Aurion Evidências → Linha do tempo**.

Em registros com `permissive=1`, a decisão foi observada em modo permissivo. A recorrência por grupo ajuda a priorizar a conferência do contexto, da configuração do serviço e da política aplicável. A ferramenta somente lê os logs e produz relatórios.

## Testar

```sh
python3 -m unittest discover -s tests -v
```

## Referência

[SELinuxProject/selinux — Fix Policy Problems](https://github.com/SELinuxProject/selinux/wiki/Fix-Policy-Problems)

## Processamento em lote

```sh
python3 avc_batch.py exemplo.log --output caso.zip --asset "Portal"
```

Informe vários caminhos para processar mais de um log. O ZIP contém:

- `provenance.json` com o SHA-256 dos bytes analisados, o tamanho do arquivo, as contagens e os caminhos dos resultados.
- `reports/` com um relatório por entrada processada.
- `aurion/` com arquivos JSON prontos para importar na linha do tempo. Cada parte respeita os limites do importador.

Uma falha de leitura aparece no manifesto e resulta no código de saída 2. Os relatórios das entradas válidas continuam disponíveis. Escolha um caminho de saída novo em um sistema de arquivos que suporte links físicos, como ext4 ou NTFS. O lote preserva o arquivo existente quando o nome já está em uso.

Referência de arquitetura: [Apache NiFi — Data Provenance](https://nifi.apache.org/nifi-docs/user-guide.html#data-provenance).

## Painel local do Aurion Cyber

Abra `web/index.html` no navegador para acessar Triagem de logs web, Central de evidências, Senhas e histórico Git e Simulador Enigma. O analisador SELinux continua disponível pela linha de comando. Para cruzar dados, exporte os eventos da triagem web ou do lote SELinux e importe o JSON na Central de evidências.

O laboratório do painel verifica SHA-256 com dois vetores conhecidos. Ele mede 21 chamadas por tamanho após uma chamada de aquecimento e exporta as amostras e medianas. O tempo inclui a chamada à Web Crypto e pode variar conforme navegador e hardware. Nenhum arquivo pessoal é usado no benchmark. Se o navegador restringir Web Crypto ao abrir o HTML local, execute `python3 -m http.server 8000 --bind 127.0.0.1 --directory web` e abra `http://127.0.0.1:8000/`.

Referência para o desenho do laboratório: [nsacyber/simon-speck-supercop](https://github.com/nsacyber/simon-speck-supercop).

Identificador do projeto: `7x77`.

## Investigação de arquivos

No painel Aurion, abra **Investigação de arquivos**. Os botões identificam formatos por assinatura binária, verificam SHA-256 com uma referência opcional e exportam um evento para a Central de evidências. Arquivos são processados localmente, até 32 MiB, sem execução ou extração de conteúdo. A identificação é preliminar. Use o exemplo sintético para testar.

O visualizador hexadecimal lê apenas a janela solicitada de até 256 bytes. É possível navegar por páginas e saltar para um deslocamento decimal ou hexadecimal. O relatório continua exportando os dados de triagem, sem anexar a janela de bytes.

## Inventário de serviços

No painel web, importe duas coletas JSON do mesmo ambiente. O comparador identifica adições, remoções e mudanças no serviço declarado por ativo, porta e transporte. Campos ausentes de transporte formam uma chave própria. Use duas coletas com o mesmo formato e escopo. A exportação é compatível com a linha do tempo da Central de Evidências.

## Mesa de fontes

Registre o link público, as datas de origem e publicação, o achado e sua verificação. Salve o dossiê JSON para retomar o trabalho. A importação mescla por URL e atualiza registros coincidentes. Exporte os resultados filtrados para a linha do tempo. A página não recupera documentos automaticamente.
