# # Relatório Bry Challenge



# Melhorias

A seguir seguem algumas melhorias que gostaria de fazer caso tivesse mais tempo:

- adicionar testes de condições de erro na biblioteca `core`.
- adicionar testes para os executáveis bry-checksum e bry-signature.
- usar CAfile da Bry e fazer verificação do certificado (remover `PKCS7_NOVERIFY`).
  - talvez embutir o certificado no executável.
- analisar possíveis vazamentos de memória com ferramentas adequadas, p.ex. memgrind.
  - possivelmente há algum vazamento por não liberar corretamente algum objeto OpenSSL.
- documentar funções da lib `core`.
- padronizar nomes de variáveis.
- adicionar parâmetros de `host` e `port` no bry-server.

