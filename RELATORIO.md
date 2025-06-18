# # Relatório Bry Challenge

## Sistema Operacional

O sistema-alvo é *Linux*.

## Estrutura do projeto

O código que implementa o domínio deste desafio (cálculos criptográficos) está contido na biblioteca `core`, localizada em `src/core`. Dessa forma, as funcionalidades da biblioteca podem ser compartilhadas pelas ferramentas de linha de comando e pelo servidor HTTP.

À parte o código da `core`, cada um dos outros arquivos `.cpp` em `src` correspondem aos executáveis pedidos no desafio.

O diretório `include` inclui os headers públicos das bibliotecas locais, de não-terceiros - neste caso, somente a `core`.

`external` inclui arquivos de bibliotecas de terceiros inclusas no repositório. No projeto incluí a biblioteca header-only `scope_guard`, mas poderia
tê-la incluída via `vcpkg`.

`tests/tests.cpp` contem os testes da biblioteca `core`, usando a lib `Catch2`. Arquivos usados nos testes estão `data`.

## Biblioteca `core`

A biblioteca contém as funções para o cálculo do hash (`msgDigest`), assinatura (`cmsSign`) e verificação da assinatura (`cmsVerify`). `cmsSign` e `cmsVerify` disponibilizam versões aceitando nomes de arquivos como entrada, para interfacear com os parâmetro de linha de comando, e com ponteiros para buffers de dados, para interfacear com os dados de requisição HTTP. Ambas as versões acabam delegando para uma implementação interna das funções, interfaceada por objetos `BIO*` da OpenSSL.

Erros de runtime derivados de operações da biblioteca OpenSSL são comunicados via exceções próprias da biblioteca. Logs de erros da OpenSSL são mostrados no `stdout` quando compilado em modo Debug, ou quando `BRY_LOG_OPENSSL_ERRORS` é definido na compilação.

Eu optei por usar scoped guards para a liberação de recursos da OpenSSL, por alguns motivos:
- garantia da liberação de recursos.
- evitar embrulhar código em try/catch, melhorando a legibilidade.
- diminui as chances de se esquecer de liberar recursos em uma condição de erro.


## Sistema de build

De início tentei usar `Conan` como o gerenciador de pacotes, mas tive muitos problemas tentando
configurá-lo com o gerador do CMake `Ninja Multi-Config`, então acabei optando pelo `vcpkg`.

Eu normalmente uso o sistema de build `ninja` nos meus projetos por oferecer algumas vantagens em relação ao Make, e acabei usando-o aqui também.

## Continuous Integration

Por falta de tempo não consegui implementar o CI do projeto. Como o projeto está no GitHub, eu usaria GitHub Actions.

## Melhorias

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

