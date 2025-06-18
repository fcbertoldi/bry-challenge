# Bry Challenge - Assinatura Digital


## Requisitos

Linux:

- `gcc` >= 11.0
- `cmake` >= 3.23
- `vcpkg` - gerenciador de pacotes
- `ninja` - sistema de build

## Building

Rode os seguintes targets do make:

```
make clean
make cmake-configure && make build-debug
```

## Testes

```
make test
```
