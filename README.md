# Bry Challenge - Assinatura Digital


## Requisitos

Linux:

- `gcc` >= 11.0
- `cmake` >= 3.23
- `vcpkg` - gerenciador de pacotes
- `ninja` - sistema de build

## Building

Caso ainda não tenha configurado os perfil de toolchain no Conan, rode o seguinte comando:

```
conan profile detect --force
```


Rode o seguinte comando para que `conan` gere os arquivos CMake referentes à dependência de bibliotecas:

```
cd <project-root>
conan install . --output-folder=build --build=missing
```


