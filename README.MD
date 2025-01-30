# Biblioteca utilizada

https://github.com/antirez/smaz

# Instruções

Instalar clan se não tiver:

```sudo apt update```
```sudo apt install clang```

- Clonar repo https://github.com/google/oss-fuzz.
- Copiar a pasta **smaz** deste repo e colar dentro ela dentro da pasta projects do oss-fuzz.

# Comandos para rodar fuzzer

O comando a seguir builda os containers necessários rodar o fuzzer do projeto com um sanitizer específico, o sanitizer pode ter estes valores: <address/memory/undefined>

```python3 infra/helper.py build_fuzzers --sanitizer memory smaz```

O comando a seguir, roda um __fuzzer__ para um projeto. **Ele sempre tem que ser executado após o build**. O resultado muda de acordo com qual sanitizer é utilizado.

```python3 infra/helper.py run_fuzzer smaz fuzz_smaz``` 

(python3 infra/helper.py run_fuzzer <project_name> <fuzzer_name>)

# Comandos para debugar

Comando para entrar no shell do container:

```python3 infra/helper.py shell smaz```

Comando para reproduzir um erro. É preciso estar no shell da VM. Troque o número do crash... pelo seu.

```/out/fuzz_smaz /out/crash-38e8edafbad4f83f3d5d9cb138ee20905b981f07```

# Links úteis

https://opensource.com/article/22/2/debug-open-source-project-oss-fuzz

https://google.github.io/oss-fuzz/getting-started/new-project-guide/#homepage