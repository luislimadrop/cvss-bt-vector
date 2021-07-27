# Overview
Script para retornar informações do CVSS através do Vetor CVSS.

# Usage
```
python cvssbyvector.py AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L
```

Output:

```
+-------------------------------+------------+
| Indicador                     | Métrica    |
|-------------------------------+------------|
| Vetor de Acesso:              | Rede       |
| Complexidade do Ataque:       | Baixo      |
| Privilégios exigidos:         | Nenhum     |
| Interação do usuário:         | Nenhum     |
| Escopo:                       | Inalterado |
| Impacto de Confidencialidade: | Alto       |
| Impacto de Integridade:       | Alto       |
| Impacto de Disponibilidade:   | Baixo      |
|                               |            |
| Explorabilidade:              | 3.9        |
| Impacto:                      | 5.5        |
| CVSS Base:                    | 9.4        |
+-------------------------------+------------+
```
