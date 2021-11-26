## Input functions summary

| Function                          | Input terminator                     | Null terminated? |
| --------------------------------- | ------------------------------------ | ---------------- |
| `gets(char *str)`                 | Newline or EOF                       | Yes              |
| `fgets(char *str, int len, file)` | Newline, EOF or input length reached | Yes              |
| `scanf("%s", char *str)`          | Newline or EOF                       | Yes              |

strncpy is not null terminated. 