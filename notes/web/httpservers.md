# HTTP Servers

| Server        | Arrays in query str                                       | Dictionaries in query str | Duplicate params in query string |
| ------------- | --------------------------------------------------------- | ------------------------- | -------------------------------- |
| PHP*          | `foo[]=1&foo[]=2` or `foo=1&foo=2` or `foo[0]=1&foo[1]=2` | `foo[bar]=baz`            | Becomes array                    |
| Node/Express* | Same as PHP                                               | Same as PHP               | Becomes array                    |
| Flask         | Not supported                                             | Not supported             | First one                        |

\*Passing arrays when strings are expected can cause unexpected results when string operations are performed.